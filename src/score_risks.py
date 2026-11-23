"""Score only NVD-aligned synthetic relationships supported by their case evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.scoring import RiskScoringConfig, risk_tier, score_components

DEFAULT_DATE = "2026-10-19"
DEFAULT_INPUT = ROOT / "results" / f"{DEFAULT_DATE}-nvd-aligned"
DEFAULT_INVENTORY = ROOT / "data" / "synthetic_nvd_aligned"
DEFAULT_OUTPUT = ROOT / "results" / f"{DEFAULT_DATE}-risk-scoring-prototype"

RISK_FIELDS = [
    "asset_id",
    "cve_id",
    "risk_score",
    "risk_tier",
    "cvss_score",
    "cvss_version",
    "severity_component",
    "in_kev",
    "kev_bonus_component",
    "kev_date_added",
    "criticality",
    "criticality_component",
    "exposure",
    "exposure_component",
    "asset_type",
    "business_unit",
    "environment",
    "scenario_type",
    "installation_ids",
    "software_products",
    "software_versions",
    "matched_criteria",
    "configuration_indices",
    "evidence_used",
    "ranking_reason",
    "uncertainties",
    "data_origin",
]

ASSET_FIELDS = [
    "asset_id",
    "scenario_type",
    "scored_relationship_count",
    "kev_scored_relationship_count",
    "max_risk_score",
    "top_risk_cve_id",
    "top_risk_tier",
    "top_risk_reason",
    "criticality",
    "exposure",
    "environment",
    "asset_type",
    "business_unit",
    "risk_summary_status",
    "data_origin",
    "uncertainties",
]

ELIGIBILITY_FIELDS = [
    "asset_id",
    "cve_id",
    "eligibility_status",
    "reason",
    "case_id",
    "audit_status",
    "matched_asset_count_after_tree_evaluation",
    "installation_ids",
]

GAP_FIELDS = [
    "asset_id",
    "cve_id",
    "missing_or_invalid_evidence",
    "data_origin",
]

SYNTHETIC_LIMITATION = (
    "Synthetic enterprise inventory and generated test scenario; "
    "not confirmed real-world enterprise exposure."
)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return document


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def _resolve_inputs(
    input_dir: Path,
    inventory_dir: Path,
) -> dict[str, Path]:
    paths = {
        "matches": input_dir / "vulnerability_asset_matches.csv",
        "audit": input_dir / "cve_configuration_audit.csv",
        "phase3_summary": input_dir / "phase3_summary.json",
        "cases": inventory_dir / "configuration_cases.csv",
        "assets": inventory_dir / "enterprise_assets.csv",
        "software": inventory_dir / "software_inventory.csv",
        "generation_manifest": inventory_dir / "generation_manifest.json",
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("Required scoring evidence is missing: " + ", ".join(missing))
    return paths


def _verify_generation_provenance(
    manifest: dict[str, Any],
    paths: dict[str, Path],
    snapshot_date: str,
) -> None:
    if manifest.get("experiment") != "NVD-aligned synthetic coverage":
        raise ValueError("Input inventory is not the NVD-aligned synthetic experiment")
    if manifest.get("data_origin") != "synthetic":
        raise ValueError("Inventory manifest does not declare synthetic data")
    if manifest.get("snapshot_date") != snapshot_date:
        raise ValueError("Inventory manifest snapshot does not match requested snapshot")

    raw_records = {
        Path(str(record.get("path", ""))).name: record
        for record in manifest.get("source_raw_files", [])
        if isinstance(record, dict)
    }
    if not raw_records:
        raise ValueError("Synthetic generation manifest has no raw source provenance")
    for name, record in raw_records.items():
        source_path = ROOT / "data" / "raw" / snapshot_date / name
        if not source_path.is_file():
            raise FileNotFoundError(f"Manifest source file is missing: {source_path}")
        if _sha256(source_path) != record.get("sha256"):
            raise ValueError(f"Raw NVD source hash mismatch: {source_path}")


def _join_source_relationships(
    paths: dict[str, Path],
    snapshot_date: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, str]],
    dict[str, Any],
]:
    summary = _read_json(paths["phase3_summary"])
    if summary.get("phase") != 3 or summary.get("snapshot_date") != snapshot_date:
        raise ValueError("Phase 3 report is not for the requested snapshot")
    if Path(str(summary.get("output_directory", ""))).resolve() != paths[
        "matches"
    ].parent.resolve():
        raise ValueError("Phase 3 summary does not describe the selected result directory")
    if Path(str(summary.get("inventory_directory", ""))).resolve() != paths[
        "assets"
    ].parent.resolve():
        raise ValueError("Phase 3 report references a different inventory directory")

    assets = _read_csv(paths["assets"])
    installations = _read_csv(paths["software"])
    cases = _read_csv(paths["cases"])
    matches = _read_csv(paths["matches"])
    audit_rows = _read_csv(paths["audit"])
    expected_match_rows = summary.get("results", {}).get("vulnerability_asset_match_rows")
    if expected_match_rows is not None and int(expected_match_rows) != len(matches):
        raise ValueError("Phase 3 match row count differs from its summary")

    assets_by_id = {row["asset_id"]: row for row in assets}
    if len(assets_by_id) != len(assets):
        raise ValueError("Synthetic asset input contains duplicate asset IDs")
    installations_by_id = {row["installation_id"]: row for row in installations}
    if len(installations_by_id) != len(installations):
        raise ValueError("Synthetic software input contains duplicate installation IDs")
    audit_by_cve = {row["cve_id"]: row for row in audit_rows}
    if len(audit_by_cve) != len(audit_rows):
        raise ValueError("CVE audit contains duplicate CVE IDs")
    cases_by_pair: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in cases:
        if row.get("case_status") == "positive_and_control":
            cases_by_pair[(row["positive_asset_id"], row["source_cve_id"])].append(row)

    output_rows_by_pair: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in matches:
        output_rows_by_pair[(row["asset_id"], row["cve_id"])].append(row)
    relation_rows: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    relationship_case_ids: dict[tuple[str, str], str] = {}
    eligibility_rows: list[dict[str, Any]] = []
    for asset_id, cve_id in sorted(output_rows_by_pair):
        rows = output_rows_by_pair[(asset_id, cve_id)]
        asset = assets_by_id.get(asset_id)
        audit = audit_by_cve.get(cve_id)
        pair_cases = cases_by_pair.get((asset_id, cve_id), [])
        reason: str | None = None
        selected_case: dict[str, str] | None = None
        if asset is None:
            reason = "asset_missing_from_synthetic_inventory"
        elif asset.get("data_origin") != "synthetic" or asset.get("scenario_type") != "positive":
            reason = "not_a_generated_positive_scenario"
        elif asset.get("source_cve_id") != cve_id:
            reason = "asset_source_cve_does_not_match_relationship"
        elif not pair_cases:
            reason = "no_positive_configuration_case_evidence"
        elif len(pair_cases) != 1:
            reason = "ambiguous_positive_configuration_case_evidence"
        else:
            selected_case = pair_cases[0]
            if selected_case.get("expected_positive_match") != "candidate_match":
                reason = "positive_case_does_not_expect_candidate_match"
            elif (
                asset.get("source_configuration_index")
                != selected_case.get("configuration_index")
            ):
                reason = "asset_configuration_provenance_does_not_match_case"
            else:
                rows = [
                    row for row in rows
                    if row.get("configuration_index")
                    == selected_case.get("configuration_index")
                ]
                if not rows:
                    reason = "matched_configuration_index_does_not_match_positive_case"
        if reason is None:
            if audit is None:
                reason = "cve_missing_from_configuration_audit"
            elif audit.get("status") != "matched_assets_under_local_configuration_evaluation":
                reason = "cve_audit_does_not_confirm_local_configuration_evaluation"
            else:
                try:
                    audit_matches = int(audit["matched_asset_count_after_tree_evaluation"])
                except (KeyError, ValueError) as exc:
                    raise ValueError(f"Invalid matched asset count for {cve_id}") from exc
                if audit_matches <= 0:
                    reason = "cve_audit_reports_no_matched_assets"

        installation_ids = sorted({row["installation_id"] for row in rows})
        if reason is None:
            for installation_id in installation_ids:
                software = installations_by_id.get(installation_id)
                if software is None:
                    reason = "installation_missing_from_synthetic_inventory"
                    break
                if (
                    software.get("asset_id") != asset_id
                    or software.get("source_cve_id") != cve_id
                    or software.get("data_origin") != "synthetic_nvd_criterion_derived"
                    or software.get("source_configuration_index")
                    != selected_case.get("configuration_index")
                ):
                    reason = "installation_provenance_does_not_support_relationship"
                    break
        if reason is None:
            for row in rows:
                if (
                    row.get("in_kev") not in {"True", "False"}
                    or row.get("in_kev") != audit.get("in_kev")
                    or row.get("cvss_score") != audit.get("cvss_score")
                ):
                    reason = "match_and_audit_vulnerability_evidence_disagree"
                    break

        status = "eligible_for_scoring" if reason is None else "withheld"
        eligibility_rows.append({
            "asset_id": asset_id,
            "cve_id": cve_id,
            "eligibility_status": status,
            "reason": reason or "positive_case_and_phase3_audit_support_relationship",
            "case_id": selected_case["case_id"] if selected_case else "",
            "audit_status": audit.get("status", "") if audit else "",
            "matched_asset_count_after_tree_evaluation": (
                audit.get("matched_asset_count_after_tree_evaluation", "")
                if audit else ""
            ),
            "installation_ids": installation_ids,
        })
        if reason is None:
            relation_rows[(asset_id, cve_id)].extend(rows)
            relationship_case_ids[(asset_id, cve_id)] = selected_case["case_id"]

    scored_candidates: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    for (asset_id, cve_id), rows in sorted(relation_rows.items()):
        asset = assets_by_id[asset_id]
        audit = audit_by_cve[cve_id]
        row = rows[0]
        score = score_components(
            row.get("cvss_score"),
            row.get("in_kev"),
            asset.get("criticality"),
            asset.get("exposure"),
        )
        if score["missing_evidence"]:
            gaps.append({
                "asset_id": asset_id,
                "cve_id": cve_id,
                "missing_or_invalid_evidence": json.dumps(
                    score["missing_evidence"]
                ),
                "data_origin": SYNTHETIC_LIMITATION,
            })
            continue
        if any(
            score_components(
                other.get("cvss_score"),
                other.get("in_kev"),
                asset.get("criticality"),
                asset.get("exposure"),
            )["score"] != score["score"]
            for other in rows[1:]
        ):
            raise ValueError(f"Inconsistent risk inputs across installations for {asset_id}/{cve_id}")

        components = score["components"]
        context = {
            "criticality": asset["criticality"],
            "exposure": asset["exposure"],
            "environment": asset.get("environment", ""),
            "asset_type": asset.get("asset_type", ""),
            "business_unit": asset.get("business_unit", ""),
        }
        installations_for_relation = [
            installations_by_id[installation_id]
            for installation_id in sorted({item["installation_id"] for item in rows})
        ]
        reasons = [
            f"CVSS {float(row['cvss_score']):g} contributes {components['severity']:g} severity points",
            (
                f"CISA KEV membership contributes {components['kev']:g} points"
                if row["in_kev"] == "True"
                else "No KEV bonus: CVE is absent from the staged CISA KEV snapshot"
            ),
            f"{asset['criticality']} criticality contributes {components['criticality']:g} points",
            f"{asset['exposure']} exposure contributes {components['exposure']:g} points",
        ]
        evidence = {
            "severity": {
                "value": row["cvss_score"],
                "version": row["cvss_version"],
                "source": "NVD-normalized severity carried in the Phase 3 match and CVE audit",
                "score_component": components["severity"],
            },
            "kev": {
                "member": row["in_kev"] == "True",
                "date_added": row.get("kev_date_added", ""),
                "source": "CISA KEV membership carried in the Phase 3 match and CVE audit",
                "score_component": components["kev"],
            },
            "criticality": {
                "value": asset["criticality"],
                "source": "synthetic enterprise_assets.csv; generated test context",
                "score_component": components["criticality"],
            },
            "exposure": {
                "value": asset["exposure"],
                "source": "synthetic enterprise_assets.csv; generated test context",
                "score_component": components["exposure"],
            },
            "candidate_relationship": {
                "case_id": relationship_case_ids[(asset_id, cve_id)],
                "configuration_index": row["configuration_index"],
                "phase3_audit_status": audit["status"],
                "match_method": row["match_method"],
                "installations": [
                    {
                        "installation_id": item["installation_id"],
                        "product": item["software_product"],
                        "version": item["software_version"],
                        "matched_criteria": next(
                            (
                                match["matched_criteria"]
                                for match in rows
                                if match["installation_id"] == item["installation_id"]
                            ),
                            "",
                        ),
                    }
                    for item in installations_for_relation
                ],
            },
        }
        scored_candidates.append({
            "asset_id": asset_id,
            "cve_id": cve_id,
            "risk_score": score["score"],
            "risk_tier": score["tier"],
            "cvss_score": row["cvss_score"],
            "cvss_version": row["cvss_version"],
            "severity_component": components["severity"],
            "in_kev": row["in_kev"],
            "kev_bonus_component": components["kev"],
            "kev_date_added": row.get("kev_date_added", ""),
            "criticality": asset["criticality"],
            "criticality_component": components["criticality"],
            "exposure": asset["exposure"],
            "exposure_component": components["exposure"],
            "asset_type": context["asset_type"],
            "business_unit": context["business_unit"],
            "environment": context["environment"],
            "scenario_type": asset["scenario_type"],
            "installation_ids": sorted({item["installation_id"] for item in rows}),
            "software_products": sorted({
                item["software_product"] for item in installations_for_relation
            }),
            "software_versions": sorted({
                item["software_version"] for item in installations_for_relation
            }),
            "matched_criteria": sorted({
                item["matched_criteria"] for item in rows
            }),
            "configuration_indices": sorted({
                item["configuration_index"] for item in rows
            }),
            "evidence_used": evidence,
            "ranking_reason": "; ".join(reasons) + f"; total score {score['score']:g} ({score['tier']} tier)",
            "uncertainties": [
                SYNTHETIC_LIMITATION,
                "CVSS is severity, not a calibrated organizational risk probability.",
                "Criticality and exposure are randomly generated scenario labels, not validated organizational measurements.",
                "The Phase 3 relationship is a local matcher candidate and is not independently confirmed production exposure.",
                "A missing KEV entry is not proof that a CVE is unexploited.",
            ],
            "data_origin": SYNTHETIC_LIMITATION,
        })

    eligibility_rows.sort(key=lambda item: (item["asset_id"], item["cve_id"]))
    return scored_candidates, eligibility_rows, gaps, summary


def _ranked_rows(
    scored: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    criticality_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    exposure_rank = {"internet-facing": 2, "internal": 1, "restricted": 0}
    return sorted(
        scored,
        key=lambda row: (
            -row["risk_score"],
            row["in_kev"] != "True",
            -float(row["cvss_score"]),
            -criticality_rank[row["criticality"]],
            -exposure_rank[row["exposure"]],
            row["cve_id"],
            row["asset_id"],
        ),
    )


def _asset_summary(
    assets: list[dict[str, str]],
    ranked: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in ranked:
        by_asset[row["asset_id"]].append(row)
    summaries = []
    for asset in assets:
        relations = by_asset.get(asset["asset_id"], [])
        top = relations[0] if relations else None
        summaries.append({
            "asset_id": asset["asset_id"],
            "scenario_type": asset.get("scenario_type", ""),
            "scored_relationship_count": len(relations),
            "kev_scored_relationship_count": sum(
                row["in_kev"] == "True" for row in relations
            ),
            "max_risk_score": top["risk_score"] if top else "",
            "top_risk_cve_id": top["cve_id"] if top else "",
            "top_risk_tier": top["risk_tier"] if top else "",
            "top_risk_reason": top["ranking_reason"] if top else "",
            "criticality": asset.get("criticality", ""),
            "exposure": asset.get("exposure", ""),
            "environment": asset.get("environment", ""),
            "asset_type": asset.get("asset_type", ""),
            "business_unit": asset.get("business_unit", ""),
            "risk_summary_status": (
                "scored_synthetic_candidate_relationships"
                if relations
                else "no_audit_supported_positive_relationship_scored_not_cleared"
            ),
            "data_origin": SYNTHETIC_LIMITATION,
            "uncertainties": json.dumps([
                SYNTHETIC_LIMITATION,
                "No score is not evidence that the asset is safe or vulnerability-free.",
                "Per-asset summary uses the maximum candidate relationship score; it is not a calibrated aggregate loss estimate.",
            ]),
        })
    return summaries


def _csv_content(
    rows: list[dict[str, Any]],
    fields: list[str],
    json_fields: set[str] | None = None,
) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    json_fields = json_fields or set()
    for row in rows:
        normalized = {}
        for key, value in row.items():
            normalized[key] = (
                json.dumps(value, sort_keys=True)
                if key in json_fields or isinstance(value, (list, dict))
                else value
            )
        writer.writerow(normalized)
    return buffer.getvalue()


def score_experiment(
    input_dir: Path = DEFAULT_INPUT,
    inventory_dir: Path = DEFAULT_INVENTORY,
    snapshot_date: str = DEFAULT_DATE,
    config: RiskScoringConfig = RiskScoringConfig(),
) -> dict[str, Any]:
    config.validate()
    input_dir = input_dir.resolve()
    inventory_dir = inventory_dir.resolve()
    paths = _resolve_inputs(input_dir, inventory_dir)
    generation_manifest = _read_json(paths["generation_manifest"])
    _verify_generation_provenance(generation_manifest, paths, snapshot_date)
    scored, eligibility, gaps, phase3 = _join_source_relationships(
        paths, snapshot_date
    )
    ranked = _ranked_rows(scored)
    assets = _read_csv(paths["assets"])
    asset_summary = _asset_summary(assets, ranked)

    tier_counts = Counter(row["risk_tier"] for row in ranked)
    scoreable_eligibility = sum(
        row["eligibility_status"] == "eligible_for_scoring" for row in eligibility
    )
    inputs = {
        name: {
            "path": _display_path(path),
            "sha256": _sha256(path),
        }
        for name, path in sorted(paths.items())
    }
    report = {
        "project": "PRIORIS",
        "phase": 4,
        "report": "synthetic_context_aware_risk_scoring_prototype",
        "snapshot_date": snapshot_date,
        "data_origin": "synthetic NVD-aligned inventory and generated test scenarios",
        "interpretation": (
            "Prototype prioritization of synthetic candidate relationships only; "
            "not confirmed real-world enterprise exposure."
        ),
        "scoring_method": {
            "formula": (
                "risk_score = CVSS base score + KEV bonus * is_KEV "
                "+ criticality_step * criticality_level + exposure bonus"
            ),
            "criticality_levels": {"low": 0, "medium": 1, "high": 2, "critical": 3},
            "exposure_bonuses": {
                "restricted": 0.0,
                "internal": config.internal_bonus,
                "internet-facing": config.internet_facing_bonus,
            },
            "configuration": asdict(config),
            "score_bounds": [0.0, config.maximum_score],
            "risk_tiers": {
                "critical": f"score >= {config.critical_threshold}",
                "high": f"{config.high_threshold} <= score < {config.critical_threshold}",
                "medium": f"{config.medium_threshold} <= score < {config.high_threshold}",
                "low": f"score < {config.medium_threshold}",
            },
            "unavailable_or_excluded_fields": [
                "No exploit probability or exploit maturity score is synthesized from CVSS.",
                "No business-unit impact, asset value, service dependency, or financial loss score is available.",
                "Environment and asset type are reported but not weighted because their relative risk meaning is not established.",
            ],
        },
        "evidence_and_limitations": [
            SYNTHETIC_LIMITATION,
            "Only match rows traceable to one generated positive configuration case, matching derived installation provenance, and a positive Phase 3 local-configuration audit are eligible.",
            "Negative-control scenarios, unsupported/unmatched relationships, and the 77 affected-products custom-version records are not scored.",
            "CVSS is used as a severity input; this additive formula is an illustrative, configurable prototype, not a validated risk model.",
            "The input contains both CVSS 3.1 and 4.0 base scores; the prototype uses their reported 0-to-10 values directly and does not calibrate cross-version differences.",
            "Criticality and exposure are generated uniformly at random in the NVD-aligned experiment; they demonstrate context weighting but are not validated asset observations.",
            "KEV absence receives no bonus and is not evidence that exploitation is absent.",
            "A candidate match is not proof that a real asset is affected; all generated inventory and scenario fields are synthetic.",
        ],
        "input_files": inputs,
        "counts": {
            "synthetic_assets_in_summary": len(assets),
            "phase3_match_rows": int(
                phase3.get("results", {}).get("vulnerability_asset_match_rows", 0)
            ),
            "unique_phase3_asset_cve_relationships": len({
                (row["asset_id"], row["cve_id"])
                for row in _read_csv(paths["matches"])
            }),
            "relationships_with_generated_positive_case_and_audit_support": scoreable_eligibility,
            "scored_relationships": len(ranked),
            "relationships_withheld_by_eligibility": sum(
                row["eligibility_status"] == "withheld" for row in eligibility
            ),
            "relationships_with_missing_or_invalid_score_evidence": len(gaps),
            "assets_with_scored_relationships": sum(
                row["scored_relationship_count"] > 0 for row in asset_summary
            ),
            "risk_tier_counts": dict(sorted(tier_counts.items())),
            "kev_scored_relationships": sum(
                row["in_kev"] == "True" for row in ranked
            ),
        },
        "generation_manifest": {
            "random_seed": generation_manifest.get("random_seed"),
            "source_configurations": generation_manifest.get("counts", {}).get(
                "source_configurations"
            ),
            "positive_configuration_cases": generation_manifest.get("counts", {}).get(
                "positive_configuration_cases"
            ),
            "excluded_configurations": generation_manifest.get("counts", {}).get(
                "excluded_configurations"
            ),
        },
    }
    return {
        "ranked_risks": ranked,
        "asset_summary": asset_summary,
        "eligibility": eligibility,
        "gaps": gaps,
        "report": report,
    }


def write_reports(result: dict[str, Any], output_dir: Path) -> None:
    output_dir = output_dir.resolve()
    outputs = {
        "ranked_asset_cve_risks.csv": _csv_content(
            result["ranked_risks"],
            RISK_FIELDS,
        ),
        "per_asset_risk_summary.csv": _csv_content(
            result["asset_summary"],
            ASSET_FIELDS,
        ),
        "relationship_eligibility_audit.csv": _csv_content(
            result["eligibility"],
            ELIGIBILITY_FIELDS,
        ),
        "scoring_evidence_gaps.csv": _csv_content(
            result["gaps"],
            GAP_FIELDS,
        ),
        "risk_scoring_summary.json": json.dumps(result["report"], indent=2),
    }
    existing = [output_dir / name for name in outputs if (output_dir / name).exists()]
    if existing:
        raise FileExistsError(
            "Risk prototype outputs already exist; refusing to overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (output_dir / name).write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score audit-supported NVD-aligned synthetic CVE/asset candidates."
    )
    parser.add_argument("--date", default=DEFAULT_DATE)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--inventory-dir", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--kev-bonus", type=float, default=2.0)
    parser.add_argument("--criticality-step", type=float, default=1.0)
    parser.add_argument("--internet-facing-bonus", type=float, default=2.0)
    parser.add_argument("--internal-bonus", type=float, default=1.0)
    parser.add_argument("--medium-threshold", type=float, default=6.0)
    parser.add_argument("--high-threshold", type=float, default=10.0)
    parser.add_argument("--critical-threshold", type=float, default=14.0)
    args = parser.parse_args(argv)
    config = RiskScoringConfig(
        kev_bonus=args.kev_bonus,
        criticality_step=args.criticality_step,
        internet_facing_bonus=args.internet_facing_bonus,
        internal_bonus=args.internal_bonus,
        medium_threshold=args.medium_threshold,
        high_threshold=args.high_threshold,
        critical_threshold=args.critical_threshold,
    )
    try:
        result = score_experiment(
            args.input_dir,
            args.inventory_dir,
            args.date,
            config,
        )
        write_reports(result, args.output_dir)
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as exc:
        print(f"ERROR: risk scoring prototype failed: {exc}", file=sys.stderr)
        return 2
    counts = result["report"]["counts"]
    print(
        f"Scored {counts['scored_relationships']} audit-supported synthetic "
        f"asset-CVE relationships across {counts['assets_with_scored_relationships']} assets."
    )
    print(f"Reports written to {args.output_dir.resolve()}")
    print("These are synthetic candidate rankings, not real-world exposure findings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
