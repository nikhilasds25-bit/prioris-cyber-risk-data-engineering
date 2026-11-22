"""Validate and analyze visitor inventories against the staged local snapshot."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pandas as pd

from src import match_vulnerabilities as matcher
from src.score_risks import RiskScoringConfig, score_components

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT_DATE = "2026-10-19"

ASSET_TEMPLATE_COLUMNS = [
    "asset_id",
    "asset_type",
    "business_unit",
    "criticality",
    "exposure",
    "environment",
    "data_origin",
]
SOFTWARE_TEMPLATE_COLUMNS = [
    "installation_id",
    "asset_id",
    "software_vendor",
    "software_product",
    "software_name",
    "software_version",
    "cpe23_uri",
    "data_origin",
]

ASSET_REQUIRED_COLUMNS = {"asset_id", "criticality", "exposure"}
SOFTWARE_REQUIRED_COLUMNS = {
    "installation_id",
    "asset_id",
    "software_vendor",
    "software_product",
    "software_name",
    "software_version",
    "cpe23_uri",
}

ASSET_CONTEXT_FIELDS = {
    "criticality": {"low", "medium", "high", "critical"},
    "exposure": {"restricted", "internal", "internet-facing"},
}

MATCHING_FINDING_FIELDS = [
    "asset_id",
    "cve_id",
    "risk_score",
    "risk_tier",
    "cvss_score",
    "cvss_version",
    "severity_component",
    "in_kev",
    "kev_bonus_component",
    "criticality",
    "criticality_component",
    "exposure",
    "exposure_component",
    "installation_ids",
    "software_products",
    "software_versions",
    "matched_criteria",
    "configuration_indices",
    "ranking_reason",
    "source_evidence",
    "uncertainties",
]

ASSET_SUMMARY_FIELDS = [
    "asset_id",
    "scored_candidate_count",
    "kev_candidate_count",
    "maximum_candidate_score",
    "top_candidate_cve_id",
    "top_candidate_tier",
    "criticality",
    "exposure",
    "asset_summary_status",
    "interpretation",
]

AUDIT_FIELDS = [
    "asset_id",
    "cve_id",
    "analysis_status",
    "reason",
    "source_evidence_status",
    "candidate_installation_ids",
    "matched_criteria",
    "missing_evidence",
    "interpretation",
]


@dataclass(frozen=True)
class InventoryValidation:
    assets: list[dict[str, str]]
    software: list[dict[str, str]]
    errors: list[str]
    asset_row_count: int
    software_row_count: int

    @property
    def valid(self) -> bool:
        return not self.errors and bool(self.assets) and bool(self.software)


@dataclass(frozen=True)
class UploadedAnalysis:
    findings: pd.DataFrame
    assets: pd.DataFrame
    audit: pd.DataFrame
    source_gaps: pd.DataFrame
    summary: dict[str, Any]
    source_snapshot: dict[str, Any]


def _read_csv_bytes(content: bytes, label: str) -> tuple[list[dict[str, str]], list[str]]:
    if not content:
        return [], [f"{label}: file is empty."]
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return [], [f"{label}: CSV must be UTF-8 encoded (optional UTF-8 BOM). {exc}"]
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if not reader.fieldnames:
            return [], [f"{label}: CSV has no header row."]
        headers = [name.strip() if name else "" for name in reader.fieldnames]
        if len(headers) != len(set(headers)):
            return [], [f"{label}: CSV contains duplicate column names."]
        reader.fieldnames = headers
        records: list[dict[str, str]] = []
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                return [], [
                    f"{label}: row {row_number} has more fields than the header."
                ]
            records.append({
                (key.strip() if key else ""): (value.strip() if value else "")
                for key, value in row.items()
            })
    except csv.Error as exc:
        return [], [f"{label}: invalid CSV structure: {exc}"]
    if not records:
        return [], [f"{label}: CSV contains a header but no data rows."]
    return records, []


def validate_inventory_csvs(
    asset_csv: bytes,
    software_csv: bytes,
) -> InventoryValidation:
    assets, asset_errors = _read_csv_bytes(asset_csv, "Asset inventory")
    software, software_errors = _read_csv_bytes(software_csv, "Software inventory")
    errors = [*asset_errors, *software_errors]
    if asset_errors or software_errors:
        return InventoryValidation(
            assets, software, errors, len(assets), len(software)
        )

    asset_headers = set(assets[0])
    software_headers = set(software[0])
    missing_asset_columns = sorted(ASSET_REQUIRED_COLUMNS - asset_headers)
    missing_software_columns = sorted(SOFTWARE_REQUIRED_COLUMNS - software_headers)
    if missing_asset_columns:
        errors.append(
            "Asset inventory is missing required columns: "
            + ", ".join(missing_asset_columns)
        )
    if missing_software_columns:
        errors.append(
            "Software inventory is missing required columns: "
            + ", ".join(missing_software_columns)
        )
    if missing_asset_columns or missing_software_columns:
        return InventoryValidation(
            assets, software, errors, len(assets), len(software)
        )

    assets_by_id: dict[str, dict[str, str]] = {}
    for row_number, row in enumerate(assets, start=2):
        asset_id = row.get("asset_id", "").strip()
        if not asset_id:
            errors.append(f"Asset inventory row {row_number}: asset_id is missing.")
            continue
        if asset_id in assets_by_id:
            errors.append(
                f"Asset inventory row {row_number}: duplicate asset_id "
                f"{asset_id!r}."
            )
        else:
            assets_by_id[asset_id] = row
        for field, accepted in ASSET_CONTEXT_FIELDS.items():
            value = row.get(field, "").strip().casefold()
            if not value:
                errors.append(
                    f"Asset inventory row {row_number} ({asset_id}): "
                    f"{field} is required for risk scoring."
                )
            elif value not in accepted:
                errors.append(
                    f"Asset inventory row {row_number} ({asset_id}): "
                    f"unsupported {field} {row.get(field)!r}; accepted values: "
                    + ", ".join(sorted(accepted))
                    + "."
                )

    installation_ids: set[str] = set()
    for row_number, row in enumerate(software, start=2):
        installation_id = row.get("installation_id", "").strip()
        asset_id = row.get("asset_id", "").strip()
        prefix = f"Software inventory row {row_number}"
        if not installation_id:
            errors.append(f"{prefix}: installation_id is missing.")
        elif installation_id in installation_ids:
            errors.append(
                f"{prefix}: duplicate installation_id {installation_id!r}."
            )
        installation_ids.add(installation_id)
        if not asset_id:
            errors.append(f"{prefix}: asset_id is missing.")
        elif asset_id not in assets_by_id:
            errors.append(
                f"{prefix}: asset_id {asset_id!r} does not exist in the asset inventory."
            )
        for field in (
            "software_vendor",
            "software_product",
            "software_name",
            "software_version",
            "cpe23_uri",
        ):
            if not row.get(field, "").strip():
                errors.append(f"{prefix} ({installation_id or 'unknown'}): {field} is required.")

        cpe_text = row.get("cpe23_uri", "").strip()
        parts = matcher.split_cpe(cpe_text)
        if cpe_text and parts is None:
            errors.append(
                f"{prefix} ({installation_id or 'unknown'}): cpe23_uri must be a valid CPE 2.3 formatted string."
            )
            continue
        if parts is None:
            continue
        for index, label in ((2, "part"), (3, "vendor"), (4, "product")):
            invalid_identifier = (
                parts[index] in {"", "*", "-"}
                or not matcher._component_is_exact(parts[index])
            )
            if label == "part" and parts[index] not in {"a", "o", "h"}:
                invalid_identifier = True
            if invalid_identifier:
                errors.append(
                    f"{prefix} ({installation_id or 'unknown'}): CPE {label} identifier must be a concrete supported value, not empty, wildcard, or not-applicable."
                )
        cpe_version = matcher.unescape_cpe_component(parts[5])
        software_version = row.get("software_version", "").strip()
        if (
            cpe_version in {"", "*", "-"}
            or not matcher._component_is_exact(parts[5])
        ):
            errors.append(
                f"{prefix} ({installation_id or 'unknown'}): CPE version must be explicit; wildcard or not-applicable versions cannot support version matching."
            )
        elif software_version and cpe_version.casefold() != software_version.casefold():
            errors.append(
                f"{prefix} ({installation_id or 'unknown'}): software_version does not match the CPE version component."
            )

    return InventoryValidation(
        assets,
        software,
        errors,
        len(assets),
        len(software),
    )


def load_source_snapshot(
    project_root: Path = ROOT,
    snapshot_date: str = DEFAULT_SNAPSHOT_DATE,
) -> dict[str, Any]:
    raw_dir = project_root / "data" / "raw" / snapshot_date
    processed_dir = project_root / "data" / "processed" / snapshot_date
    required = [
        raw_dir / "nvd_general.json",
        raw_dir / "nvd_known_exploited.json",
        raw_dir / "manifest.json",
        processed_dir / "nvd_cves.jsonl",
        processed_dir / "cisa_kev.jsonl",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "The staged source snapshot is incomplete; missing: "
            + ", ".join(missing)
            + ". Upload analysis requires local NVD and CISA files and will not "
            "download data or call external APIs."
        )
    with (raw_dir / "manifest.json").open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("snapshot_folder") != snapshot_date:
        raise ValueError(
            f"Staged source manifest date does not match {snapshot_date}."
        )
    try:
        raw_nvd_count = sum(
            len(matcher.json_cves(matcher.read_json(path)))
            for path in required[:2]
        )
        normalized_nvd_count = len(matcher.read_jsonl(processed_dir / "nvd_cves.jsonl"))
        normalized_cisa_count = len(matcher.read_jsonl(processed_dir / "cisa_kev.jsonl"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Staged source snapshot is invalid: {exc}") from exc
    if not raw_nvd_count or not normalized_nvd_count or not normalized_cisa_count:
        raise ValueError(
            "The staged NVD and CISA files must each contain source records; "
            "no upload data was analyzed."
        )
    return {
        "snapshot_date": snapshot_date,
        "retrieved_at_utc": manifest.get("retrieved_at_utc", ""),
        "cisa_catalog_version": manifest.get("cisa_catalog_version", ""),
        "nvd_record_count": raw_nvd_count,
        "normalized_nvd_record_count": normalized_nvd_count,
        "cisa_record_count": normalized_cisa_count,
        "raw_nvd_files": [str(path) for path in required[:2]],
        "normalized_nvd_file": str(processed_dir / "nvd_cves.jsonl"),
        "normalized_cisa_file": str(processed_dir / "cisa_kev.jsonl"),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _reason_for_score_gap(missing: list[str]) -> str:
    labels = {
        "valid_cvss_score_0_to_10": "staged NVD CVSS score is missing or invalid",
        "explicit_cisa_kev_membership": "staged CISA KEV membership evidence is invalid",
        "recognized_asset_criticality": "asset criticality is not supported",
        "recognized_asset_exposure": "asset exposure is not supported",
    }
    return "Risk score withheld because " + "; ".join(
        labels.get(item, item) for item in missing
    ) + "."


def _build_unsupported_candidate_rows(
    assets: list[dict[str, str]],
    software: list[dict[str, str]],
    source_snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    inventory = matcher.InventoryIndex(software)
    raw_paths = [Path(path) for path in source_snapshot["raw_nvd_files"]]
    configurations, _, _, _ = matcher.load_raw_configuration_map(raw_paths)
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for cve_id, cve_configurations in configurations.items():
        manual_reasons: set[str] = set()
        for config in cve_configurations:
            manual_reasons.update(matcher.configuration_manual_review_reasons(config))
        for config in cve_configurations:
            candidate_assets = matcher.configuration_candidate_assets(config, inventory)
            for term in matcher.all_cpe_terms(config):
                if term.get("vulnerable", False) is not True:
                    continue
                unsupported_assets = inventory.unsupported_version_asset_ids(term)
                criteria = matcher.term_criteria(term) or ""
                for asset_id in unsupported_assets:
                    key = (asset_id, cve_id)
                    row = rows.setdefault(key, {
                        "asset_id": asset_id,
                        "cve_id": cve_id,
                        "analysis_status": "withheld",
                        "reason": "Unsupported local version comparison; version ordering is not established by the matcher for this product/version format.",
                        "source_evidence_status": "Potential product/CPE candidate only; version applicability not evaluated.",
                        "candidate_installation_ids": set(),
                        "matched_criteria": set(),
                        "missing_evidence": set(),
                        "interpretation": "Not scored. This possible candidate is retained for review and is not a vulnerability finding.",
                    })
                    pattern = matcher.split_cpe(criteria)
                    if pattern is not None:
                        row["candidate_installation_ids"].update(
                            installation["installation_id"]
                            for actual, installations in inventory.entries
                            if matcher._matches_non_version_cpe_parts(pattern, actual)
                            for installation in installations
                            if installation["asset_id"] == asset_id
                        )
                    row["matched_criteria"].add(criteria)
        if manual_reasons:
            for config in cve_configurations:
                for asset_id in matcher.configuration_candidate_assets(config, inventory):
                    key = (asset_id, cve_id)
                    row = rows.setdefault(key, {
                        "asset_id": asset_id,
                        "cve_id": cve_id,
                        "analysis_status": "withheld",
                        "reason": "Configuration requires manual review: " + ", ".join(sorted(manual_reasons)) + ".",
                        "source_evidence_status": "Potential vulnerable-criterion product candidate; full configuration semantics not evaluated.",
                        "candidate_installation_ids": set(),
                        "matched_criteria": set(),
                        "missing_evidence": set(),
                        "interpretation": "Not scored. Configuration semantics are unresolved; this is neither a confirmed vulnerability nor a safety determination.",
                    })
                    for term in matcher.all_cpe_terms(config):
                        if term.get("vulnerable", False) is not True:
                            continue
                        for installation in inventory.matches(term).get(asset_id, ()):
                            row["candidate_installation_ids"].add(
                                installation["installation_id"]
                            )
                            row["matched_criteria"].add(
                                matcher.term_criteria(term) or ""
                            )

    for row in rows.values():
        row["candidate_installation_ids"] = sorted(row["candidate_installation_ids"])
        row["matched_criteria"] = sorted(row["matched_criteria"])
        row["missing_evidence"] = sorted(row["missing_evidence"])
    return list(rows.values())


def _score_match_rows(
    matches: list[dict[str, str]],
    audits: list[dict[str, str]],
    assets: list[dict[str, str]],
    source_snapshot: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assets_by_id = {row["asset_id"]: row for row in assets}
    audit_by_cve = {row["cve_id"]: row for row in audits}
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in matches:
        grouped[(row["asset_id"], row["cve_id"])].append(row)

    findings: list[dict[str, Any]] = []
    withheld: list[dict[str, Any]] = []
    for (asset_id, cve_id), rows in sorted(grouped.items()):
        audit = audit_by_cve.get(cve_id, {})
        asset = assets_by_id[asset_id]
        selected = rows[0]
        audit_status = audit.get("status", "")
        if (
            audit_status != "matched_assets_under_local_configuration_evaluation"
            or audit.get("risk_scoring_disposition")
            != "candidate_only_not_verified_exposure"
            or audit.get("manual_review_required") == "True"
        ):
            withheld.append({
                "asset_id": asset_id,
                "cve_id": cve_id,
                "analysis_status": "withheld",
                "reason": audit.get("manual_review_reasons")
                or f"Phase 3 audit status is not eligible for candidate scoring: {audit_status or 'missing audit row'}.",
                "source_evidence_status": "Phase 3 matcher row exists, but its CVE-level audit does not permit scoring.",
                "candidate_installation_ids": sorted({
                    row["installation_id"] for row in rows
                }),
                "matched_criteria": sorted({
                    row["matched_criteria"] for row in rows
                }),
                "missing_evidence": "",
                "interpretation": "Not scored. A withheld relationship is not evidence that the asset is safe or that the CVE affects it.",
            })
            continue

        consistency = {
            (row.get("cvss_score", ""), row.get("in_kev", ""))
            for row in rows
        }
        if len(consistency) != 1:
            withheld.append({
                "asset_id": asset_id,
                "cve_id": cve_id,
                "analysis_status": "withheld",
                "reason": "Matched installation rows disagree on CVSS or KEV evidence.",
                "source_evidence_status": "Inconsistent matcher output requires manual review.",
                "candidate_installation_ids": sorted({
                    row["installation_id"] for row in rows
                }),
                "matched_criteria": sorted({
                    row["matched_criteria"] for row in rows
                }),
                "missing_evidence": "conflicting_CVSS_or_KEV",
                "interpretation": "Not scored. Conflicting evidence is retained for review.",
            })
            continue

        score = score_components(
            selected.get("cvss_score"),
            selected.get("in_kev"),
            asset.get("criticality"),
            asset.get("exposure"),
        )
        if score["missing_evidence"]:
            withheld.append({
                "asset_id": asset_id,
                "cve_id": cve_id,
                "analysis_status": "withheld",
                "reason": _reason_for_score_gap(score["missing_evidence"]),
                "source_evidence_status": "Candidate match exists, but required scoring evidence is incomplete.",
                "candidate_installation_ids": sorted({
                    row["installation_id"] for row in rows
                }),
                "matched_criteria": sorted({
                    row["matched_criteria"] for row in rows
                }),
                "missing_evidence": score["missing_evidence"],
                "interpretation": "Not scored. Missing evidence is not replaced with a default.",
            })
            continue

        components = score["components"]
        reasons = [
            f"CVSS {float(selected['cvss_score']):g} contributes {components['severity']:g} points",
            (
                f"CISA KEV membership contributes {components['kev']:g} points"
                if selected["in_kev"] == "True"
                else "No KEV bonus: CVE is absent from the staged CISA KEV snapshot"
            ),
            f"{asset['criticality']} asset criticality contributes {components['criticality']:g} points",
            f"{asset['exposure']} asset exposure contributes {components['exposure']:g} points",
        ]
        finding = {
            "asset_id": asset_id,
            "cve_id": cve_id,
            "risk_score": score["score"],
            "risk_tier": score["tier"],
            "cvss_score": selected["cvss_score"],
            "cvss_version": selected.get("cvss_version", ""),
            "severity_component": components["severity"],
            "in_kev": selected["in_kev"],
            "kev_bonus_component": components["kev"],
            "criticality": asset["criticality"],
            "criticality_component": components["criticality"],
            "exposure": asset["exposure"],
            "exposure_component": components["exposure"],
            "installation_ids": sorted({row["installation_id"] for row in rows}),
            "software_products": sorted({row["software_product"] for row in rows}),
            "software_versions": sorted({row["software_version"] for row in rows}),
            "matched_criteria": sorted({row["matched_criteria"] for row in rows}),
            "configuration_indices": sorted({
                str(row["configuration_index"]) for row in rows
            }),
            "ranking_reason": "; ".join(reasons)
            + f"; total score {score['score']:g} ({score['tier']} tier).",
            "source_evidence": {
                "candidate_match_method": sorted({
                    row.get("match_method", "") for row in rows
                }),
                "phase3_audit_status": audit_status,
                "configuration_source": audit.get("configuration_source", ""),
                "cvss_source": "Staged normalized NVD record carried by the local Phase 3 matcher.",
                "kev_source": "Staged normalized CISA KEV record carried by the local Phase 3 matcher.",
                "asset_context_source": "Visitor-supplied enterprise asset CSV; values are user-provided and not independently verified.",
                "snapshot_date": source_snapshot["snapshot_date"],
                "scoring_formula": "CVSS + 2*KEV membership + criticality points + exposure points (existing Phase 4 defaults).",
                "score_components": components,
                "candidate_is_not_confirmed_exposure": True,
            },
            "uncertainties": [
                "Local Phase 3 CPE/configuration candidate only; not independently verified asset exposure.",
                "The user-supplied software inventory and business context are not independently verified.",
                "CVSS severity and the additive score are not calibrated to organizational loss or exploit probability.",
                "CVSS 3.1 and 4.0 base values are used directly and are not cross-version calibrated.",
                "Absence from the staged CISA KEV snapshot is not evidence that exploitation is absent.",
            ],
        }
        findings.append(finding)

    findings.sort(key=lambda row: (-row["risk_score"], row["cve_id"], row["asset_id"]))
    return findings, withheld


def _build_asset_summaries(
    assets: list[dict[str, str]],
    findings: list[dict[str, Any]],
    withheld: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings_by_asset: dict[str, list[dict[str, Any]]] = defaultdict(list)
    withheld_by_asset: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        findings_by_asset[finding["asset_id"]].append(finding)
    for row in withheld:
        withheld_by_asset[row["asset_id"]].add(row["cve_id"])
    summaries = []
    for asset in assets:
        asset_findings = findings_by_asset.get(asset["asset_id"], [])
        highest = asset_findings[0] if asset_findings else None
        summaries.append({
            "asset_id": asset["asset_id"],
            "scored_candidate_count": len(asset_findings),
            "kev_candidate_count": sum(
                row["in_kev"] == "True" for row in asset_findings
            ),
            "maximum_candidate_score": highest["risk_score"] if highest else "",
            "top_candidate_cve_id": highest["cve_id"] if highest else "",
            "top_candidate_tier": highest["risk_tier"] if highest else "",
            "criticality": asset.get("criticality", ""),
            "exposure": asset.get("exposure", ""),
            "asset_summary_status": (
                "supported_candidate_scores_available"
                if asset_findings
                else "no_supported_score_not_cleared"
            ),
            "interpretation": (
                f"{len(withheld_by_asset.get(asset['asset_id'], set()))} candidate relationship(s) withheld; "
                "no score or no match is not a safety determination."
            ),
        })
    return summaries


def _summary_text(
    summary: dict[str, Any],
    source_snapshot: dict[str, Any],
) -> str:
    return "\n".join([
        "PRIORIS uploaded-inventory analysis",
        f"Source snapshot: {source_snapshot['snapshot_date']}",
        f"Assets analyzed: {summary['asset_count']}",
        f"Software installations analyzed: {summary['software_installation_count']}",
        f"Supported candidate relationships scored: {summary['scored_relationship_count']}",
        f"Candidate relationships withheld for evidence review: {summary['withheld_relationship_count']}",
        f"CVE-level source evidence gaps: {summary['source_evidence_gap_count']}",
        f"Risk tiers: {json.dumps(summary['risk_tier_counts'], sort_keys=True)}",
        "",
        "A match is a local NVD configuration/CPE candidate, not confirmed exposure.",
        "A withheld candidate or lack of matches does not mean an asset is safe.",
        "Asset context was provided by the uploader and was not independently verified.",
        "Risk scores use the existing illustrative Phase 4 formula; they are not an operationally validated risk model.",
        "No uploaded inventory is permanently stored or sent to an external service by this local workflow.",
    ])


def analyze_uploaded_inventory(
    asset_csv: bytes,
    software_csv: bytes,
    *,
    project_root: Path = ROOT,
    snapshot_date: str = DEFAULT_SNAPSHOT_DATE,
) -> UploadedAnalysis:
    validation = validate_inventory_csvs(asset_csv, software_csv)
    if not validation.valid:
        raise ValueError(
            "Uploaded inventory validation failed: "
            + " ".join(validation.errors or ["Both files must contain data rows."])
        )
    source_snapshot = load_source_snapshot(project_root, snapshot_date)

    with tempfile.TemporaryDirectory(prefix="prioris-upload-") as temp_name:
        temp_root = Path(temp_name)
        inventory_dir = temp_root / "inventory"
        output_dir = temp_root / "phase3"
        inventory_dir.mkdir()
        _write_csv(
            inventory_dir / "enterprise_assets.csv",
            validation.assets,
            list(validation.assets[0]),
        )
        _write_csv(
            inventory_dir / "software_inventory.csv",
            validation.software,
            list(validation.software[0]),
        )
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with patch.object(matcher, "ROOT", project_root):
            with contextlib.redirect_stdout(stdout_buffer), contextlib.redirect_stderr(
                stderr_buffer
            ):
                status = matcher.main([
                    "--date",
                    snapshot_date,
                    "--inventory-dir",
                    str(inventory_dir),
                    "--output-dir",
                    str(output_dir),
                ])
        if status != 0:
            raise RuntimeError(
                "The local matcher could not complete using the staged source snapshot. "
                "No external calls were made and temporary upload files were removed."
            )

        matches = matcher.read_csv(output_dir / "vulnerability_asset_matches.csv")
        audits = matcher.read_csv(output_dir / "cve_configuration_audit.csv")
        findings, withheld = _score_match_rows(
            matches,
            audits,
            validation.assets,
            source_snapshot,
        )
        withheld.extend(
            _build_unsupported_candidate_rows(
                validation.assets,
                validation.software,
                source_snapshot,
            )
        )
        source_audit_rows = matcher.read_csv(
            output_dir / "cve_configuration_audit.csv"
        )

    unique_withheld: dict[tuple[str, str], dict[str, Any]] = {}
    for row in withheld:
        key = (row["asset_id"], row["cve_id"])
        existing = unique_withheld.get(key)
        if existing is None:
            unique_withheld[key] = row
        elif row["reason"] not in existing["reason"]:
            existing["reason"] += " " + row["reason"]
            existing["candidate_installation_ids"] = sorted(set(
                existing["candidate_installation_ids"]
            ) | set(row["candidate_installation_ids"]))
            existing["matched_criteria"] = sorted(set(
                existing["matched_criteria"]
            ) | set(row["matched_criteria"]))
    withheld = sorted(
        unique_withheld.values(),
        key=lambda row: (row["cve_id"], row["asset_id"]),
    )
    for row in withheld:
        for field in ("candidate_installation_ids", "matched_criteria", "missing_evidence"):
            if isinstance(row[field], (list, set)):
                row[field] = json.dumps(sorted(row[field]))

    audit_rows: list[dict[str, Any]] = []
    for finding in findings:
        audit_rows.append({
            "asset_id": finding["asset_id"],
            "cve_id": finding["cve_id"],
            "analysis_status": "scored_supported_candidate",
            "reason": finding["ranking_reason"],
            "source_evidence_status": "staged NVD configuration/CVSS and staged CISA KEV membership; local CPE candidate",
            "candidate_installation_ids": json.dumps(finding["installation_ids"]),
            "matched_criteria": json.dumps(finding["matched_criteria"]),
            "missing_evidence": "",
            "interpretation": "Scored candidate only; not confirmed real-world exposure.",
        })
    audit_rows.extend({
        **row,
        "candidate_installation_ids": (
            row["candidate_installation_ids"]
            if isinstance(row["candidate_installation_ids"], str)
            else json.dumps(row["candidate_installation_ids"])
        ),
        "matched_criteria": (
            row["matched_criteria"]
            if isinstance(row["matched_criteria"], str)
            else json.dumps(row["matched_criteria"])
        ),
        "missing_evidence": (
            row["missing_evidence"]
            if isinstance(row["missing_evidence"], str)
            else json.dumps(row["missing_evidence"])
        ),
    } for row in withheld)

    source_gaps = []
    for row in source_audit_rows:
        if row.get("risk_scoring_disposition") not in {
            "withhold_manual_review",
            "withhold_pending_version_review",
            "withhold_missing_configuration",
        }:
            continue
        source_gaps.append({
            "cve_id": row.get("cve_id", ""),
            "evaluation_status": row.get("evaluation_status", ""),
            "risk_scoring_disposition": row.get("risk_scoring_disposition", ""),
            "configuration_source": row.get("configuration_source", ""),
            "manual_review_reasons": row.get("manual_review_reasons", ""),
            "interpretation": (
                "CVE-level source limitation; no asset applicability is asserted. "
                "Candidate relationships are withheld where matcher evidence is insufficient."
            ),
        })

    risk_tiers = Counter(row["risk_tier"] for row in findings)
    summary = {
        "snapshot_date": snapshot_date,
        "source_snapshot": source_snapshot,
        "asset_count": validation.asset_row_count,
        "software_installation_count": validation.software_row_count,
        "matched_candidate_rows": len(matches),
        "scored_relationship_count": len(findings),
        "withheld_relationship_count": len(withheld),
        "source_evidence_gap_count": len(source_gaps),
        "risk_tier_counts": {
            tier: risk_tiers.get(tier, 0)
            for tier in ("critical", "high", "medium", "low")
        },
        "score_formula": (
            "CVSS base score + 2 * staged CISA KEV membership + "
            "criticality level (low/medium/high/critical = 0/1/2/3) + "
            "exposure (restricted/internal/internet-facing = 0/1/2)"
        ),
        "interpretation": (
            "Scores prioritize locally evaluated candidate relationships. "
            "They are not confirmed asset exposure or a validated operational risk model."
        ),
        "privacy": (
            "Uploaded CSVs are processed locally in temporary storage during analysis, "
            "then removed. They are not written to canonical project datasets or reports."
        ),
    }
    asset_rows = _build_asset_summaries(validation.assets, findings, withheld)
    return UploadedAnalysis(
        findings=pd.DataFrame(findings, columns=MATCHING_FINDING_FIELDS),
        assets=pd.DataFrame(asset_rows, columns=ASSET_SUMMARY_FIELDS),
        audit=pd.DataFrame(audit_rows, columns=AUDIT_FIELDS),
        source_gaps=pd.DataFrame(
            source_gaps,
            columns=[
                "cve_id",
                "evaluation_status",
                "risk_scoring_disposition",
                "configuration_source",
                "manual_review_reasons",
                "interpretation",
            ],
        ),
        summary=summary,
        source_snapshot=source_snapshot,
    )


def dataframe_csv_bytes(dataframe: pd.DataFrame) -> bytes:
    export = dataframe.copy()
    for column in export.columns:
        export[column] = export[column].map(
            lambda value: json.dumps(value, sort_keys=True)
            if isinstance(value, (list, dict, set))
            else value
        )
    return export.to_csv(index=False).encode("utf-8")


def summary_report_bytes(summary: dict[str, Any]) -> bytes:
    return _summary_text(summary, summary["source_snapshot"]).encode("utf-8")
