"""Run the provenance-backed, independent CPE matcher golden cases."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "matcher_validation" / "golden_cases.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.match_vulnerabilities import (
    InventoryIndex,
    all_cpe_terms,
    audit_status,
    compare_versions,
    component_matches,
    cpe_term_matches_installation,
    evaluate_configuration_indexed,
    load_raw_configuration_map,
    unique_match_pairs,
)


def _installation_rows(fixture: dict[str, Any], case: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for installation_id in case.get("installations", []):
        source = fixture["installations"][installation_id]
        rows.append({
            "installation_id": installation_id,
            "asset_id": source["asset_id"],
            "cpe23_uri": source["cpe23_uri"],
        })
    return rows


def _resolve_template(value: Any, fixture: dict[str, Any]) -> Any:
    if isinstance(value, list):
        return [_resolve_template(item, fixture) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$term"}:
            return fixture["source_terms"][value["$term"]]["term"]
        return {key: _resolve_template(item, fixture) for key, item in value.items()}
    return value


def evaluate_case(fixture: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one bounded fixture without loading the production snapshot."""
    kind = case["kind"]
    if kind == "component_match":
        return {
            "observed": component_matches(case["pattern"], case["actual"]),
            "expected": case["expected"],
        }
    if kind == "cpe_term_match":
        term = {"criteria": case["pattern_cpe"], "vulnerable": True}
        installation = {"cpe23_uri": case["actual_cpe"]}
        return {
            "observed": cpe_term_matches_installation(term, installation),
            "expected": case["expected"],
        }
    if kind == "version_compare":
        return {
            "observed": compare_versions(case["left"], case["right"]),
            "expected": case["expected"],
        }
    if kind == "criterion_match":
        term = fixture["source_terms"][case["source_term"]]["term"]
        inventory = InventoryIndex(_installation_rows(fixture, case))
        matched = sorted(
            row["installation_id"]
            for rows in inventory.matches(term).values()
            for row in rows
        )
        unsupported_assets = sorted(inventory.unsupported_version_asset_ids(term))
        return {
            "observed": matched,
            "unsupported_assets": unsupported_assets,
            "expected": case["expected"],
        }
    if kind in {"configuration_match", "configuration_template"}:
        if kind == "configuration_match":
            config = fixture["source_configurations"][case["source_configuration"]][
                "configuration"
            ]
        else:
            config = _resolve_template(case["template"], fixture)
        inventory = InventoryIndex(_installation_rows(fixture, case))
        passed, pairs = evaluate_configuration_indexed(
            config, case["asset_id"], inventory
        )
        unique_pairs = unique_match_pairs(
            case["asset_id"],
            case["id"],
            pairs,
            set(),
        )
        return {
            "observed": {
                "satisfied": passed,
                "vulnerable_installations": sorted({
                    row["installation_id"] for row, _ in unique_pairs
                }),
            },
            "expected": case["expected"],
        }
    if kind == "audit_status":
        return {
            "observed": audit_status(**case["arguments"]),
            "expected": case["expected"],
        }
    raise ValueError(f"Unknown golden case kind: {kind}")


def _source_term(raw_configs: dict[str, list[dict[str, Any]]], source: dict[str, Any]):
    cve_id = source["cve_id"]
    config_index = source["configuration_index"]
    term_index = source["term_index"]
    try:
        config = raw_configs[cve_id][config_index]
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Source configuration not found for {source}") from exc
    terms = list(all_cpe_terms(config))
    try:
        return terms[term_index]
    except IndexError as exc:
        raise ValueError(f"Source CPE term not found for {source}") from exc


def _validate_provenance(fixture: dict[str, Any], date: str) -> dict[str, Any]:
    raw_dir = ROOT / "data" / "raw" / date
    for filename, expected_hash in fixture["source_files"].items():
        path = raw_dir / filename
        if not path.is_file():
            raise FileNotFoundError(f"Required provenance source is missing: {path}")
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(
                f"Source hash mismatch for {path}: expected {expected_hash}, got {actual_hash}"
            )

    raw_paths = [
        raw_dir / "nvd_general.json",
        raw_dir / "nvd_known_exploited.json",
    ]
    raw_configs, _, _, source_counts = load_raw_configuration_map(raw_paths)
    for name, reference in fixture["source_terms"].items():
        actual = _source_term(raw_configs, reference["source"])
        if actual != reference["term"]:
            raise ValueError(f"Fixture term {name!r} differs from its staged NVD source")
    for name, reference in fixture["source_configurations"].items():
        source = reference["source"]
        try:
            actual = raw_configs[source["cve_id"]][source["configuration_index"]]
        except (KeyError, IndexError) as exc:
            raise ValueError(f"Source configuration not found for {name!r}") from exc
        if actual != reference["configuration"]:
            raise ValueError(f"Fixture configuration {name!r} differs from its staged NVD source")

    configurations = [
        config for configs in raw_configs.values() for config in configs
    ]
    node_count = 0
    negated_node_count = 0
    non_vulnerable_term_count = 0
    maximum_depth = 0
    node_operator_counts: Counter[str] = Counter()

    def visit(value: Any, depth: int = 0, is_configuration: bool = False) -> None:
        nonlocal node_count, negated_node_count, non_vulnerable_term_count, maximum_depth
        if isinstance(value, list):
            for item in value:
                visit(item, depth)
        elif isinstance(value, dict):
            if not is_configuration and (
                "operator" in value or "cpeMatch" in value or "cpe_match" in value
            ):
                node_count += 1
                maximum_depth = max(maximum_depth, depth)
                if value.get("operator"):
                    node_operator_counts[str(value["operator"]).upper()] += 1
                if value.get("negate") is True:
                    negated_node_count += 1
                non_vulnerable_term_count += sum(
                    term.get("vulnerable", False) is False
                    for term in (
                        value.get("cpeMatch") or value.get("cpe_match") or []
                    )
                    if isinstance(term, dict)
                )
            for key in ("nodes", "children"):
                children = value.get(key)
                if isinstance(children, list):
                    for child in children:
                        visit(child, depth + 1)

    for config in configurations:
        visit(config, is_configuration=True)
    configuration_operator_counts = Counter(
        str(config.get("operator", "OR")).upper()
        for config in configurations
    )
    multiple_root_configuration_count = sum(
        len(config.get("nodes") or config.get("children") or []) > 1
        for config in configurations
    )
    return {
        "source_record_counts": source_counts,
        "raw_cves_with_configurations": len(raw_configs),
        "structured_configuration_count": len(configurations),
        "configuration_node_count": node_count,
        "maximum_node_depth": maximum_depth,
        "configuration_operator_counts": dict(sorted(configuration_operator_counts.items())),
        "node_operator_counts": dict(sorted(node_operator_counts.items())),
        "multiple_root_configuration_count": multiple_root_configuration_count,
        "cves_with_multiple_configuration_objects": sum(
            len(configs) > 1 for configs in raw_configs.values()
        ),
        "negated_node_count": negated_node_count,
        "non_vulnerable_criterion_count": non_vulnerable_term_count,
        "verified_source_term_count": len(fixture["source_terms"]),
        "verified_source_configuration_count": len(fixture["source_configurations"]),
    }


def _classify(case: dict[str, Any], result: dict[str, Any]) -> str:
    status = case["status"]
    if status == "unsupported":
        if "expected_unsupported_assets" in case:
            expected_unsupported = sorted(case["expected_unsupported_assets"])
            if result["observed"] or result.get("unsupported_assets") != expected_unsupported:
                return "unsupported_diagnostic_mismatch"
        return "unsupported_not_scored"
    if status == "pending_review":
        return "pending_review_not_scored"
    if result["observed"] == result["expected"]:
        return "supported_pass"
    expected = result["expected"]
    observed = result["observed"]
    if isinstance(expected, list) and isinstance(observed, list):
        unexpected = set(observed) - set(expected)
        missing = set(expected) - set(observed)
        if unexpected and missing:
            return "false_positive_and_false_negative"
        if unexpected:
            return "false_positive"
        if missing:
            return "false_negative"
    if isinstance(expected, bool) and isinstance(observed, bool):
        return "false_positive" if observed else "false_negative"
    if isinstance(expected, dict) and isinstance(observed, dict):
        if expected.get("satisfied") != observed.get("satisfied"):
            return "false_positive" if observed.get("satisfied") else "false_negative"
        unexpected = (
            set(observed.get("vulnerable_installations", []))
            - set(expected.get("vulnerable_installations", []))
        )
        missing = (
            set(expected.get("vulnerable_installations", []))
            - set(observed.get("vulnerable_installations", []))
        )
        if unexpected and missing:
            return "false_positive_and_false_negative"
        if unexpected:
            return "false_positive"
        if missing:
            return "false_negative"
        return "relationship_mismatch"
    return "expectation_mismatch"


def run_validation(date: str) -> dict[str, Any]:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    if fixture["snapshot_date"] != date:
        raise ValueError(
            f"Fixture snapshot date {fixture['snapshot_date']} does not match --date {date}"
        )
    provenance = _validate_provenance(fixture, date)
    records = []
    for case in fixture["cases"]:
        result = evaluate_case(fixture, case)
        assessment = _classify(case, result)
        reference_ids = case.get("reference_ids", fixture["default_reference_ids"])
        unknown_references = set(reference_ids) - set(fixture["references"])
        if unknown_references:
            raise ValueError(
                f"Case {case['id']} refers to unknown references: "
                + ", ".join(sorted(unknown_references))
            )
        source_cves = set()
        referenced_terms = set(case.get("source_terms", []))
        if case.get("source_term"):
            referenced_terms.add(case["source_term"])
        for name in referenced_terms:
            source_cves.add(fixture["source_terms"][name]["source"]["cve_id"])
        if case.get("source_configuration"):
            source_cves.add(
                fixture["source_configurations"][case["source_configuration"]][
                    "source"
                ]["cve_id"]
            )
        records.append({
            "case_id": case["id"],
            "status": case["status"],
            "kind": case["kind"],
            "source_cves": sorted(source_cves),
            "reference_ids": reference_ids,
            "expected": result["expected"],
            "observed": result["observed"],
            "assessment": assessment,
            "investigation": case.get("investigation", {}),
            "justification": case["justification"],
        })

    assessments = Counter(record["assessment"] for record in records)
    summary = {
        "project": "PRIORIS",
        "report": "independent_cpe_matcher_golden_validation",
        "snapshot_date": date,
        "fixture_file": str(FIXTURE_PATH),
        "references": fixture["references"],
        "provenance": provenance,
        "counts": {
            "total_cases": len(records),
            "supported_cases": sum(case["status"] == "supported" for case in fixture["cases"]),
            "supported_passes": assessments["supported_pass"],
            "false_positives": (
                assessments["false_positive"]
                + assessments["false_positive_and_false_negative"]
            ),
            "false_negatives": (
                assessments["false_negative"]
                + assessments["false_positive_and_false_negative"]
            ),
            "other_supported_expectation_mismatches": (
                assessments["relationship_mismatch"] + assessments["expectation_mismatch"]
            ),
            "unsupported_cases": sum(case["status"] == "unsupported" for case in fixture["cases"]),
            "pending_review_cases": sum(
                case["status"] == "pending_review" for case in fixture["cases"]
            ),
            "unsupported_diagnostic_mismatches": assessments["unsupported_diagnostic_mismatch"],
        },
        "cases": records,
        "interpretation": [
            "Only cases marked supported are scored as conformance checks; pending_review and unsupported cases are not counted as passes.",
            "Golden outcomes are controlled local expectations derived from the cited CPE component rules and the verbatim staged NVD criterion/configuration data.",
            "A successful test establishes behavior only for the stated fixture, not full CPE/NVD conformance or production vulnerability applicability.",
        ],
    }
    return summary


def write_report(summary: dict[str, Any], output_dir: Path, force: bool) -> None:
    json_path = output_dir / "golden_validation.json"
    csv_path = output_dir / "golden_validation.csv"
    existing = [path for path in (json_path, csv_path) if path.exists()]
    if existing and not force:
        raise FileExistsError(
            "Validation outputs already exist; use --force to replace only these files: "
            + ", ".join(str(path) for path in existing)
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        fields = [
            "case_id", "status", "kind", "source_cves", "expected", "observed",
            "reference_ids", "assessment", "investigation", "justification",
        ]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in summary["cases"]:
            writer.writerow({
                **record,
                "source_cves": ";".join(record["source_cves"]),
                "reference_ids": ";".join(record["reference_ids"]),
                "expected": json.dumps(record["expected"], sort_keys=True),
                "observed": json.dumps(record["observed"], sort_keys=True),
                "investigation": json.dumps(record["investigation"], sort_keys=True),
            })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate the local CPE matcher against independent golden fixtures."
    )
    parser.add_argument("--date", default="2026-10-19", help="Staged NVD snapshot date.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Report directory (default: results/<date>-matcher-validation).",
    )
    parser.add_argument("--force", action="store_true", help="Replace only the validation reports.")
    args = parser.parse_args(argv)
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date) is None:
        parser.error("--date must use YYYY-MM-DD format.")
    output_dir = args.output_dir or Path("results") / f"{args.date}-matcher-validation"
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    try:
        summary = run_validation(args.date)
        write_report(summary, output_dir.resolve(), args.force)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    counts = summary["counts"]
    print(
        f"Golden validation: {counts['supported_passes']}/{counts['supported_cases']} "
        f"supported cases passed; {counts['false_positives']} false positives; "
        f"{counts['false_negatives']} false negatives; {counts['unsupported_cases']} unsupported; "
        f"{counts['pending_review_cases']} pending review."
    )
    print(f"Reports written to {output_dir.resolve()}")
    return 1 if (
        counts["false_positives"]
        or counts["false_negatives"]
        or counts["other_supported_expectation_mismatches"]
        or counts["unsupported_diagnostic_mismatches"]
    ) else 0
if __name__ == "__main__":
    raise SystemExit(main())
