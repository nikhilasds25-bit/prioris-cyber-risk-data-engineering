"""Generate reproducible synthetic inventory cases from staged NVD CPE criteria.

Generated assets and software are controlled test data, not an enterprise
inventory and not evidence of actual organizational exposure.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

try:
    from .match_vulnerabilities import (
        InventoryIndex,
        ROOT,
        _unsupported_version_comparison,
        _matches_version,
        all_cpe_terms,
        component_matches,
        evaluate_configuration_indexed,
        get_children,
        get_configurations,
        get_cve_id,
        get_terms,
        json_cves,
        read_json,
        split_cpe,
        term_criteria,
        unwrap_cve,
    )
except ImportError:
    from match_vulnerabilities import (
        InventoryIndex,
        ROOT,
        _unsupported_version_comparison,
        _matches_version,
        all_cpe_terms,
        component_matches,
        evaluate_configuration_indexed,
        get_children,
        get_configurations,
        get_cve_id,
        get_terms,
        json_cves,
        read_json,
        split_cpe,
        term_criteria,
        unwrap_cve,
    )


DEFAULT_DATE = "2026-10-19"
DEFAULT_OUTPUT = ROOT / "data" / "synthetic_nvd_aligned"
ASSET_FIELDS = [
    "asset_id", "asset_type", "business_unit", "criticality", "exposure",
    "environment", "data_origin", "scenario_type", "source_cve_id",
    "source_configuration_index", "generation_reason",
]
SOFTWARE_FIELDS = [
    "installation_id", "asset_id", "software_vendor", "software_product",
    "software_name", "software_version", "cpe23_uri", "data_origin",
    "source_cve_id", "source_configuration_index", "source_criteria",
    "generation_reason",
]
CASE_FIELDS = [
    "case_id", "source_cve_id", "configuration_index", "positive_asset_id",
    "control_asset_id", "expected_positive_match", "expected_control_match",
    "control_type", "case_status", "exclusion_reason",
]


def has_negated_node(value: Any) -> bool:
    if isinstance(value, list):
        return any(has_negated_node(item) for item in value)
    if not isinstance(value, dict):
        return False
    if value.get("negate") is True:
        return True
    return any(has_negated_node(value.get(key)) for key in ("nodes", "children"))


def _positive_version_candidates(term: dict[str, Any]) -> list[str]:
    criteria = term_criteria(term)
    parts = split_cpe(criteria or "")
    if parts is None:
        return []
    pattern_version = parts[5]
    bounds = tuple(
        str(term.get(key) or "")
        for key in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        )
    )
    candidates: list[str] = []

    def add(value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    if not any(bounds):
        if not any(char in pattern_version for char in "*?"):
            add(pattern_version)
        else:
            add(pattern_version.replace("*", "1").replace("?", "1"))
            add("1.0")
    else:
        for boundary in bounds:
            if not boundary:
                continue
            add(boundary)
            add(boundary + ".1")
            add(boundary + ".0.1")
            numeric_parts = boundary.split(".")
            if all(piece.isdigit() for piece in numeric_parts):
                last = numeric_parts[:]
                last[-1] = str(int(last[-1]) + 1)
                add(".".join(last))
                for zero_count in range(1, 9):
                    add(boundary + ".0" * zero_count + ".1")
        for fallback in ("0", "0.0", "1", "1.0", "2.0", "10.0", "9999.0"):
            add(fallback)

    return [
        version for version in candidates
        if _matches_version(term, pattern_version, version)
    ]


def _outside_version_candidates(term: dict[str, Any]) -> list[str]:
    criteria = term_criteria(term)
    parts = split_cpe(criteria or "")
    if parts is None:
        return []
    candidates: list[str] = []

    def add(value: str) -> None:
        if value and value not in candidates:
            candidates.append(value)

    pattern_version = parts[5]
    if pattern_version not in {"*", "-"} and not any(c in pattern_version for c in "*?"):
        add("0")
        add("1.0")
        add("999999.0")
    for key in (
        "versionStartIncluding", "versionStartExcluding",
        "versionEndIncluding", "versionEndExcluding",
    ):
        boundary = str(term.get(key) or "")
        if not boundary:
            continue
        add(boundary)
        add(boundary + ".0.1")
        add(boundary + ".1")
        pieces = boundary.split(".")
        if all(piece.isdigit() for piece in pieces):
            lower = pieces[:]
            if int(lower[-1]) > 0:
                lower[-1] = str(int(lower[-1]) - 1)
                add(".".join(lower))
            else:
                add("0")
            upper = pieces[:]
            upper[-1] = str(int(upper[-1]) + 1)
            add(".".join(upper))
    return [
        version for version in candidates
        if (
            not _matches_version(term, pattern_version, version)
            and not _unsupported_version_comparison(term, pattern_version, version)
        )
    ]


def _supported_term_solution(
    term: dict[str, Any], require_vulnerable: bool
) -> list[dict[str, Any]] | None:
    if require_vulnerable and term.get("vulnerable") is not True:
        return None
    if not term_criteria(term) or not _positive_version_candidates(term):
        return None
    return [term]


def _best_node_solution(
    node: dict[str, Any], require_vulnerable: bool
) -> list[dict[str, Any]] | None:
    if node.get("negate") is True:
        return None
    terms = get_terms(node)
    children = get_children(node)
    operands: list[tuple[str, Any]] = [("term", term) for term in terms]
    operands.extend(("child", child) for child in children)
    if not operands:
        return None

    operator = str(node.get("operator", "OR")).upper()
    if operator == "AND":
        term_solutions: list[list[dict[str, Any]]] = []
        for kind, operand in operands:
            if kind == "term":
                solution = _supported_term_solution(operand, False)
                if solution is None:
                    return None
                term_solutions.append(solution)
            else:
                solution = _best_node_solution(operand, False)
                if solution is None:
                    return None
                term_solutions.append(solution)
        combined = [term for solution in term_solutions for term in solution]
        if not require_vulnerable or any(
            term.get("vulnerable") is True for term in combined
        ):
            return combined
        best: list[dict[str, Any]] | None = None
        for index, (kind, operand) in enumerate(operands):
            if kind != "child":
                continue
            required_solution = _best_node_solution(operand, True)
            if required_solution is None:
                continue
            candidate = [
                term
                for part_index, solution in enumerate(term_solutions)
                for term in (
                    required_solution if part_index == index else solution
                )
            ]
            if best is None or len(candidate) < len(best):
                best = candidate
        return best

    candidates: list[list[dict[str, Any]]] = []
    for kind, operand in operands:
        if kind == "term":
            solution = _supported_term_solution(operand, require_vulnerable)
        else:
            solution = _best_node_solution(operand, require_vulnerable)
        if solution is not None:
            candidates.append(solution)
    return min(candidates, key=len) if candidates else None


def configuration_solution(
    configuration: dict[str, Any],
) -> list[dict[str, Any]] | None:
    if has_negated_node(configuration):
        return None
    selected = _best_node_solution(configuration, True)
    if selected is None:
        return None
    unique: dict[str, dict[str, Any]] = {}
    for term in selected:
        unique.setdefault(json.dumps(term, sort_keys=True), term)
    return list(unique.values())


def configuration_exclusion_reason(configuration: dict[str, Any]) -> str:
    if has_negated_node(configuration):
        return "configuration_contains_negation"
    terms = list(all_cpe_terms(configuration))
    if not any(term.get("vulnerable") is True for term in terms):
        return "configuration_has_no_vulnerable_criterion"
    if any(split_cpe(term_criteria(term) or "") is None for term in terms):
        return "configuration_contains_invalid_cpe_criterion"
    if any(not _positive_version_candidates(term) for term in terms):
        return "no_positive_version_under_supported_version_semantics"
    return "no_vulnerable_path_satisfies_supported_configuration_semantics"


def _materialized_cpe(term: dict[str, Any], version: str) -> str:
    parts = split_cpe(term_criteria(term) or "")
    if parts is None:
        raise ValueError(f"Invalid CPE criterion: {term_criteria(term)!r}")
    actual = list(parts)
    actual[5] = version
    return ":".join(actual)


def _row_from_term(
    term: dict[str, Any],
    version: str,
    asset_id: str,
    installation_id: str,
    cve_id: str,
    configuration_index: int,
    reason: str,
) -> dict[str, str]:
    cpe = _materialized_cpe(term, version)
    parts = split_cpe(cpe)
    assert parts is not None
    return {
        "installation_id": installation_id,
        "asset_id": asset_id,
        "software_vendor": parts[3],
        "software_product": parts[4],
        "software_name": f"{parts[3]} {parts[4]}",
        "software_version": version,
        "cpe23_uri": cpe,
        "data_origin": "synthetic_nvd_criterion_derived",
        "source_cve_id": cve_id,
        "source_configuration_index": str(configuration_index),
        "source_criteria": term_criteria(term) or "",
        "generation_reason": reason,
    }


def _installations_for_terms(
    terms: list[dict[str, Any]],
    asset_id: str,
    cve_id: str,
    configuration_index: int,
    first_installation_number: int,
) -> list[dict[str, str]] | None:
    rows: list[dict[str, str]] = []
    for offset, term in enumerate(terms):
        versions = _positive_version_candidates(term)
        if not versions:
            return None
        version = versions[0]
        if any(term.get(key) for key in (
            "versionStartIncluding", "versionStartExcluding",
            "versionEndIncluding", "versionEndExcluding",
        )):
            reason = "positive_version_satisfies_nvd_numeric_boundaries"
        elif split_cpe(term_criteria(term) or "")[5] != version:
            reason = "positive_version_selected_for_wildcard_criterion"
        else:
            reason = "positive_exact_version_from_nvd_criterion"
        if term.get("vulnerable") is not True:
            reason = "supporting_non_vulnerable_configuration_criterion"
        rows.append(_row_from_term(
            term, version, asset_id,
            f"CVSI-{first_installation_number + offset:08d}",
            cve_id, configuration_index, reason,
        ))
    return rows


def _negative_control_installations(
    positive_rows: list[dict[str, str]],
    terms: list[dict[str, Any]],
    configurations: list[dict[str, Any]],
    asset_id: str,
    cve_id: str,
    configuration_index: int,
    first_installation_number: int,
) -> tuple[list[dict[str, str]] | None, str]:
    controls: list[dict[str, str]] = []
    control_types: set[str] = set()
    for offset, (positive_row, term) in enumerate(zip(positive_rows, terms)):
        if term.get("vulnerable") is not True:
            row = dict(positive_row)
            row["asset_id"] = asset_id
            row["installation_id"] = f"CVSI-{first_installation_number + offset:08d}"
            row["generation_reason"] = "supporting_criterion_preserved_in_negative_control"
            controls.append(row)
            continue

        outside = _outside_version_candidates(term)
        if outside:
            row = _row_from_term(
                term, outside[0], asset_id,
                f"CVSI-{first_installation_number + offset:08d}",
                cve_id, configuration_index,
                "negative_control_outside_nvd_version_constraints",
            )
            control_types.add("version")
        else:
            source = split_cpe(term_criteria(term) or "")
            if source is None:
                return None, "invalid_source_criteria"
            changed = list(source)
            changed_index = next(
                (index for index in (3, 4, 2) if not any(c in changed[index] for c in "*?")),
                None,
            )
            if changed_index is None:
                return None, "no_concrete_component_for_negative_control"
            if changed_index == 2:
                changed[changed_index] = next(
                    part for part in ("a", "o", "h") if part != changed[changed_index]
                )
            else:
                changed[changed_index] = "synthetic_control_mismatch"
            row = _row_from_term(
                term, positive_row["software_version"], asset_id,
                f"CVSI-{first_installation_number + offset:08d}",
                cve_id, configuration_index,
                "negative_control_nonmatching_cpe_component",
            )
            row["cpe23_uri"] = ":".join(changed)
            row["software_vendor"] = changed[3]
            row["software_product"] = changed[4]
            control_types.add("product_component")
        controls.append(row)

    inventory = InventoryIndex(controls)
    for configuration in configurations:
        passed, pairs = evaluate_configuration_indexed(configuration, asset_id, inventory)
        if passed and pairs:
            return None, "constructed_control_still_matches_cve_configuration"
    control_type = "+".join(sorted(control_types)) if control_types else "supporting_only"
    return controls, control_type


def _asset_row(
    rng: random.Random,
    asset_id: str,
    cve_id: str,
    configuration_index: int,
    scenario: str,
    reason: str,
) -> dict[str, str]:
    return {
        "asset_id": asset_id,
        "asset_type": "coverage_candidate" if scenario == "positive" else "coverage_control",
        "business_unit": rng.choice([
            "Finance", "Human Resources", "Engineering", "IT Operations",
            "Payments", "Customer Support", "Research",
        ]),
        "criticality": rng.choice(["critical", "high", "medium", "low"]),
        "exposure": rng.choice(["internet-facing", "internal", "restricted"]),
        "environment": rng.choice(["production", "staging", "development", "test"]),
        "data_origin": "synthetic",
        "scenario_type": scenario,
        "source_cve_id": cve_id,
        "source_configuration_index": str(configuration_index),
        "generation_reason": reason,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generate_dataset(
    raw_paths: list[Path], output_dir: Path, seed: int = 42, force: bool = False
) -> dict[str, Any]:
    output_files = [
        output_dir / "enterprise_assets.csv",
        output_dir / "software_inventory.csv",
        output_dir / "configuration_cases.csv",
        output_dir / "generation_manifest.json",
    ]
    existing = [path for path in output_files if path.exists()]
    if existing and not force:
        raise FileExistsError(
            "Output already exists; refusing to overwrite: "
            + ", ".join(str(path) for path in existing)
            + ". Use --force only to replace these generated files."
        )

    configuration_map: dict[str, list[dict[str, Any]]] = {}
    signatures: dict[str, set[str]] = {}
    raw_source_counts: dict[str, int] = {}
    for path in raw_paths:
        if not path.is_file():
            continue
        records = json_cves(read_json(path))
        raw_source_counts[path.name] = len(records)
        for item in records:
            cve = unwrap_cve(item)
            cve_id = get_cve_id(cve)
            if not cve_id:
                continue
            seen = signatures.setdefault(cve_id, set())
            for config in get_configurations(cve, item):
                encoded = json.dumps(config, sort_keys=True)
                if encoded not in seen:
                    configuration_map.setdefault(cve_id, []).append(config)
                    seen.add(encoded)

    rng = random.Random(seed)
    assets: list[dict[str, str]] = []
    installations: list[dict[str, str]] = []
    cases: list[dict[str, str]] = []
    excluded_reasons: dict[str, int] = {}
    positive_count = 0
    control_count = 0
    next_installation = 1
    next_asset = 1

    configurations_total = sum(map(len, configuration_map.values()))
    configuration_number = 0
    started_at = time.perf_counter()
    for cve_id in sorted(configuration_map):
        for configuration_index, configuration in enumerate(configuration_map[cve_id], start=1):
            configuration_number += 1
            if configuration_number % 50 == 0 or configuration_number == configurations_total:
                elapsed = time.perf_counter() - started_at
                print(
                    f"[{elapsed:7.1f}s] Processing source configuration "
                    f"{configuration_number:,}/{configurations_total:,}; "
                    f"{positive_count:,} positive cases, {control_count:,} controls",
                    flush=True,
                )
            case_id = f"{cve_id}-CFG-{configuration_index:03d}"
            if has_negated_node(configuration):
                excluded_reasons["negated_configuration_excluded_from_positive_cases"] = (
                    excluded_reasons.get("negated_configuration_excluded_from_positive_cases", 0) + 1
                )
                cases.append({
                    "case_id": case_id,
                    "source_cve_id": cve_id,
                    "configuration_index": str(configuration_index),
                    "positive_asset_id": "",
                    "control_asset_id": "",
                    "expected_positive_match": "not_generated",
                    "expected_control_match": "not_generated",
                    "control_type": "",
                    "case_status": "excluded",
                    "exclusion_reason": "configuration_contains_negation",
                })
                continue

            solution = configuration_solution(configuration)
            if not solution:
                exclusion_reason = configuration_exclusion_reason(configuration)
                excluded_reasons[exclusion_reason] = excluded_reasons.get(exclusion_reason, 0) + 1
                cases.append({
                    "case_id": case_id,
                    "source_cve_id": cve_id,
                    "configuration_index": str(configuration_index),
                    "positive_asset_id": "",
                    "control_asset_id": "",
                    "expected_positive_match": "not_generated",
                    "expected_control_match": "not_generated",
                    "control_type": "",
                    "case_status": "excluded",
                    "exclusion_reason": exclusion_reason,
                })
                continue

            positive_asset_id = f"NCV-ASSET-{next_asset:07d}"
            positive_rows = _installations_for_terms(
                solution, positive_asset_id, cve_id, configuration_index, next_installation
            )
            if positive_rows is None:
                excluded_reasons["unsupported_positive_version"] = (
                    excluded_reasons.get("unsupported_positive_version", 0) + 1
                )
                cases.append({
                    "case_id": case_id,
                    "source_cve_id": cve_id,
                    "configuration_index": str(configuration_index),
                    "positive_asset_id": "",
                    "control_asset_id": "",
                    "expected_positive_match": "not_generated",
                    "expected_control_match": "not_generated",
                    "control_type": "",
                    "case_status": "excluded",
                    "exclusion_reason": "no_version_in_supported_semantics",
                })
                continue

            positive_inventory = InventoryIndex(positive_rows)
            passed, matched = evaluate_configuration_indexed(
                configuration, positive_asset_id, positive_inventory
            )
            if not passed or not matched:
                excluded_reasons["independent_positive_validation_failed"] = (
                    excluded_reasons.get("independent_positive_validation_failed", 0) + 1
                )
                cases.append({
                    "case_id": case_id,
                    "source_cve_id": cve_id,
                    "configuration_index": str(configuration_index),
                    "positive_asset_id": "",
                    "control_asset_id": "",
                    "expected_positive_match": "not_generated",
                    "expected_control_match": "not_generated",
                    "control_type": "",
                    "case_status": "excluded",
                    "exclusion_reason": "generated_positive_failed_matcher_validation",
                })
                continue

            assets.append(_asset_row(
                rng, positive_asset_id, cve_id, configuration_index,
                "positive", "configuration_satisfying_candidate_from_raw_nvd_criteria",
            ))
            installations.extend(positive_rows)
            next_installation += len(positive_rows)
            next_asset += 1
            positive_count += 1

            control_asset_id = f"NCV-ASSET-{next_asset:07d}"
            control_rows, control_type = _negative_control_installations(
                positive_rows, solution, configuration_map[cve_id], control_asset_id, cve_id,
                configuration_index, next_installation,
            )
            if control_rows is None:
                excluded_reasons[control_type] = excluded_reasons.get(control_type, 0) + 1
                control_asset_id = ""
                expected_control = "not_generated"
                case_status = "positive_only"
                control_type = ""
            else:
                assets.append(_asset_row(
                    rng, control_asset_id, cve_id, configuration_index,
                    "negative_control", f"nonmatching_{control_type}_control_for_same_source_configuration",
                ))
                installations.extend(control_rows)
                next_installation += len(control_rows)
                next_asset += 1
                control_count += 1
                expected_control = "no_match"
                case_status = "positive_and_control"

            cases.append({
                "case_id": case_id,
                "source_cve_id": cve_id,
                "configuration_index": str(configuration_index),
                "positive_asset_id": positive_asset_id,
                "control_asset_id": control_asset_id,
                "expected_positive_match": "candidate_match",
                "expected_control_match": expected_control,
                "control_type": control_type,
                "case_status": case_status,
                "exclusion_reason": "",
            })

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_files[0], assets, ASSET_FIELDS)
    _write_csv(output_files[1], installations, SOFTWARE_FIELDS)
    _write_csv(output_files[2], cases, CASE_FIELDS)
    summary = {
        "project": "PRIORIS",
        "experiment": "NVD-aligned synthetic coverage",
        "snapshot_date": raw_paths[0].parent.name if raw_paths else "",
        "random_seed": seed,
        "data_origin": "synthetic",
        "source_raw_files": [
            {"path": str(path), "sha256": _sha256(path), "records": raw_source_counts.get(path.name, 0)}
            for path in raw_paths if path.is_file()
        ],
        "counts": {
            "source_cves_with_configurations": len(configuration_map),
            "source_configurations": sum(map(len, configuration_map.values())),
            "positive_configuration_cases": positive_count,
            "negative_control_cases": control_count,
            "assets": len(assets),
            "software_installations": len(installations),
            "excluded_configurations": sum(int(row["case_status"] == "excluded") for row in cases),
            "exclusion_reasons": dict(sorted(excluded_reasons.items())),
        },
        "generation_notes": [
            "Each positive case is derived from one structured raw NVD configuration and includes a vulnerable criterion plus the selected AND/OR branch and required non-vulnerable supporting criteria.",
            "Configurations containing a negated node are excluded rather than simplified; the matcher evaluates negation in the separate controlled unit tests.",
            "Positive versions are exact criterion versions or tested numeric dotted versions satisfying the staged inclusive/exclusive boundaries.",
            "Negative controls change vulnerable versions outside supported constraints when possible; otherwise they change a concrete CPE component and are independently checked to fail the source configuration.",
            "NVD CPE text and criteria are preserved; generated records are synthetic coverage fixtures, not claims about real software deployments.",
            "Version syntax outside the matcher's numeric dotted range implementation is excluded from generated boundary-positive examples.",
        ],
    }
    output_files[3].write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a separate NVD-criteria-derived synthetic coverage inventory."
    )
    parser.add_argument("--date", default=DEFAULT_DATE, help="NVD snapshot date.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for asset context fields.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--force", action="store_true", help="Replace only this experiment's generated files.")
    args = parser.parse_args(argv)
    if not args.date or any(char not in "0123456789-" for char in args.date):
        parser.error("--date must use YYYY-MM-DD.")
    output_dir = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    output_dir = output_dir.resolve()
    raw_dir = ROOT / "data" / "raw" / args.date
    raw_paths = [raw_dir / "nvd_general.json", raw_dir / "nvd_known_exploited.json"]
    if not any(path.is_file() for path in raw_paths):
        parser.error(f"No raw NVD snapshot files found under {raw_dir}")
    try:
        summary = generate_dataset(raw_paths, output_dir, args.seed, args.force)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("PRIORIS — NVD-Aligned Synthetic Coverage Inventory", flush=True)
    print(f"Seed: {args.seed}", flush=True)
    for label, value in summary["counts"].items():
        print(f"{label}: {value}", flush=True)
    print(f"Output directory: {output_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
