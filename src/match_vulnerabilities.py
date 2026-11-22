"""Match staged NVD CPE configuration criteria to PRIORIS synthetic assets.

This local matcher supports common CPE 2.3 component patterns and numeric
dotted-version boundaries. It is not a complete CPE name-binding or NVD
configuration evaluator. Results are candidate matches against illustrative
inventory, not verified production vulnerabilities.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_STARTED_AT = time.perf_counter()


def progress(message: str) -> None:
    elapsed = time.perf_counter() - _STARTED_AT
    print(f"[{elapsed:8.1f}s] {message}", flush=True)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on {path}, line {line_no}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Expected a JSON object on {path}, line {line_no}")
            rows.append(row)
    return rows


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def json_cves(document: Any) -> list[dict[str, Any]]:
    """Support NVD API 2.0 responses and older NVD 1.x feeds."""
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    if not isinstance(document, dict):
        return []
    if isinstance(document.get("vulnerabilities"), list):
        return [item for item in document["vulnerabilities"] if isinstance(item, dict)]
    if isinstance(document.get("CVE_Items"), list):
        return [item for item in document["CVE_Items"] if isinstance(item, dict)]
    result = document.get("result")
    if isinstance(result, dict) and isinstance(result.get("CVE_Items"), list):
        return [item for item in result["CVE_Items"] if isinstance(item, dict)]
    return []


def unwrap_cve(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve")
    return cve if isinstance(cve, dict) else item


def get_cve_id(cve: dict[str, Any]) -> str | None:
    value = cve.get("id")
    if not value:
        metadata = cve.get("CVE_data_meta")
        if isinstance(metadata, dict):
            value = metadata.get("ID")
    return str(value).strip() if value else None


def get_configurations(cve: dict[str, Any], item: dict[str, Any]) -> list[dict[str, Any]]:
    configs = cve.get("configurations")
    if configs is None:
        configs = item.get("configurations")
    if isinstance(configs, list):
        return [config for config in configs if isinstance(config, dict)]
    if isinstance(configs, dict):
        return [configs]
    return []


def get_terms(node: dict[str, Any]) -> list[dict[str, Any]]:
    terms = node.get("cpeMatch")
    if terms is None:
        terms = node.get("cpe_match")
    if not isinstance(terms, list):
        return []
    return [term for term in terms if isinstance(term, dict)]


def get_children(node: dict[str, Any]) -> list[dict[str, Any]]:
    children = node.get("nodes")
    if children is None:
        children = node.get("children")
    if not isinstance(children, list):
        return []
    return [child for child in children if isinstance(child, dict)]


def all_cpe_terms(value: Any):
    """Yield CPE match terms recursively from NVD v2 or legacy-style trees."""
    if isinstance(value, list):
        for item in value:
            yield from all_cpe_terms(item)
    elif isinstance(value, dict):
        yield from get_terms(value)
        for key in ("nodes", "children"):
            children = value.get(key)
            if isinstance(children, list):
                for child in children:
                    yield from all_cpe_terms(child)


def split_cpe(cpe: str) -> tuple[str, ...] | None:
    """Split a CPE 2.3 formatted string while respecting escaped colons."""
    parts: list[str] = []
    buffer: list[str] = []
    escaped = False
    for char in cpe.strip():
        if char == ":" and not escaped:
            parts.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)
        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False
    parts.append("".join(buffer))
    if len(parts) != 13 or parts[0].lower() != "cpe" or parts[1] != "2.3":
        return None
    return tuple(parts)


def unescape_cpe_component(value: str) -> str:
    """Conservatively unescape common punctuation in formatted CPE values."""
    return re.sub(r"\\([\\:!\"#$%&'()+,;<=>?@\[\]^`{|}~*-])", r"\1", value)


def component_matches(pattern: str, actual: str) -> bool:
    pattern = str(pattern).lower()
    actual = unescape_cpe_component(str(actual)).lower()
    regex_parts: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            index += 1
            regex_parts.append(re.escape(pattern[index]))
        elif char == "*":
            regex_parts.append(".*")
        elif char == "?":
            regex_parts.append(".")
        else:
            regex_parts.append(re.escape(char))
        index += 1
    return re.fullmatch("".join(regex_parts), actual, flags=re.IGNORECASE) is not None


def numeric_version_tokens(version: str) -> list[int] | None:
    """Return a numeric dotted-version representation or None if unsupported."""
    text = str(version).strip()
    if not text or text in {"*", "-"} or not re.fullmatch(r"\d+(?:\.\d+)*", text):
        return None
    return [int(piece) for piece in text.split(".")]


def compare_versions(left: str, right: str) -> int | None:
    """Compare numeric dotted versions; return None for unsupported formats."""
    left_tokens = numeric_version_tokens(left)
    right_tokens = numeric_version_tokens(right)
    if (
        left_tokens is None
        or right_tokens is None
        or len(left_tokens) != len(right_tokens)
    ):
        return None
    return (left_tokens > right_tokens) - (left_tokens < right_tokens)


_OPENSSL_HEARTBLEED_MATCH_CRITERIA_ID = "9EE79AC6-5484-4A53-8333-373DAD1B5649"
_OPENSSL_HEARTBLEED_VERSION_ORDER = {
    "1.0.1": 0,
    "1.0.1f": 1,
    "1.0.1g": 2,
}


def _compare_term_versions(
    term: dict[str, Any], left: str, right: str
) -> int | None:
    if left == right:
        return 0
    comparison = compare_versions(left, right)
    if comparison is not None:
        return comparison

    cpe = split_cpe(term_criteria(term) or "")
    if (
        cpe is None
        or cpe[2].lower() != "a"
        or unescape_cpe_component(cpe[3]).lower() != "openssl"
        or unescape_cpe_component(cpe[4]).lower() != "openssl"
        or str(term.get("matchCriteriaId", "")).upper()
        != _OPENSSL_HEARTBLEED_MATCH_CRITERIA_ID
    ):
        return None
    left_rank = _OPENSSL_HEARTBLEED_VERSION_ORDER.get(left.lower())
    right_rank = _OPENSSL_HEARTBLEED_VERSION_ORDER.get(right.lower())
    if left_rank is None or right_rank is None:
        return None
    return (left_rank > right_rank) - (left_rank < right_rank)


def term_criteria(term: dict[str, Any]) -> str | None:
    value = term.get("criteria") or term.get("cpe23Uri") or term.get("cpe23uri")
    return str(value) if value else None


def _term_boundaries(term: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(term.get("versionStartIncluding") or term.get("version_start_including") or ""),
        str(term.get("versionStartExcluding") or term.get("version_start_excluding") or ""),
        str(term.get("versionEndIncluding") or term.get("version_end_including") or ""),
        str(term.get("versionEndExcluding") or term.get("version_end_excluding") or ""),
    )


def _matches_version(term: dict[str, Any], pattern_version: str, actual_version: str) -> bool:
    start_including, start_excluding, end_including, end_excluding = _term_boundaries(term)
    has_range = any((start_including, start_excluding, end_including, end_excluding))

    if pattern_version != "*" and not component_matches(pattern_version, actual_version):
        return False
    if not has_range:
        return True
    if actual_version in {"", "*", "-"}:
        return False

    for boundary, relation in (
        (start_including, "ge"),
        (start_excluding, "gt"),
        (end_including, "le"),
        (end_excluding, "lt"),
    ):
        if not boundary:
            continue
        comparison = _compare_term_versions(term, actual_version, boundary)
        if comparison is None:
            return False
        if relation == "ge" and comparison < 0:
            return False
        if relation == "gt" and comparison <= 0:
            return False
        if relation == "le" and comparison > 0:
            return False
        if relation == "lt" and comparison >= 0:
            return False
    return True


def _unsupported_version_comparison(
    term: dict[str, Any], pattern_version: str, actual_version: str
) -> bool:
    boundaries = [boundary for boundary in _term_boundaries(term) if boundary]
    if not boundaries or actual_version in {"", "*", "-"}:
        return False
    if pattern_version != "*" and not component_matches(pattern_version, actual_version):
        return False
    return any(
        _compare_term_versions(term, actual_version, boundary) is None
        for boundary in boundaries
    )


def _matches_non_version_cpe_parts(
    pattern: tuple[str, ...], actual: tuple[str, ...]
) -> bool:
    return all(
        component_matches(pattern[index], actual[index])
        for index in range(2, 13)
        if index != 5
    )


def _matches_cpe_parts(
    term: dict[str, Any], pattern: tuple[str, ...], actual: tuple[str, ...]
) -> bool:
    if not _matches_non_version_cpe_parts(pattern, actual):
        return False
    return _matches_version(term, pattern[5], actual[5])


def cpe_term_matches_installation(term: dict[str, Any], installation: dict[str, str]) -> bool:
    criteria = term_criteria(term)
    pattern = split_cpe(criteria) if criteria else None
    actual = split_cpe(installation.get("cpe23_uri", ""))
    return pattern is not None and actual is not None and _matches_cpe_parts(term, pattern, actual)


def _component_is_exact(pattern: str) -> bool:
    index = 0
    while index < len(pattern):
        if pattern[index] == "\\":
            index += 2
            continue
        if pattern[index] in "*?":
            return False
        index += 1
    return True


class InventoryIndex:
    """Parsed CPE index with memoized criterion-to-installation matches."""

    def __init__(self, software_rows: list[dict[str, str]]) -> None:
        entries_by_cpe: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
        invalid_rows = 0
        for row in software_rows:
            parts = split_cpe(row.get("cpe23_uri", ""))
            if parts is None:
                invalid_rows += 1
                continue
            entries_by_cpe[parts].append(row)

        self.invalid_rows = invalid_rows
        self.entries: list[tuple[tuple[str, ...], list[dict[str, str]]]] = [
            (parts, rows) for parts, rows in entries_by_cpe.items()
        ]
        self.by_part: dict[str, list[int]] = defaultdict(list)
        self.by_part_vendor: dict[tuple[str, str], list[int]] = defaultdict(list)
        self.by_part_product: dict[tuple[str, str], list[int]] = defaultdict(list)
        self.by_part_vendor_product: dict[tuple[str, str, str], list[int]] = defaultdict(list)
        for entry_index, (parts, _) in enumerate(self.entries):
            part, vendor, product = (unescape_cpe_component(parts[i]).lower() for i in (2, 3, 4))
            self.by_part[part].append(entry_index)
            self.by_part_vendor[(part, vendor)].append(entry_index)
            self.by_part_product[(part, product)].append(entry_index)
            self.by_part_vendor_product[(part, vendor, product)].append(entry_index)

        self._matches_cache: dict[
            tuple[str, str, str, str, str], dict[str, tuple[dict[str, str], ...]]
        ] = {}
        self._unsupported_version_assets: dict[tuple[str, str, str, str, str], set[str]] = (
            defaultdict(set)
        )
        self.candidate_cpe_checks = 0

    @staticmethod
    def _cache_key(term: dict[str, Any]) -> tuple[str, str, str, str, str]:
        return (term_criteria(term) or "", *_term_boundaries(term))

    def unsupported_version_asset_ids(self, term: dict[str, Any]) -> set[str]:
        return self._unsupported_version_assets.get(self._cache_key(term), set())

    def _candidate_indexes(self, pattern: tuple[str, ...]) -> list[int]:
        part, vendor, product = (pattern[index] for index in (2, 3, 4))
        part_exact = _component_is_exact(part)
        vendor_exact = _component_is_exact(vendor)
        product_exact = _component_is_exact(product)
        normalized = tuple(
            unescape_cpe_component(value).lower() for value in (part, vendor, product)
        )
        if part_exact and vendor_exact and product_exact:
            return self.by_part_vendor_product.get(normalized, [])
        if part_exact and vendor_exact:
            return self.by_part_vendor.get(normalized[:2], [])
        if part_exact and product_exact:
            return self.by_part_product.get((normalized[0], normalized[2]), [])
        if part_exact:
            return self.by_part.get(normalized[0], [])
        return list(range(len(self.entries)))

    def matches(self, term: dict[str, Any]) -> dict[str, tuple[dict[str, str], ...]]:
        criteria = term_criteria(term)
        if not criteria:
            return {}
        cache_key = self._cache_key(term)
        cached = self._matches_cache.get(cache_key)
        if cached is not None:
            return cached

        pattern = split_cpe(criteria)
        matches_by_asset: dict[str, list[dict[str, str]]] = defaultdict(list)
        if pattern is not None:
            for entry_index in self._candidate_indexes(pattern):
                actual, installations = self.entries[entry_index]
                self.candidate_cpe_checks += 1
                if not _matches_cpe_parts(term, pattern, actual):
                    if (
                        _matches_non_version_cpe_parts(pattern, actual)
                        and _unsupported_version_comparison(term, pattern[5], actual[5])
                    ):
                        self._unsupported_version_assets[cache_key].update(
                            row["asset_id"] for row in installations
                        )
                    continue
                for installation in installations:
                    matches_by_asset[installation["asset_id"]].append(installation)

        result = {asset_id: tuple(rows) for asset_id, rows in matches_by_asset.items()}
        self._matches_cache[cache_key] = result
        return result


def combine_results(
    operator: str, results: list[tuple[bool, list[tuple[dict[str, str], dict[str, Any]]]]]
) -> tuple[bool, list[tuple[dict[str, str], dict[str, Any]]]]:
    if not results:
        return False, []
    operator = str(operator or "OR").upper()
    passed = [condition for condition, _ in results]
    condition = all(passed) if operator == "AND" else any(passed)
    if not condition:
        return False, []
    if operator == "AND":
        selected = [pair for _, pairs in results for pair in pairs]
    else:
        selected = [pair for result, pairs in results if result for pair in pairs]
    return True, selected


def evaluate_node_indexed(
    node: dict[str, Any], asset_id: str, inventory: InventoryIndex
) -> tuple[bool, list[tuple[dict[str, str], dict[str, Any]]]]:
    results: list[tuple[bool, list[tuple[dict[str, str], dict[str, Any]]]]] = []
    for term in get_terms(node):
        matching_rows = inventory.matches(term).get(asset_id, ())
        is_vulnerable = term.get("vulnerable", False) is True
        pairs = [(row, term) for row in matching_rows] if is_vulnerable else []
        results.append((bool(matching_rows), pairs))
    for child in get_children(node):
        results.append(evaluate_node_indexed(child, asset_id, inventory))
    condition, pairs = combine_results(str(node.get("operator", "OR")), results)
    if node.get("negate", False) is True:
        return not condition, []
    return condition, pairs if condition else []


def evaluate_configuration_indexed(
    config: dict[str, Any], asset_id: str, inventory: InventoryIndex
) -> tuple[bool, list[tuple[dict[str, str], dict[str, Any]]]]:
    roots = get_children(config)
    if not roots and (get_terms(config) or get_children(config)):
        roots = [config]
    if not roots:
        return False, []
    return combine_results(
        str(config.get("operator", "OR")),
        [evaluate_node_indexed(root, asset_id, inventory) for root in roots],
    )


def extract_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions")
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
                return str(item["value"])
    legacy = cve.get("description")
    if isinstance(legacy, dict):
        details = legacy.get("description_data")
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict) and item.get("value"):
                    return str(item["value"])
    return ""


def load_raw_configuration_map(raw_paths: list[Path]):
    config_by_id: dict[str, list[dict[str, Any]]] = {}
    config_signatures: dict[str, set[str]] = defaultdict(set)
    raw_ids: set[str] = set()
    existing_paths: list[str] = []
    source_counts: dict[str, int] = {}
    for path in raw_paths:
        if not path.is_file():
            continue
        existing_paths.append(str(path))
        records = json_cves(read_json(path))
        source_counts[path.name] = len(records)
        for item in records:
            cve = unwrap_cve(item)
            cve_id = get_cve_id(cve)
            if not cve_id:
                continue
            raw_ids.add(cve_id)
            for config in get_configurations(cve, item):
                encoded = json.dumps(config, sort_keys=True)
                if encoded not in config_signatures[cve_id]:
                    config_by_id.setdefault(cve_id, []).append(config)
                    config_signatures[cve_id].add(encoded)
    return config_by_id, raw_ids, existing_paths, source_counts


def enrichment_configuration_paths(enrichment_dir: Path, snapshot_date: str) -> list[Path]:
    manifest_path = enrichment_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"NVD enrichment manifest is missing: {manifest_path}")
    manifest = read_json(manifest_path)
    if manifest.get("source_snapshot_date") != snapshot_date:
        raise ValueError(
            "NVD enrichment source snapshot date does not match --date: "
            f"{manifest.get('source_snapshot_date')} != {snapshot_date}"
        )
    paths: list[Path] = []
    for record in manifest.get("records", []):
        if (
            record.get("classification") != "configuration_recovered"
            or record.get("http_status") != 200
        ):
            continue
        if not str(record.get("url", "")).startswith(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        ):
            raise ValueError(
                f"Recovered configuration does not cite the official NVD CVE API: "
                f"{record.get('cve_id')}"
            )
        relative = Path(record.get("file", ""))
        response_path = (enrichment_dir / relative).resolve()
        if not response_path.is_relative_to(enrichment_dir.resolve()):
            raise ValueError(f"Invalid NVD enrichment response path: {relative}")
        if not response_path.is_file():
            raise ValueError(f"NVD enrichment response is missing: {response_path}")
        digest = hashlib.sha256(response_path.read_bytes()).hexdigest()
        if digest != record.get("sha256"):
            raise ValueError(f"NVD enrichment response hash mismatch: {response_path}")
        response = read_json(response_path)
        records = response.get("vulnerabilities", [])
        expected_id = record.get("cve_id")
        matching = [
            item.get("cve", {})
            for item in records
            if isinstance(item, dict) and isinstance(item.get("cve"), dict)
            and item["cve"].get("id") == expected_id
        ] if isinstance(records, list) else []
        if not matching or not any(get_configurations(cve, {}) for cve in matching):
            raise ValueError(
                f"Manifest marks {expected_id} as recovered, but response has no "
                "structured configuration tree."
            )
        paths.append(response_path)
    return paths


def flatten_criteria(configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    terms: list[dict[str, Any]] = []
    seen: set[str] = set()
    for config in configurations:
        for term in all_cpe_terms(config):
            if term_criteria(term):
                encoded = json.dumps(term, sort_keys=True)
                if encoded not in seen:
                    terms.append(term)
                    seen.add(encoded)
    return terms


def configuration_candidate_assets(
    config: dict[str, Any], inventory: InventoryIndex
) -> set[str]:
    candidate_assets: set[str] = set()
    seen: set[str] = set()
    for term in all_cpe_terms(config):
        if term.get("vulnerable", False) is not True:
            continue
        signature = json.dumps(term, sort_keys=True)
        if signature in seen:
            continue
        seen.add(signature)
        candidate_assets.update(inventory.matches(term))
    return candidate_assets


def unique_match_pairs(
    asset_id: str,
    cve_id: str,
    pairs: list[tuple[dict[str, str], dict[str, Any]]],
    seen: set[tuple[str, str, str, str]],
) -> list[tuple[dict[str, str], dict[str, Any]]]:
    unique: list[tuple[dict[str, str], dict[str, Any]]] = []
    for installation, term in pairs:
        signature = (
            asset_id,
            cve_id,
            installation.get("installation_id", ""),
            term_criteria(term) or "",
        )
        if signature not in seen:
            seen.add(signature)
            unique.append((installation, term))
    return unique


def audit_status(
    configuration_count: int,
    criterion_hits: int,
    matched_asset_count: int,
    normalized_configuration_flag: Any,
    unsatisfied_candidate_config_count: int = 0,
    unsupported_version_candidate_count: int = 0,
) -> str:
    if matched_asset_count:
        if unsatisfied_candidate_config_count:
            return "matched_assets_and_other_product_criteria_candidates_failed_full_configuration"
        return "matched_assets_under_local_configuration_evaluation"
    if configuration_count and criterion_hits:
        return "product_criteria_hit_but_full_configuration_not_satisfied"
    if configuration_count and unsupported_version_candidate_count:
        return "unsupported_version_comparison_involved"
    if configuration_count:
        return "no_installed_product_version_matched_supported_criteria"
    if normalized_configuration_flag is True or str(normalized_configuration_flag).lower() == "true":
        return "configuration_flag_true_but_raw_configuration_missing"
    return "no_configuration_data_in_staged_raw_record"


def configuration_manual_review_reasons(config: dict[str, Any]) -> list[str]:
    """Return reasons a configuration must not enter automatic risk scoring."""
    reasons: set[str] = set()
    if not get_children(config):
        reasons.add("configuration_has_no_nodes")
    config_operator = config.get("operator")
    if config_operator is not None and str(config_operator).upper() not in {"AND", "OR"}:
        reasons.add("unsupported_configuration_operator")
    if config.get("negate") is True:
        reasons.add("negation_semantics_require_manual_review")

    def visit(node: dict[str, Any], depth: int) -> None:
        operator = node.get("operator")
        if str(operator or "").upper() not in {"AND", "OR"}:
            reasons.add("unsupported_configuration_operator")
        if depth > 1:
            reasons.add("nested_node_shape_not_defined_in_nvd_api_schema")
        if not get_terms(node) and not get_children(node):
            reasons.add("configuration_node_has_no_criteria")
        if "negate" in node and not isinstance(node["negate"], bool):
            reasons.add("invalid_negate_value")
        if node.get("negate") is True:
            reasons.add("negation_semantics_require_manual_review")
        for child in get_children(node):
            visit(child, depth + 1)

    for node in get_children(config):
        visit(node, 1)
    return sorted(reasons)


def classify_evaluation_status(
    configuration_count: int,
    candidate_match_count: int,
    unsupported_version_candidate_count: int,
    manual_review_required: bool,
) -> str:
    if configuration_count <= 0:
        return "missing_configuration_data"
    if manual_review_required or (
        candidate_match_count > 0 and unsupported_version_candidate_count > 0
    ):
        return "pending_manual_review"
    if unsupported_version_candidate_count > 0:
        return "unsupported_version_comparison"
    if candidate_match_count > 0:
        return "confirmed_candidate_match"
    return "evaluated_no_match"


def risk_scoring_disposition(evaluation_status: str) -> str:
    return {
        "confirmed_candidate_match": "candidate_only_not_verified_exposure",
        "evaluated_no_match": "no_candidate_to_score",
        "unsupported_version_comparison": "withhold_pending_version_review",
        "missing_configuration_data": "withhold_missing_configuration",
        "pending_manual_review": "withhold_manual_review",
    }[evaluation_status]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Match staged NVD CPE configuration criteria to PRIORIS synthetic assets."
    )
    parser.add_argument("--date", default="2026-10-19", help="Snapshot date folder (default: 2026-10-19).")
    parser.add_argument(
        "--inventory-dir",
        type=Path,
        help="Inventory directory (default: data/synthetic under the project root).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Report directory (default: results/<date> under the project root).",
    )
    parser.add_argument(
        "--enrichment-dir",
        type=Path,
        help="Optional dated NVD enrichment directory with provenance-verified configurations.",
    )
    parser.add_argument("--force", action="store_true", help="Replace existing Phase 3 output files.")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        parser.error("--date must use YYYY-MM-DD format.")

    processed = ROOT / "data" / "processed" / args.date
    raw_dir = ROOT / "data" / "raw" / args.date
    inventory_dir = args.inventory_dir or Path("data") / "synthetic"
    if not inventory_dir.is_absolute():
        inventory_dir = ROOT / inventory_dir
    inventory_dir = inventory_dir.resolve()
    assets_path = inventory_dir / "enterprise_assets.csv"
    software_path = inventory_dir / "software_inventory.csv"
    nvd_jsonl = processed / "nvd_cves.jsonl"
    kev_jsonl = processed / "cisa_kev.jsonl"
    raw_paths = [raw_dir / "nvd_general.json", raw_dir / "nvd_known_exploited.json"]
    required = [assets_path, software_path, nvd_jsonl, kev_jsonl]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        print("ERROR: Required project inputs are missing:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        return 2
    if not any(path.is_file() for path in raw_paths):
        print("ERROR: Neither expected raw NVD JSON file exists:", file=sys.stderr)
        for name in raw_paths:
            print(f"  - {name}", file=sys.stderr)
        return 2

    enrichment_dir = args.enrichment_dir
    enriched_cve_ids: set[str] = set()
    if enrichment_dir is not None:
        if not enrichment_dir.is_absolute():
            enrichment_dir = ROOT / enrichment_dir
        enrichment_dir = enrichment_dir.resolve()
        enriched_paths = enrichment_configuration_paths(enrichment_dir, args.date)
        enrichment_manifest = read_json(enrichment_dir / "manifest.json")
        enriched_cve_ids = {
            str(record["cve_id"])
            for record in enrichment_manifest.get("records", [])
            if record.get("classification") == "configuration_recovered"
            and record.get("http_status") == 200
        }
        raw_paths.extend(enriched_paths)
        progress(
            f"Verified {len(enriched_paths):,} recovered configuration responses from "
            f"{enrichment_dir}"
        )

    out_dir = args.output_dir or (Path("results") / args.date)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    out_dir = out_dir.resolve()
    matches_path = out_dir / "vulnerability_asset_matches.csv"
    audit_path = out_dir / "cve_configuration_audit.csv"
    asset_summary_path = out_dir / "asset_exposure_summary.csv"
    coverage_path = out_dir / "cpe_coverage.csv"
    summary_path = out_dir / "phase3_summary.json"
    output_paths = [matches_path, audit_path, asset_summary_path, coverage_path, summary_path]
    existing = [path for path in output_paths if path.exists()]
    if existing and not args.force:
        print("ERROR: Phase 3 outputs already exist. No files were changed.", file=sys.stderr)
        print("Use --force to replace only these Phase 3 output files:", file=sys.stderr)
        for path in existing:
            print(f"  - {path}", file=sys.stderr)
        return 2

    progress("Loading local Phase 1 and Phase 2 inputs")
    assets = read_csv(assets_path)
    software = read_csv(software_path)
    nvd_rows = read_jsonl(nvd_jsonl)
    kev_rows = read_jsonl(kev_jsonl)
    assets_by_id: dict[str, dict[str, str]] = {}
    for row in assets:
        asset_id = row.get("asset_id", "").strip()
        if not asset_id:
            raise ValueError("enterprise_assets.csv has a row with an empty asset_id")
        if asset_id in assets_by_id:
            raise ValueError(f"Duplicate asset_id in enterprise_assets.csv: {asset_id}")
        assets_by_id[asset_id] = row

    software_ids: set[str] = set()
    software_by_asset: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in software:
        asset_id = row.get("asset_id", "").strip()
        installation_id = row.get("installation_id", "").strip()
        if asset_id not in assets_by_id:
            raise ValueError(f"Orphan software row references unknown asset_id: {asset_id}")
        if not installation_id:
            raise ValueError("software_inventory.csv has a row with an empty installation_id")
        if installation_id in software_ids:
            raise ValueError(f"Duplicate installation_id in software_inventory.csv: {installation_id}")
        software_ids.add(installation_id)
        software_by_asset[asset_id].append(row)

    meta_by_id = {
        str(row["cve_id"]): row for row in nvd_rows if row.get("cve_id")
    }
    kev_by_id = {
        str(row["cve_id"]): row for row in kev_rows if row.get("cve_id")
    }
    progress(
        f"Loaded {len(assets_by_id):,} assets, {len(software):,} installations, "
        f"{len(meta_by_id):,} normalized CVEs, and {len(kev_by_id):,} KEV records"
    )

    config_by_id, raw_ids, raw_paths_found, raw_source_counts = load_raw_configuration_map(raw_paths)
    all_cve_ids = sorted(set(meta_by_id) | set(config_by_id) | raw_ids)
    progress(
        f"Loaded {len(raw_ids):,} raw CVEs with {sum(map(len, config_by_id.values())):,} "
        f"structured configurations across {len(config_by_id):,} CVEs"
    )

    inventory = InventoryIndex(software)
    progress(
        f"Indexed {len(inventory.entries):,} distinct installed CPEs; "
        f"{inventory.invalid_rows:,} inventory rows have invalid CPEs"
    )

    coverage_rows: list[dict[str, Any]] = []
    criterion_match_counts: dict[str, int] = {}
    criterion_install_counts: dict[str, int] = {}
    vulnerable_term_counts: dict[str, int] = {}
    unsupported_version_term_counts: dict[str, int] = {}
    unsupported_version_candidate_asset_counts: dict[str, int] = {}
    unsupported_version_asset_ids_by_cve: dict[str, set[str]] = {}
    for index, cve_id in enumerate(all_cve_ids, start=1):
        configurations = config_by_id.get(cve_id, [])
        terms = flatten_criteria(configurations)
        vulnerable_terms = [term for term in terms if term.get("vulnerable", False) is True]
        matched_asset_ids: set[str] = set()
        matched_installation_ids: set[str] = set()
        criterion_hits = 0
        unsupported_version_terms = 0
        unsupported_version_candidate_assets: set[str] = set()
        for term in terms:
            term_matches = inventory.matches(term)
            unsupported_assets = inventory.unsupported_version_asset_ids(term)
            if unsupported_assets:
                unsupported_version_terms += 1
                unsupported_version_candidate_assets.update(unsupported_assets)
            if term.get("vulnerable", False) is not True:
                continue
            if term_matches:
                criterion_hits += 1
                matched_asset_ids.update(term_matches)
                matched_installation_ids.update(
                    row["installation_id"]
                    for rows in term_matches.values()
                    for row in rows
                )
        criterion_match_counts[cve_id] = criterion_hits
        criterion_install_counts[cve_id] = len(matched_installation_ids)
        vulnerable_term_counts[cve_id] = len(vulnerable_terms)
        unsupported_version_term_counts[cve_id] = unsupported_version_terms
        unsupported_version_asset_ids_by_cve[cve_id] = unsupported_version_candidate_assets
        unsupported_version_candidate_asset_counts[cve_id] = len(
            unsupported_version_candidate_assets
        )
        coverage_rows.append({
            "cve_id": cve_id,
            "configuration_count": len(configurations),
            "vulnerable_criteria_count": len(vulnerable_terms),
            "vulnerable_criteria_with_inventory_hits": criterion_hits,
            "criteria_with_unsupported_version_comparisons": unsupported_version_terms,
            "unsupported_version_candidate_asset_count": len(unsupported_version_candidate_assets),
            "candidate_asset_count_ignoring_tree_logic": len(matched_asset_ids),
            "candidate_installation_count_ignoring_tree_logic": len(matched_installation_ids),
            "structured_configuration_available": bool(configurations),
            "coverage_status": (
                "vulnerable_criterion_candidate_found"
                if criterion_hits and not unsupported_version_terms
                else "vulnerable_candidate_and_unsupported_version_comparison"
                if criterion_hits
                else "unsupported_version_comparison_present"
                if unsupported_version_terms
                else "no_vulnerable_criterion_candidate"
            ) if configurations else "structured_configuration_missing",
            "configuration_source": (
                "nvd_api_enrichment"
                if cve_id in enriched_cve_ids
                else "staged_raw_snapshot"
                if configurations
                else "missing"
            ),
        })
        if index % 50 == 0 or index == len(all_cve_ids):
            progress(
                f"Evaluated vulnerable CPE criterion coverage for {index:,}/{len(all_cve_ids):,} CVEs; "
                f"{len(inventory._matches_cache):,} criterion variants cached"
            )

    match_rows: list[dict[str, Any]] = []
    matched_cves_by_asset: dict[str, set[str]] = defaultdict(set)
    kev_cves_by_asset: dict[str, set[str]] = defaultdict(set)
    max_cvss_by_asset: dict[str, float] = {}
    output_seen: set[tuple[str, str, str, str]] = set()
    unsatisfied_candidate_config_counts: dict[str, int] = {}
    full_config_candidate_pairs = 0
    pending_manual_review_candidate_pairs: dict[str, int] = {}
    manual_review_reasons_by_cve: dict[str, set[str]] = defaultdict(set)
    manual_review_candidate_assets_by_cve: dict[str, set[str]] = defaultdict(set)
    unsupported_candidate_assets_by_cve: dict[str, set[str]] = defaultdict(set)
    configuration_review_reasons: dict[tuple[str, int], list[str]] = {}
    for cve_id, configs in config_by_id.items():
        for config_index, config in enumerate(configs, start=1):
            reasons = configuration_manual_review_reasons(config)
            configuration_review_reasons[(cve_id, config_index)] = reasons
            manual_review_reasons_by_cve[cve_id].update(reasons)

    for cve_index, cve_id in enumerate(all_cve_ids, start=1):
        configs = config_by_id.get(cve_id, [])
        if not configs:
            continue
        meta = meta_by_id.get(cve_id, {})
        kev_info = kev_by_id.get(cve_id, {})
        score = meta.get("cvss_score", "")
        try:
            score_float = float(score) if score not in (None, "") else None
        except (TypeError, ValueError):
            score_float = None
        description = str(meta.get("description", ""))
        published = str(meta.get("published", ""))
        kev_date = str(kev_info.get("date_added", ""))
        in_kev = cve_id in kev_by_id
        cve_candidate_pairs: set[tuple[str, int]] = set()
        cve_satisfied_pairs: set[tuple[str, int]] = set()
        cve_pending_review_pairs: set[tuple[str, int]] = set()

        for config_index, config in enumerate(configs, start=1):
            candidate_assets = configuration_candidate_assets(config, inventory)
            cve_candidate_pairs.update((asset_id, config_index) for asset_id in candidate_assets)
            review_reasons = configuration_review_reasons.get(
                (cve_id, config_index), []
            )
            if review_reasons:
                cve_pending_review_pairs.update(
                    (asset_id, config_index) for asset_id in candidate_assets
                )
            if (
                manual_review_reasons_by_cve.get(cve_id)
                or unsupported_version_candidate_asset_counts.get(cve_id, 0)
            ):
                cve_pending_review_pairs.update(
                    (asset_id, config_index) for asset_id in candidate_assets
                )
                continue
            for asset_id in candidate_assets:
                passed, pairs = evaluate_configuration_indexed(config, asset_id, inventory)
                if not passed or not pairs:
                    continue
                cve_satisfied_pairs.add((asset_id, config_index))
                for installation, term in unique_match_pairs(asset_id, cve_id, pairs, output_seen):
                    criteria = term_criteria(term) or ""
                    install_id = installation["installation_id"]
                    asset_row = assets_by_id[asset_id]
                    start_inc, start_exc, end_inc, end_exc = _term_boundaries(term)
                    match_rows.append({
                        "asset_id": asset_id,
                        "asset_type": asset_row.get("asset_type", ""),
                        "business_unit": asset_row.get("business_unit", ""),
                        "criticality": asset_row.get("criticality", ""),
                        "exposure": asset_row.get("exposure", ""),
                        "environment": asset_row.get("environment", ""),
                        "installation_id": install_id,
                        "software_name": installation.get("software_name", ""),
                        "software_vendor": installation.get("software_vendor", ""),
                        "software_product": installation.get("software_product", ""),
                        "software_version": installation.get("software_version", ""),
                        "cpe23_uri": installation.get("cpe23_uri", ""),
                        "cve_id": cve_id,
                        "cvss_score": score if score is not None else "",
                        "cvss_version": meta.get("cvss_version", ""),
                        "in_kev": in_kev,
                        "kev_date_added": kev_date,
                        "published": published,
                        "configuration_index": config_index,
                        "matched_criteria": criteria,
                        "version_start_including": start_inc,
                        "version_start_excluding": start_exc,
                        "version_end_including": end_inc,
                        "version_end_excluding": end_exc,
                        "match_method": "local_cpe_criteria_and_supported_version_bounds",
                        "description": description,
                    })
                    matched_cves_by_asset[asset_id].add(cve_id)
                    if in_kev:
                        kev_cves_by_asset[asset_id].add(cve_id)
                    if score_float is not None:
                        previous = max_cvss_by_asset.get(asset_id)
                        max_cvss_by_asset[asset_id] = (
                            score_float if previous is None else max(previous, score_float)
                        )
        full_config_candidate_pairs += len(cve_candidate_pairs)
        unsatisfied_candidate_config_counts[cve_id] = len(
            cve_candidate_pairs - cve_satisfied_pairs
        )
        pending_manual_review_candidate_pairs[cve_id] = len(cve_pending_review_pairs)
        if manual_review_reasons_by_cve.get(cve_id):
            manual_review_candidate_assets_by_cve[cve_id].update(
                asset_id for asset_id, _ in cve_candidate_pairs
            )
        if unsupported_version_candidate_asset_counts.get(cve_id, 0):
            unsupported_candidate_assets_by_cve[cve_id].update(
                asset_id for asset_id, _ in cve_candidate_pairs
            )
            unsupported_candidate_assets_by_cve[cve_id].update(
                unsupported_version_asset_ids_by_cve.get(cve_id, set())
            )
        if cve_index % 25 == 0 or cve_index == len(all_cve_ids):
            progress(
                f"Evaluated complete configuration trees for CVE {cve_id} "
                f"({cve_index:,}/{len(all_cve_ids):,}); {len(match_rows):,} match rows so far"
            )

    manual_review_cves_by_asset: dict[str, set[str]] = defaultdict(set)
    unsupported_version_cves_by_asset: dict[str, set[str]] = defaultdict(set)
    for cve_id, asset_ids in manual_review_candidate_assets_by_cve.items():
        for asset_id in asset_ids:
            manual_review_cves_by_asset[asset_id].add(cve_id)
    for cve_id, asset_ids in unsupported_candidate_assets_by_cve.items():
        for asset_id in asset_ids:
            unsupported_version_cves_by_asset[asset_id].add(cve_id)

    matched_asset_ids_by_cve: dict[str, set[str]] = defaultdict(set)
    for row in match_rows:
        matched_asset_ids_by_cve[str(row["cve_id"])].add(str(row["asset_id"]))
    coverage_by_id = {str(row["cve_id"]): row for row in coverage_rows}
    audit_rows: list[dict[str, Any]] = []
    evaluation_status_by_cve: dict[str, str] = {}
    for cve_id in all_cve_ids:
        meta = meta_by_id.get(cve_id, {})
        configurations = config_by_id.get(cve_id, [])
        config_flag = meta.get("has_configurations", "")
        matched_asset_count = len(matched_asset_ids_by_cve.get(cve_id, set()))
        candidate_match_count = len(matched_asset_ids_by_cve.get(cve_id, set()))
        unsupported_candidate_count = unsupported_version_candidate_asset_counts.get(
            cve_id, 0
        )
        manual_review_reasons = sorted(manual_review_reasons_by_cve.get(cve_id, set()))
        evaluation_status = classify_evaluation_status(
            len(configurations),
            candidate_match_count,
            unsupported_candidate_count,
            bool(manual_review_reasons),
        )
        evaluation_status_by_cve[cve_id] = evaluation_status
        status = audit_status(
            len(configurations), criterion_match_counts.get(cve_id, 0),
            matched_asset_count, config_flag,
            unsatisfied_candidate_config_counts.get(cve_id, 0),
            unsupported_version_candidate_count=unsupported_version_candidate_asset_counts.get(
                cve_id, 0
            ),
        )
        kev_info = kev_by_id.get(cve_id, {})
        audit_rows.append({
            "cve_id": cve_id,
            "cvss_score": meta.get("cvss_score", ""),
            "in_kev": cve_id in kev_by_id,
            "kev_date_added": kev_info.get("date_added", ""),
            "present_in_normalized_nvd": cve_id in meta_by_id,
            "present_in_raw_nvd": cve_id in raw_ids,
            "has_configurations_flag": config_flag,
            "configuration_count": len(configurations),
            "vulnerable_criteria_count": vulnerable_term_counts.get(cve_id, 0),
            "vulnerable_criteria_with_inventory_hits": criterion_match_counts.get(cve_id, 0),
            "criteria_with_unsupported_version_comparisons": unsupported_version_term_counts.get(
                cve_id, 0
            ),
            "unsupported_version_candidate_asset_count": unsupported_version_candidate_asset_counts.get(
                cve_id, 0
            ),
            "candidate_asset_count_ignoring_tree_logic": coverage_by_id[cve_id][
                "candidate_asset_count_ignoring_tree_logic"
            ],
            "candidate_asset_configuration_pairs_not_satisfied": unsatisfied_candidate_config_counts.get(
                cve_id, 0
            ),
            "candidate_asset_configuration_pairs_pending_manual_review": (
                pending_manual_review_candidate_pairs.get(cve_id, 0)
            ),
            "matched_asset_count_after_tree_evaluation": matched_asset_count,
            "evaluation_status": evaluation_status,
            "manual_review_required": bool(manual_review_reasons),
            "manual_review_reasons": json.dumps(manual_review_reasons),
            "configuration_source": (
                "nvd_api_enrichment"
                if cve_id in enriched_cve_ids
                else "staged_raw_snapshot"
                if configurations
                else "missing"
            ),
            "risk_scoring_disposition": risk_scoring_disposition(evaluation_status),
            "status": status,
        })

    global_missing_configuration_count = sum(
        status == "missing_configuration_data"
        for status in evaluation_status_by_cve.values()
    )
    asset_summary_rows = [
        {
            "asset_id": asset_id,
            "asset_type": asset_row.get("asset_type", ""),
            "business_unit": asset_row.get("business_unit", ""),
            "criticality": asset_row.get("criticality", ""),
            "exposure": asset_row.get("exposure", ""),
            "environment": asset_row.get("environment", ""),
            "matched_cve_count": len(matched_cves_by_asset.get(asset_id, set())),
            "matched_kev_cve_count": len(kev_cves_by_asset.get(asset_id, set())),
            "max_matched_cvss_score": max_cvss_by_asset.get(asset_id, ""),
            "pending_manual_review_cve_count": len(
                manual_review_cves_by_asset.get(asset_id, set())
            ),
            "unsupported_version_cve_count": len(
                unsupported_version_cves_by_asset.get(asset_id, set())
            ),
            "global_missing_configuration_cve_count": global_missing_configuration_count,
            "risk_input_status": (
                "withheld_unresolved_candidate_evidence"
                if manual_review_cves_by_asset.get(asset_id)
                or unsupported_version_cves_by_asset.get(asset_id)
                else "incomplete_missing_configuration_data"
                if global_missing_configuration_count
                else "candidate_match_available"
                if matched_cves_by_asset.get(asset_id)
                else "no_candidate_match_not_cleared"
            ),
            "risk_scoring_disposition": (
                "withhold_manual_review"
                if manual_review_cves_by_asset.get(asset_id)
                else "withhold_pending_version_review"
                if unsupported_version_cves_by_asset.get(asset_id)
                else "withhold_missing_configuration"
                if global_missing_configuration_count
                else "candidate_only_not_verified_exposure"
                if matched_cves_by_asset.get(asset_id)
                else "no_candidate_to_score_not_cleared"
            ),
            "data_origin": "synthetic_asset_with_local_nvd_match_candidates",
        }
        for asset_id, asset_row in assets_by_id.items()
    ]

    progress(f"Writing five Phase 3 reports under {out_dir}")
    write_csv(matches_path, match_rows, [
        "asset_id", "asset_type", "business_unit", "criticality", "exposure", "environment",
        "installation_id", "software_name", "software_vendor", "software_product", "software_version",
        "cpe23_uri", "cve_id", "cvss_score", "cvss_version", "in_kev", "kev_date_added", "published",
        "configuration_index", "matched_criteria", "version_start_including", "version_start_excluding",
        "version_end_including", "version_end_excluding", "match_method", "description",
    ])
    write_csv(audit_path, audit_rows, [
        "cve_id", "cvss_score", "in_kev", "kev_date_added", "present_in_normalized_nvd",
        "present_in_raw_nvd", "has_configurations_flag", "configuration_count",
        "vulnerable_criteria_count", "vulnerable_criteria_with_inventory_hits",
        "criteria_with_unsupported_version_comparisons",
        "unsupported_version_candidate_asset_count",
        "candidate_asset_count_ignoring_tree_logic",
        "candidate_asset_configuration_pairs_not_satisfied",
        "candidate_asset_configuration_pairs_pending_manual_review",
        "matched_asset_count_after_tree_evaluation", "evaluation_status",
        "manual_review_required", "manual_review_reasons", "risk_scoring_disposition",
        "configuration_source", "status",
    ])
    write_csv(asset_summary_path, asset_summary_rows, [
        "asset_id", "asset_type", "business_unit", "criticality", "exposure", "environment",
        "matched_cve_count", "matched_kev_cve_count", "max_matched_cvss_score", "data_origin",
        "pending_manual_review_cve_count", "unsupported_version_cve_count",
        "global_missing_configuration_cve_count", "risk_input_status",
        "risk_scoring_disposition",
    ])
    write_csv(coverage_path, coverage_rows, [
        "cve_id", "configuration_count", "vulnerable_criteria_count",
        "vulnerable_criteria_with_inventory_hits",
        "criteria_with_unsupported_version_comparisons",
        "unsupported_version_candidate_asset_count",
        "candidate_asset_count_ignoring_tree_logic",
        "candidate_installation_count_ignoring_tree_logic", "structured_configuration_available",
        "coverage_status",
        "configuration_source",
    ])

    status_counts: dict[str, int] = defaultdict(int)
    for row in audit_rows:
        status_counts[str(row["status"])] += 1
    unique_asset_cve_pairs = len({
        (row["asset_id"], row["cve_id"]) for row in match_rows
    })
    summary = {
        "project": "PRIORIS",
        "phase": 3,
        "snapshot_date": args.date,
        "inventory_directory": str(inventory_dir),
        "output_directory": str(out_dir),
        "execution_seconds": round(time.perf_counter() - _STARTED_AT, 3),
        "input_counts": {
            "synthetic_assets": len(assets),
            "software_installations": len(software),
            "distinct_installed_cpes": len(inventory.entries),
            "normalized_nvd_records": len(nvd_rows),
            "cisa_kev_rows": len(kev_rows),
            "unique_cve_ids_seen": len(all_cve_ids),
            "raw_nvd_records_by_file": raw_source_counts,
            "raw_nvd_files_used": raw_paths_found,
            "nvd_enrichment_directory": str(enrichment_dir) if enrichment_dir else None,
            "nvd_enrichment_manifest_sha256": (
                hashlib.sha256((enrichment_dir / "manifest.json").read_bytes()).hexdigest()
                if enrichment_dir else None
            ),
            "nvd_enrichment_configuration_records": (
                len(enriched_paths) if enrichment_dir else 0
            ),
            "nvd_enriched_cve_ids": sorted(enriched_cve_ids),
            "cves_with_raw_configuration_data": len(config_by_id),
            "invalid_cpe_inventory_rows": inventory.invalid_rows,
        },
        "matching_work": {
            "cached_criterion_variants": len(inventory._matches_cache),
            "distinct_cpe_entries_checked_for_criteria": inventory.candidate_cpe_checks,
            "full_configuration_candidate_cve_config_pairs": full_config_candidate_pairs,
            "candidate_asset_cve_pairs_ignoring_tree_logic": sum(
                int(row["candidate_asset_count_ignoring_tree_logic"]) for row in coverage_rows
            ),
        },
        "outputs": {
            "vulnerability_asset_matches": str(matches_path),
            "cve_configuration_audit": str(audit_path),
            "asset_exposure_summary": str(asset_summary_path),
            "cpe_coverage": str(coverage_path),
            "phase3_summary": str(summary_path),
        },
        "results": {
            "vulnerability_asset_match_rows": len(match_rows),
            "unique_asset_cve_pairs": unique_asset_cve_pairs,
            "cves_with_unsupported_version_comparisons": sum(
                bool(count) for count in unsupported_version_term_counts.values()
            ),
            "unsupported_version_comparison_criterion_count": sum(
                unsupported_version_term_counts.values()
            ),
            "unsupported_version_candidate_asset_count": sum(
                unsupported_version_candidate_asset_counts.values()
            ),
            "assets_with_at_least_one_matched_cve": sum(
                bool(value) for value in matched_cves_by_asset.values()
            ),
            "assets_with_at_least_one_matched_kev_cve": sum(
                bool(value) for value in kev_cves_by_asset.values()
            ),
            "cve_audit_status_counts": dict(sorted(status_counts.items())),
            "cve_evaluation_status_counts": dict(sorted(Counter(
                str(row["evaluation_status"]) for row in audit_rows
            ).items())),
            "cves_with_candidate_matches_withheld_for_review": sum(
                row["evaluation_status"] in {
                    "pending_manual_review",
                    "unsupported_version_comparison",
                }
                and int(row["candidate_asset_count_ignoring_tree_logic"]) > 0
                for row in audit_rows
            ),
            "candidate_asset_configuration_pairs_withheld_for_review": sum(
                int(row["candidate_asset_configuration_pairs_pending_manual_review"])
                for row in audit_rows
            ),
            "cves_with_unsupported_versions_withheld_from_scoring": sum(
                row["evaluation_status"] == "unsupported_version_comparison"
                for row in audit_rows
            ),
        },
        "risk_scoring_guidance": {
            "controlled_integration_ready": False,
            "candidate_match_meaning": (
                "A confirmed_candidate_match means the local supported matcher satisfied "
                "the staged criteria and configuration; it is not verified production exposure."
            ),
            "withhold_from_automatic_scoring": [
                "unsupported_version_comparison",
                "missing_configuration_data",
                "pending_manual_review",
            ],
            "no_match_meaning": (
                "evaluated_no_match is a local evaluation result, not evidence that the "
                "product is safe or free of vulnerability."
            ),
        },
        "matching_limitations": [
            "CPE matching is a local simplified implementation, not the full CPE 2.3 name-binding specification.",
            "CPE escaping and wildcard matching cover common formatted-string cases; official CPE Match Criteria API semantics are not implemented.",
            "Version boundaries use a local numeric dotted comparator; unsupported comparisons are reported separately and are not counted as matches. Numeric dotted ordering is still product-specific and not universal.",
            "Only the CVE-2014-0160 OpenSSL criterion has a narrowly scoped release-order mapping, supported by the OpenSSL advisory and upstream release history; other alphanumeric versions remain unsupported.",
            "Configurations containing negation or nested child nodes beyond the NVD API schema shape are withheld for manual review, not automatically matched or treated as safe.",
            "NVD configuration roots are treated as alternatives; nested node AND/OR and negate flags are evaluated locally.",
            "Only structured configurations present in the staged raw NVD records are evaluated; missing configurations are reported, not inferred from descriptions.",
            "Synthetic software/CPE values are illustrative. Matches are locally evaluated candidates, not verified production vulnerabilities.",
            "CVSS is severity, not risk; this pipeline does not implement the final PRIORIS risk-scoring method.",
        ],
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    progress(
        f"Complete: {len(match_rows):,} relationship rows, {unique_asset_cve_pairs:,} unique "
        f"asset-CVE pairs, {summary['results']['assets_with_at_least_one_matched_cve']:,} "
        f"candidate assets; cache reused {len(inventory._matches_cache):,} criterion variants"
    )
    print("\nCVE audit statuses:", flush=True)
    for label, count in sorted(status_counts.items()):
        print(f"  {label}: {count}", flush=True)
    print("\nOutput files:", flush=True)
    for path in output_paths:
        print(f"  {path}", flush=True)
    print(
        "\nImportant: these are locally evaluated candidates against synthetic inventory, "
        "not verified production vulnerabilities.",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
