"""Profile saved NVD affected-product evidence without making vulnerability matches."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENRICHMENT = ROOT / "data" / "enrichment" / "2026-10-24"
DEFAULT_INVENTORY = ROOT / "data" / "synthetic" / "software_inventory.csv"
DEFAULT_OUTPUT = ROOT / "results" / "2026-10-19-affected-products-experiment"

CSV_FIELDS = [
    "cve_id",
    "source",
    "affected_product_count",
    "affected_version_entry_count",
    "version_status_counts",
    "version_type_counts",
    "bounded_version_entry_count",
    "unaffected_change_count",
    "package_identifiers",
    "exact_inventory_identifier_matches",
    "diagnostic_disposition",
    "products_json",
]


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_classification(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _affected_products(cve: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    products: list[tuple[str, dict[str, Any]]] = []
    affected = cve.get("affected")
    if not isinstance(affected, list):
        return products
    for source_record in affected:
        if not isinstance(source_record, dict):
            continue
        source = str(source_record.get("source") or "")
        affected_data = source_record.get("affectedData")
        if isinstance(affected_data, list):
            products.extend(
                (source, product)
                for product in affected_data
                if isinstance(product, dict)
            )
    return products


def _is_placeholder(value: Any) -> bool:
    return not isinstance(value, str) or not value.strip() or value.strip().casefold() in {
        "n/a",
        "na",
        "unknown",
    }


def _diagnostic_disposition(products: list[tuple[str, dict[str, Any]]]) -> str:
    if not products:
        return "no_usable_product_record"

    version_lists = [product.get("versions") for _, product in products]
    if any(
        not isinstance(versions, list)
        or not versions
        or any(not isinstance(version, dict) for version in versions)
        for versions in version_lists
    ):
        return "no_structured_version_records"
    version_records = [
        version
        for versions in version_lists
        for version in versions
    ]

    has_package_ids = all(
        isinstance(product.get("packageName"), str)
        and not _is_placeholder(product.get("packageName"))
        for _, product in products
    )
    has_bounded_custom_ranges = all(
        version.get("status") == "affected"
        and version.get("versionType") == "custom"
        and bool(version.get("lessThan") or version.get("lessThanOrEqual"))
        for version in version_records
    )
    if has_package_ids and has_bounded_custom_ranges:
        return "package_and_custom_range_need_inventory_and_comparator"

    has_named_product = all(
        not _is_placeholder(product.get("vendor"))
        and not _is_placeholder(product.get("product"))
        for _, product in products
    )
    if has_named_product:
        return "named_product_requires_vendor_specific_version_review"
    return "placeholder_or_incomplete_product_identity"


def build_diagnostic(
    enrichment_dir: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    enrichment_dir = enrichment_dir.resolve()
    manifest_path = enrichment_dir / "manifest.json"
    classification_path = enrichment_dir / "cve_classification.csv"
    manifest = _read_json(manifest_path)
    classifications = _read_classification(classification_path)
    affected_rows = [
        row for row in classifications
        if row.get("classification") == "affected_products_only"
    ]
    manifest_records = {
        record["cve_id"]: record
        for record in manifest.get("records", [])
        if isinstance(record, dict) and record.get("cve_id")
    }

    inventory_identifiers: set[str] = set()
    with inventory_path.open("r", newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            for field in ("software_product", "software_name"):
                value = row.get(field, "").strip().casefold()
                if value:
                    inventory_identifiers.add(value)

    records: list[dict[str, Any]] = []
    disposition_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    product_field_counts: Counter[str] = Counter()
    version_field_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    version_type_counts: Counter[str] = Counter()
    default_status_counts: Counter[str] = Counter()
    version_value_counts: Counter[str] = Counter()
    change_status_counts: Counter[str] = Counter()
    affected_version_entry_count = 0
    bounded_version_entry_count = 0
    unaffected_change_count = 0
    package_identifier_count = 0
    inventory_identifier_match_count = 0

    for row in affected_rows:
        cve_id = row["cve_id"]
        evidence = manifest_records.get(cve_id)
        if evidence is None or evidence.get("classification") != "affected_products_only":
            raise ValueError(f"Manifest classification is missing or inconsistent for {cve_id}")
        if evidence.get("http_status") != 200 or row.get("http_status") != "200":
            raise ValueError(f"Saved response for {cve_id} is not a successful HTTP 200 response")
        response_relative = Path(str(evidence.get("file") or ""))
        response_path = (enrichment_dir / response_relative).resolve()
        try:
            response_path.relative_to(enrichment_dir)
        except ValueError as exc:
            raise ValueError(f"Response path escapes enrichment directory for {cve_id}") from exc
        if not response_path.is_file():
            raise FileNotFoundError(f"Saved response is missing for {cve_id}: {response_path}")
        response_bytes = response_path.read_bytes()
        digest = hashlib.sha256(response_bytes).hexdigest()
        if digest != evidence.get("sha256") or digest != row.get("sha256"):
            raise ValueError(f"Saved response hash mismatch for {cve_id}")

        response = json.loads(response_bytes.decode("utf-8"))
        vulnerabilities = response.get("vulnerabilities")
        matching_cves = [
            item.get("cve")
            for item in vulnerabilities or []
            if isinstance(item, dict)
            and isinstance(item.get("cve"), dict)
            and item["cve"].get("id") == cve_id
        ]
        if len(matching_cves) != 1:
            raise ValueError(f"Expected exactly one saved CVE record for {cve_id}")
        products = _affected_products(matching_cves[0])
        if not products:
            raise ValueError(f"Classified affected-product evidence is absent for {cve_id}")

        statuses: Counter[str] = Counter()
        version_types: Counter[str] = Counter()
        version_details: list[dict[str, Any]] = []
        package_ids: set[str] = set()
        product_sources: set[str] = set()
        for source, product in products:
            product_sources.add(source or "unspecified")
            product_field_counts.update(product.keys())
            default_status_counts[str(product.get("defaultStatus") or "unspecified")] += 1
            product_name = product.get("product")
            vendor = product.get("vendor")
            package_name = product.get("packageName")
            if isinstance(package_name, str) and not _is_placeholder(package_name):
                package_ids.add(package_name)
            versions = product.get("versions")
            if not isinstance(versions, list):
                continue
            for version in versions:
                if not isinstance(version, dict):
                    continue
                version_field_counts.update(version.keys())
                version_status = str(version.get("status") or "unspecified")
                version_type = str(version.get("versionType") or "unspecified")
                statuses[version_status] += 1
                version_types[version_type] += 1
                version_value_counts[str(version.get("version") or "unspecified")] += 1
                status_counts[version_status] += 1
                version_type_counts[version_type] += 1
                affected_version_entry_count += version_status == "affected"
                bounded = bool(version.get("lessThan") or version.get("lessThanOrEqual"))
                bounded_version_entry_count += bounded
                changes = version.get("changes")
                change_status_counts.update(
                    str(change.get("status") or "unspecified")
                    for change in (changes if isinstance(changes, list) else [])
                    if isinstance(change, dict)
                )
                unaffected_change_count += sum(
                    isinstance(change, dict) and change.get("status") == "unaffected"
                    for change in (changes if isinstance(changes, list) else [])
                )
                version_details.append({
                    "version": version.get("version"),
                    "versionType": version.get("versionType"),
                    "status": version.get("status"),
                    "lessThan": version.get("lessThan"),
                    "lessThanOrEqual": version.get("lessThanOrEqual"),
                    "changes": changes if isinstance(changes, list) else [],
                })

        product_identifiers = {
            str(value).strip().casefold()
            for _, product in products
            for value in (product.get("packageName"), product.get("product"))
            if not _is_placeholder(value)
        }
        inventory_matches = sorted(product_identifiers & inventory_identifiers)
        disposition = _diagnostic_disposition(products)
        disposition_counts[disposition] += 1
        source_counts.update(product_sources)
        package_identifier_count += bool(package_ids)
        inventory_identifier_match_count += bool(inventory_matches)
        records.append({
            "cve_id": cve_id,
            "source": ";".join(sorted(product_sources)),
            "affected_product_count": len(products),
            "affected_version_entry_count": len(version_details),
            "version_status_counts": dict(sorted(statuses.items())),
            "version_type_counts": dict(sorted(version_types.items())),
            "bounded_version_entry_count": sum(
                bool(version.get("lessThan") or version.get("lessThanOrEqual"))
                for version in version_details
            ),
            "unaffected_change_count": sum(
                change.get("status") == "unaffected"
                for version in version_details
                for change in version["changes"]
                if isinstance(change, dict)
            ),
            "package_identifiers": sorted(package_ids),
            "exact_inventory_identifier_matches": inventory_matches,
            "diagnostic_disposition": disposition,
            "products": [
                {
                    "source": source,
                    "vendor": product.get("vendor"),
                    "product": product.get("product"),
                    "packageName": product.get("packageName"),
                    "collectionURL": product.get("collectionURL"),
                    "defaultStatus": product.get("defaultStatus"),
                    "versions": [
                        version
                        for version in product.get("versions", [])
                        if isinstance(version, dict)
                    ] if isinstance(product.get("versions"), list) else [],
                }
                for source, product in products
            ],
        })

    summary = {
        "project": "PRIORIS",
        "report": "saved_nvd_affected_products_diagnostic",
        "source_snapshot_date": manifest.get("source_snapshot_date"),
        "enrichment_date": manifest.get("enrichment_date"),
        "enrichment_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "classification_file": str(classification_path),
        "input_affected_products_only_cve_count": len(affected_rows),
        "saved_response_count_hash_verified": len(records),
        "product_record_source_counts": dict(sorted(source_counts.items())),
        "product_field_occurrences": dict(sorted(product_field_counts.items())),
        "version_field_occurrences": dict(sorted(version_field_counts.items())),
        "version_status_counts": dict(sorted(status_counts.items())),
        "version_type_counts": dict(sorted(version_type_counts.items())),
        "default_status_counts": dict(sorted(default_status_counts.items())),
        "version_value_counts": dict(sorted(version_value_counts.items())),
        "change_status_counts": dict(sorted(change_status_counts.items())),
        "affected_version_entry_count": affected_version_entry_count,
        "bounded_version_entry_count": bounded_version_entry_count,
        "unaffected_change_count": unaffected_change_count,
        "cves_with_package_identifiers": package_identifier_count,
        "cves_with_exact_product_identifier_overlap_in_inventory": inventory_identifier_match_count,
        "diagnostic_disposition_counts": dict(sorted(disposition_counts.items())),
        "candidate_records_for_separate_product_version_study": disposition_counts[
            "package_and_custom_range_need_inventory_and_comparator"
        ],
        "defensible_vulnerability_matches_produced": 0,
        "interpretation": [
            "This report profiles saved NVD CVE Record Format affected data; it does not create NVD configuration trees or evaluate vulnerability-to-asset matches.",
            "A version entry marked affected is source evidence, but versionType custom does not supply a comparator implementation or establish compatibility with the inventory's version syntax.",
            "The packageName values can support a future product-specific study only after the inventory captures those package identifiers and the package's version semantics are validated.",
            "No exact packageName or product-name identifier overlap with the existing synthetic software inventory is treated as a match.",
            "Results describe synthetic test data and saved evidence, not real enterprise exposure.",
        ],
        "records": records,
    }
    return summary


def write_report(summary: dict[str, Any], output_dir: Path) -> None:
    output_dir = output_dir.resolve()
    json_path = output_dir / "affected_products_diagnostic.json"
    csv_path = output_dir / "affected_products_diagnostic.csv"
    existing = [path for path in (json_path, csv_path) if path.exists()]
    if existing:
        raise FileExistsError(
            "Diagnostic outputs already exist; refusing to overwrite: "
            + ", ".join(str(path) for path in existing)
        )
    json_content = json.dumps(summary, indent=2)
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for record in summary["records"]:
        writer.writerow({
            **{
                field: record[field]
                for field in CSV_FIELDS
                if field in record
            },
            "version_status_counts": json.dumps(record["version_status_counts"], sort_keys=True),
            "version_type_counts": json.dumps(record["version_type_counts"], sort_keys=True),
            "package_identifiers": json.dumps(record["package_identifiers"]),
            "exact_inventory_identifier_matches": json.dumps(
                record["exact_inventory_identifier_matches"]
            ),
            "products_json": json.dumps(record["products"], sort_keys=True),
        })
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_content, encoding="utf-8")
    csv_path.write_text(csv_buffer.getvalue(), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diagnose saved affected-product evidence without matching assets."
    )
    parser.add_argument("--enrichment-dir", type=Path, default=DEFAULT_ENRICHMENT)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        summary = build_diagnostic(args.enrichment_dir, args.inventory)
        write_report(summary, args.output_dir)
    except (OSError, ValueError, json.JSONDecodeError, csv.Error) as exc:
        print(f"ERROR: affected-products diagnostic failed: {exc}", file=sys.stderr)
        return 2
    print(
        f"Verified {summary['saved_response_count_hash_verified']} saved records; "
        f"{summary['candidate_records_for_separate_product_version_study']} "
        "need package-specific inventory and version semantics."
    )
    print(f"Diagnostic reports written to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
