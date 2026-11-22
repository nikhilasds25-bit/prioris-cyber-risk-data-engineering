"""Validate provenance and document unresolved semantics for custom CVE versions."""

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
DEFAULT_DIAGNOSTIC = (
    ROOT / "results" / "2026-10-19-affected-products-experiment"
    / "affected_products_diagnostic.json"
)
DEFAULT_OUTPUT = (
    ROOT / "results" / "2026-10-19-affected-products-experiment"
    / "version-validation"
)
NVD_AFFECTED_SCHEMA = (
    "https://csrc.nist.gov/schema/nvd/api/2.0/cve_affected_1.0.json"
)

CSV_FIELDS = [
    "cve_id",
    "package_name",
    "vendor",
    "product",
    "version",
    "less_than",
    "less_than_or_equal",
    "version_type",
    "status",
    "default_status",
    "changes_json",
    "raw_version_entry_json",
    "source_identifier",
    "affected_data_source",
    "collection_url",
    "response_file",
    "response_url",
    "http_status",
    "retrieved_at_utc",
    "response_sha256",
    "comparator_status",
    "matching_performed",
]


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _safe_evidence_path(root: Path, relative: str, cve_id: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Response path escapes enrichment directory for {cve_id}") from exc
    return path


def _affected_sources(cve: dict[str, Any]) -> list[dict[str, Any]]:
    affected = cve.get("affected")
    if not isinstance(affected, list):
        return []
    return [entry for entry in affected if isinstance(entry, dict)]


def build_validation_report(
    enrichment_dir: Path,
    diagnostic_path: Path,
    *,
    expected_patchstack_count: int = 77,
) -> dict[str, Any]:
    enrichment_dir = enrichment_dir.resolve()
    diagnostic = _read_json(diagnostic_path.resolve())
    if diagnostic.get("report") != "saved_nvd_affected_products_diagnostic":
        raise ValueError("The affected-products diagnostic report is missing or unexpected")
    if diagnostic.get("source_snapshot_date") != "2026-10-19":
        raise ValueError("Unexpected source snapshot date in affected-products diagnostic")

    manifest_path = enrichment_dir / "manifest.json"
    classification_path = enrichment_dir / "cve_classification.csv"
    manifest = _read_json(manifest_path)
    if manifest.get("source_snapshot_date") != diagnostic["source_snapshot_date"]:
        raise ValueError("Enrichment manifest and diagnostic refer to different snapshots")
    if manifest.get("enrichment_date") != diagnostic.get("enrichment_date"):
        raise ValueError("Enrichment manifest and diagnostic refer to different dates")

    classifications = {
        row["cve_id"]: row
        for row in _read_csv(classification_path)
        if row.get("cve_id")
    }
    manifest_records = {
        row["cve_id"]: row
        for row in manifest.get("records", [])
        if isinstance(row, dict) and row.get("cve_id")
    }
    diagnostic_records = {
        row["cve_id"]: row
        for row in diagnostic.get("records", [])
        if isinstance(row, dict) and row.get("cve_id")
    }
    patchstack_ids = {
        cve_id
        for cve_id, row in classifications.items()
        if row.get("classification") == "affected_products_only"
        and cve_id in diagnostic_records
        and any(
            product.get("source") == "audit@patchstack.com"
            for product in diagnostic_records[cve_id].get("products", [])
        )
    }
    if len(patchstack_ids) != expected_patchstack_count:
        raise ValueError(
            f"Expected {expected_patchstack_count} Patchstack affected-products records "
            f"from the saved evidence, found {len(patchstack_ids)}"
        )

    records: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()
    version_counts: Counter[str] = Counter()
    change_counts: Counter[int] = Counter()
    response_bytes_total = 0

    for cve_id in sorted(patchstack_ids):
        classification = classifications[cve_id]
        evidence = manifest_records.get(cve_id)
        if evidence is None:
            raise ValueError(f"Manifest evidence is missing for {cve_id}")
        if (
            evidence.get("classification") != "affected_products_only"
            or evidence.get("http_status") != 200
            or classification.get("http_status") != "200"
        ):
            raise ValueError(f"Classification or HTTP status is inconsistent for {cve_id}")
        response_path = _safe_evidence_path(
            enrichment_dir,
            str(evidence.get("file") or ""),
            cve_id,
        )
        if not response_path.is_file():
            raise FileNotFoundError(f"Saved response is missing for {cve_id}")
        response_bytes = response_path.read_bytes()
        digest = hashlib.sha256(response_bytes).hexdigest()
        if digest != evidence.get("sha256") or digest != classification.get("sha256"):
            raise ValueError(f"Saved response hash mismatch for {cve_id}")
        response_bytes_total += len(response_bytes)

        response = json.loads(response_bytes.decode("utf-8"))
        vulnerabilities = response.get("vulnerabilities")
        cves = [
            item["cve"]
            for item in vulnerabilities or []
            if isinstance(item, dict)
            and isinstance(item.get("cve"), dict)
            and item["cve"].get("id") == cve_id
        ]
        if len(cves) != 1:
            raise ValueError(f"Expected exactly one saved CVE record for {cve_id}")
        cve = cves[0]
        sources = [
            source
            for source in _affected_sources(cve)
            if source.get("source") == "audit@patchstack.com"
        ]
        if len(sources) != 1:
            raise ValueError(f"Expected one Patchstack source statement for {cve_id}")
        products = sources[0].get("affectedData")
        if not isinstance(products, list) or len(products) != 1:
            raise ValueError(f"Expected one affected product entry for {cve_id}")
        product = products[0]
        if not isinstance(product, dict):
            raise ValueError(f"Affected product entry is malformed for {cve_id}")
        versions = product.get("versions")
        if not isinstance(versions, list) or len(versions) != 1:
            raise ValueError(f"Expected one version entry for {cve_id}")
        version = versions[0]
        if not isinstance(version, dict) or version.get("versionType") != "custom":
            raise ValueError(f"Expected one custom version statement for {cve_id}")

        diagnostic_product = diagnostic_records[cve_id]["products"][0]
        if (
            product.get("packageName") != diagnostic_product.get("packageName")
            or versions != diagnostic_product.get("versions")
        ):
            raise ValueError(f"Diagnostic fields differ from raw response for {cve_id}")

        source_identifier = str(cve.get("sourceIdentifier") or "")
        affected_source = str(sources[0].get("source") or "")
        source_counts[source_identifier] += 1
        version_counts[str(version.get("version"))] += 1
        changes = version.get("changes")
        change_list = changes if isinstance(changes, list) else []
        change_counts[len(change_list)] += 1
        records.append({
            "cve_id": cve_id,
            "package_name": product.get("packageName"),
            "vendor": product.get("vendor"),
            "product": product.get("product"),
            "version": version.get("version"),
            "less_than": version.get("lessThan"),
            "less_than_or_equal": version.get("lessThanOrEqual"),
            "version_type": version.get("versionType"),
            "status": version.get("status"),
            "default_status": product.get("defaultStatus"),
            "changes": version.get("changes"),
            "raw_version_entry": version,
            "source_identifier": source_identifier,
            "affected_data_source": affected_source,
            "collection_url": product.get("collectionURL"),
            "response_file": str(evidence["file"]).replace("\\", "/"),
            "response_url": evidence.get("url"),
            "http_status": evidence.get("http_status"),
            "retrieved_at_utc": evidence.get("retrieved_at_utc"),
            "response_sha256": digest,
            "response_bytes": len(response_bytes),
            "comparator_status": "unverified",
            "matching_performed": False,
        })

    return {
        "project": "PRIORIS",
        "report": "patchstack_custom_version_semantics_validation",
        "source_snapshot_date": manifest["source_snapshot_date"],
        "enrichment_date": manifest["enrichment_date"],
        "enrichment_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "affected_products_diagnostic_sha256": hashlib.sha256(
            diagnostic_path.resolve().read_bytes()
        ).hexdigest(),
        "authoritative_schema": {
            "title": "NVD CVE API 2.0 affected product schema",
            "url": NVD_AFFECTED_SCHEMA,
            "document_version": "NVD Vulnerability Data API 2.2.4",
            "relevance": [
                "The schema says the version comparison semantics are defined by versionType.",
                "The schema describes custom as an unspecified version type that should be avoided whenever possible.",
                "The schema defines range status changes in terms of ordering under versionType; it does not define custom ordering.",
                "The schema notes that version 0 typically denotes the earliest possible version by convention, but this does not define how custom versions are ordered.",
            ],
            "decision": (
                "The authoritative schema confirms the custom comparator is unspecified; "
                "it does not provide a defensible custom version ordering for these records."
            ),
        },
        "assessment": {
            "patchstack_cve_count": len(records),
            "records_with_provenance_verified_raw_fields": len(records),
            "records_with_custom_version_type": sum(
                record["version_type"] == "custom" for record in records
            ),
            "records_testable_for_comparison_semantics": 0,
            "records_excluded_from_matching": len(records),
            "comparator_status": "unverified",
            "matching_performed": False,
            "synthetic_test_fixtures_created": 0,
            "real_vulnerability_asset_matches_created": 0,
        },
        "field_counts": {
            "version_value_counts": dict(sorted(version_counts.items())),
            "changes_entry_count_per_record": {
                str(key): value for key, value in sorted(change_counts.items())
            },
            "status_counts": dict(sorted(Counter(
                str(record["status"]) for record in records
            ).items())),
            "default_status_counts": dict(sorted(Counter(
                str(record["default_status"]) for record in records
            ).items())),
            "less_than_present_count": sum(
                record["less_than"] is not None for record in records
            ),
            "less_than_or_equal_present_count": sum(
                record["less_than_or_equal"] is not None for record in records
            ),
            "change_status_counts": dict(sorted(Counter(
                str(change.get("status"))
                for record in records
                for change in (
                    record["changes"]
                    if isinstance(record["changes"], list)
                    else []
                )
                if isinstance(change, dict)
            ).items())),
            "source_identifier_counts": dict(sorted(source_counts.items())),
            "total_saved_response_bytes": response_bytes_total,
        },
        "missing_evidence": [
            "No Patchstack specification or other authoritative source was found in the saved project evidence defining the comparator meant by versionType=custom for these plugin package versions.",
            "The NVD affected-data schema expressly leaves custom version ordering unspecified; it does not define how its inclusive upper bounds and changes.at values should be compared for this source.",
            "No evidence establishes the semantics of the literal lower-bound values 0 and n/a for these specific package records beyond the schema's general convention that 0 typically denotes the earliest possible version.",
            "No source-backed normalization or ordering rule for each affected plugin package version is included in the enrichment response or manifest.",
            "The existing synthetic software inventory has no packageName identifiers for these plugins and does not provide real installed plugin versions.",
        ],
        "decision": (
            "Comparator UNVERIFIED. Stop before version comparison or vulnerability matching. "
            "All 77 records are evidence-preserved but none are testable for comparison semantics."
        ),
        "interpretation": [
            "The source records label the listed version/range status as affected and the product default status as unaffected. This report preserves those source assertions without interpreting their version ordering.",
            "Each record's original version object, including optional changes entries, is preserved verbatim.",
            "No boundary fixtures are generated because their expected outcomes would require the unresolved custom comparison semantics.",
            "No vulnerability-to-asset matches are produced. This report does not establish real-world exposure.",
        ],
        "records": records,
    }


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    output_dir = output_dir.resolve()
    json_path = output_dir / "custom_version_semantics_validation.json"
    csv_path = output_dir / "custom_version_evidence.csv"
    existing = [path for path in (json_path, csv_path) if path.exists()]
    if existing:
        raise FileExistsError(
            "Version-validation outputs already exist; refusing to overwrite: "
            + ", ".join(str(path) for path in existing)
        )

    json_content = json.dumps(report, indent=2)
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for record in report["records"]:
        writer.writerow({
            "cve_id": record["cve_id"],
            "package_name": record["package_name"],
            "vendor": record["vendor"],
            "product": record["product"],
            "version": record["version"],
            "less_than": record["less_than"],
            "less_than_or_equal": record["less_than_or_equal"],
            "version_type": record["version_type"],
            "status": record["status"],
            "default_status": record["default_status"],
            "changes_json": json.dumps(record["changes"], sort_keys=True),
            "raw_version_entry_json": json.dumps(
                record["raw_version_entry"], sort_keys=True
            ),
            "source_identifier": record["source_identifier"],
            "affected_data_source": record["affected_data_source"],
            "collection_url": record["collection_url"],
            "response_file": record["response_file"],
            "response_url": record["response_url"],
            "http_status": record["http_status"],
            "retrieved_at_utc": record["retrieved_at_utc"],
            "response_sha256": record["response_sha256"],
            "comparator_status": record["comparator_status"],
            "matching_performed": record["matching_performed"],
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json_content, encoding="utf-8")
    csv_path.write_text(csv_buffer.getvalue(), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate saved custom-version evidence without comparing versions."
    )
    parser.add_argument("--enrichment-dir", type=Path, default=DEFAULT_ENRICHMENT)
    parser.add_argument("--diagnostic", type=Path, default=DEFAULT_DIAGNOSTIC)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = build_validation_report(args.enrichment_dir, args.diagnostic)
        write_report(report, args.output_dir)
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as exc:
        print(f"ERROR: custom-version validation failed: {exc}", file=sys.stderr)
        return 2
    assessment = report["assessment"]
    print(
        f"Verified {assessment['records_with_provenance_verified_raw_fields']} "
        f"Patchstack records; comparator {assessment['comparator_status']}; "
        f"{assessment['records_testable_for_comparison_semantics']} testable; "
        "matching not performed."
    )
    print(f"Evidence report written to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
