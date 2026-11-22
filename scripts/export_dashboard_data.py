#!/usr/bin/env python3
"""Export current PRIORIS risk Parquet outputs as bounded static JSON for web/."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import pyarrow.dataset as ds

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RISK_DIR = ROOT / "data" / "processed" / "risk_prioritization"
DEFAULT_EXPOSURE_SUMMARY = (
    ROOT / "data" / "processed" / "enterprise_exposure" / "summary.json"
)
DEFAULT_OUTPUT_DIR = ROOT / "web" / "public" / "data"
BATCH_SIZE = 2_000
TIERS = ("critical", "high", "medium", "low")

EXPOSURE_FIELDS = [
    "asset_id",
    "installation_id",
    "software_name",
    "software_product",
    "installed_version",
    "installed_cpe_name",
    "cve_id",
    "vulnerable",
    "cvss_score",
    "known_exploited",
    "kev_date_added",
    "criticality",
    "exposure",
    "asset_type",
    "business_unit",
    "environment",
    "applicability_status",
    "risk_score",
    "risk_tier",
    "scoring_status",
    "risk_factor_components",
    "risk_factor_evidence",
    "missing_score_evidence",
    "match_evidence",
    "configuration_index",
    "node_path",
    "match_index",
    "match_criteria_id",
    "criteria",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "cpe_name",
    "cpe_name_id",
]
ASSET_FIELDS = [
    "asset_id",
    "criticality",
    "exposure",
    "asset_type",
    "business_unit",
    "environment",
    "scored_exposure_rows",
    "scored_installation_count",
    "scored_cve_count",
    "kev_exposure_rows",
    "critical_exposure_rows",
    "high_exposure_rows",
    "medium_exposure_rows",
    "low_exposure_rows",
    "max_risk_score",
    "top_risk_tier",
    "top_risk_cve_id",
    "top_installation_id",
    "asset_risk_status",
    "asset_priority_rank",
]


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _dataset(path: Path, fields: list[str], label: str):
    if not path.is_dir():
        raise FileNotFoundError(f"{label} dataset is missing: {path}")
    dataset = ds.dataset(str(path), format="parquet")
    missing = sorted(set(fields) - set(dataset.schema.names))
    if missing:
        raise ValueError(f"{label} is missing columns: {', '.join(missing)}")
    return dataset


def _records(dataset, fields: list[str], batch_size: int = BATCH_SIZE):
    scanner = dataset.scanner(columns=fields, batch_size=batch_size)
    for batch in scanner.to_batches():
        yield from batch.to_pylist()


def _cpe_vendor(cpe: Any) -> str:
    if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
        return "Unknown"
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 5:
        return "Unknown"
    return re.sub(r"\\(.)", r"\1", parts[3]).lower() or "Unknown"


def _camel_key(value: str) -> str:
    return re.sub(r"_([a-z])", lambda match: match.group(1).upper(), value)


def _write_json_records(
    path: Path,
    records: Iterable[dict[str, Any]],
    *,
    compressed: bool = False,
) -> int:
    count = 0
    opener = gzip.open if compressed else open
    with opener(path, "wt", encoding="utf-8", newline="\n", compresslevel=6) if compressed else opener(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("[")
        for record in records:
            if count:
                handle.write(",")
            handle.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
            count += 1
        handle.write("]\n")
    return count


def export_dashboard_data(
    risk_dir: Path = DEFAULT_RISK_DIR,
    exposure_summary_path: Path = DEFAULT_EXPOSURE_SUMMARY,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    risk_dir = risk_dir.resolve()
    exposure_summary_path = exposure_summary_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(
            f"Dashboard data output exists; refusing to overwrite: {output_dir}"
        )

    risk_summary_path = risk_dir / "risk_summary.json"
    prioritized_path = risk_dir / "prioritized_exposures"
    assets_path = risk_dir / "asset_risk_summary"
    for label, path in (
        ("Risk summary", risk_summary_path),
        ("Prioritized exposure", prioritized_path),
        ("Asset risk summary", assets_path),
        ("Exposure summary", exposure_summary_path),
    ):
        if not path.exists():
            raise FileNotFoundError(f"{label} is missing: {path}")

    risk_summary = _read_json(risk_summary_path)
    phase3_summary = _read_json(exposure_summary_path)
    if risk_summary.get("phase") != 4:
        raise ValueError("Risk summary does not identify Phase 4 output")
    exposure_dataset = _dataset(
        prioritized_path, EXPOSURE_FIELDS, "Prioritized exposures"
    )
    asset_dataset = _dataset(assets_path, ASSET_FIELDS, "Asset risk summary")

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(
        prefix=".prioris-dashboard-export-",
        dir=output_dir.parent,
    ))
    published = False
    try:
        print("Scanning prioritized exposures in bounded PyArrow batches...", flush=True)
        tier_counts = Counter()
        applicability_counts = Counter()
        scoring_counts = Counter()
        asset_type_tiers: dict[str, Counter] = defaultdict(Counter)
        vendor_tiers: dict[str, Counter] = defaultdict(Counter)
        cves: dict[str, dict[str, Any]] = {}
        products: dict[tuple[str, str, str], dict[str, Any]] = {}
        exposure_count = 0

        def selected_records(scored_only: bool, collect_aggregates: bool):
            nonlocal exposure_count
            record_id = 0
            for record in _records(exposure_dataset, EXPOSURE_FIELDS):
                exposure_count += 1
                status = str(record.get("applicability_status") or "unknown")
                scoring_status = str(record.get("scoring_status") or "unknown")
                if collect_aggregates:
                    applicability_counts[status] += 1
                    scoring_counts[scoring_status] += 1
                is_scored = scoring_status == "scored"
                if is_scored and collect_aggregates:
                    tier = str(record.get("risk_tier") or "").lower()
                    tier_counts[tier] += 1
                    asset_type_tiers[str(record.get("asset_type") or "Unknown")][tier] += 1
                    vendor = _cpe_vendor(record.get("installed_cpe_name"))
                    vendor_tiers[vendor][tier] += 1
                    cve_id = record.get("cve_id")
                    if cve_id:
                        raw_score_evidence = record.get("risk_factor_evidence")
                        if isinstance(raw_score_evidence, str) and raw_score_evidence:
                            score_evidence = json.loads(raw_score_evidence)
                        elif isinstance(raw_score_evidence, dict):
                            score_evidence = raw_score_evidence
                        else:
                            score_evidence = {}
                        cvss_value = record.get("cvss_score")
                        if cvss_value is None:
                            cvss_value = score_evidence.get("cvss_score")
                        cvss_score = (
                            float(cvss_value) if cvss_value is not None else None
                        )
                        cve = cves.setdefault(str(cve_id), {
                            "cveId": str(cve_id),
                            "riskScore": record.get("risk_score"),
                            "riskTier": tier,
                            "cvssScore": cvss_score,
                            "knownExploited": record.get("known_exploited"),
                            "kevDateAdded": record.get("kev_date_added"),
                            "affectedAssets": set(),
                            "affectedInstallations": set(),
                            "softwareProducts": set(),
                        })
                        cve["affectedAssets"].add(str(record["asset_id"]))
                        cve["affectedInstallations"].add(str(record["installation_id"]))
                        cve["softwareProducts"].add(str(record.get("software_product") or "Unknown"))
                        if record.get("risk_score") is not None and float(record["risk_score"]) > float(cve["riskScore"] or 0):
                            cve["riskScore"] = record["risk_score"]
                            cve["riskTier"] = tier
                            cve["cvssScore"] = cvss_score
                    product_key = (
                        vendor,
                        str(record.get("software_product") or "Unknown"),
                        str(record.get("installed_version") or "Unknown"),
                    )
                    product = products.setdefault(product_key, {
                        "vendor": vendor,
                        "product": product_key[1],
                        "installedVersion": product_key[2],
                        "affectedAssets": set(),
                        "cves": set(),
                        "riskScore": record.get("risk_score"),
                        "riskTier": tier,
                        "knownExploited": bool(record.get("known_exploited")),
                    })
                    product["affectedAssets"].add(str(record["asset_id"]))
                    if record.get("cve_id"):
                        product["cves"].add(str(record["cve_id"]))
                    if record.get("risk_score") is not None and float(record["risk_score"]) > float(product["riskScore"] or 0):
                        product["riskScore"] = record["risk_score"]
                        product["riskTier"] = tier
                    product["knownExploited"] = (
                        product["knownExploited"] or bool(record.get("known_exploited"))
                    )
                if scored_only != is_scored:
                    continue
                output = {
                    _camel_key(key): value
                    for key, value in record.items()
                }
                output["recordId"] = record_id
                record_id += 1
                output["softwareVendor"] = _cpe_vendor(record.get("installed_cpe_name"))
                for field in ("risk_factor_components", "risk_factor_evidence",
                              "missing_score_evidence", "match_evidence"):
                    camel_field = _camel_key(field)
                    raw = output.get(camel_field)
                    if isinstance(raw, str) and raw:
                        try:
                            output[camel_field] = json.loads(raw)
                        except json.JSONDecodeError:
                            raise ValueError(
                                f"Invalid {field} JSON for installation "
                                f"{record.get('installation_id')}"
                            )
                yield output

        confirmed_count = _write_json_records(
            staging_dir / "confirmed-exposures.json.gz",
            selected_records(scored_only=True, collect_aggregates=True),
            compressed=True,
        )
        print(
            f"Exported {confirmed_count:,} scored exposure rows; scanning review queue...",
            flush=True,
        )
        review_count = _write_json_records(
            staging_dir / "review-queue.json.gz",
            selected_records(scored_only=False, collect_aggregates=False),
            compressed=True,
        )
        assets = list(_records(asset_dataset, ASSET_FIELDS))
        for asset in assets:
            asset["riskScore"] = asset.pop("max_risk_score")
            asset["affectedInstallations"] = asset.pop("scored_installation_count")
            asset["affectedCves"] = asset.pop("scored_cve_count")
            asset["riskTier"] = asset.pop("top_risk_tier")
            asset["topCveId"] = asset.pop("top_risk_cve_id")
            asset["priorityRank"] = asset.pop("asset_priority_rank")
            asset["riskStatus"] = asset.pop("asset_risk_status")
            for key in list(asset):
                camel = _camel_key(key)
                if camel != key:
                    asset[camel] = asset.pop(key)

        cve_records = []
        for cve in cves.values():
            cve["affectedAssets"] = len(cve["affectedAssets"])
            cve["affectedInstallations"] = len(cve["affectedInstallations"])
            cve["softwareProducts"] = sorted(cve["softwareProducts"])
            cve_records.append(cve)
        cve_records.sort(key=lambda row: (
            -float(row["riskScore"] or 0),
            -int(bool(row["knownExploited"])),
            -float(row["cvssScore"] or 0),
            row["cveId"],
        ))
        for rank, record in enumerate(cve_records, 1):
            record["priorityRank"] = rank
        product_records = []
        for product in products.values():
            product["affectedAssets"] = len(product["affectedAssets"])
            product["cves"] = sorted(product["cves"])
            product["cveCount"] = len(product["cves"])
            product_records.append(product)
        product_records.sort(key=lambda row: (
            -float(row["riskScore"] or 0),
            -int(bool(row["knownExploited"])),
            -row["affectedAssets"],
            row["vendor"],
            row["product"],
            row["installedVersion"],
        ))
        asset_type_distribution = [
            {"assetType": asset_type, **{
                tier: int(counts[tier]) for tier in TIERS
            }}
            for asset_type, counts in sorted(asset_type_tiers.items())
        ]
        vendor_distribution = [
            {"vendor": vendor, **{tier: int(counts[tier]) for tier in TIERS}}
            for vendor, counts in sorted(
                vendor_tiers.items(),
                key=lambda item: (-sum(item[1].values()), item[0]),
            )
        ]
        snapshot_date = None
        kev_snapshot = phase3_summary.get("kev_snapshot")
        if kev_snapshot:
            snapshot_match = re.search(r"\d{4}-\d{2}-\d{2}", str(kev_snapshot))
            snapshot_date = snapshot_match.group(0) if snapshot_match else None
        exported = {
            "product": "PRIORIS",
            "description": "Distributed Cyber Risk Intelligence and Prioritization Framework",
            "datasetEnvironment": "Synthetic Demo",
            "snapshotDate": snapshot_date,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "synthetic": True,
            "scoringMethod": risk_summary.get("scoring_method"),
            "limitations": risk_summary.get("evidence_and_limitations", []),
            "metrics": {
                "totalAssets": int(risk_summary["counts"]["assets_in_asset_context"]),
                "affectedAssets": int(risk_summary["counts"]["assets_with_scored_exposure"]),
                "confirmedInstallations": int(
                    risk_summary["counts"]["distinct_scored_installations"]
                ),
                "confirmedExposures": int(risk_summary["counts"]["scored_confirmed_vulnerable_rows"]),
                "distinctCves": int(risk_summary["counts"]["distinct_scored_cves"]),
                "criticalExposures": int(tier_counts.get("critical", 0)),
                "highExposures": int(tier_counts.get("high", 0)),
                "riskTierCounts": {tier: int(tier_counts.get(tier, 0)) for tier in TIERS},
                "applicabilityStatusCounts": dict(applicability_counts),
                "scoringStatusCounts": dict(scoring_counts),
            },
            "assets": assets,
            "cves": cve_records,
            "software": product_records,
            "assetTypeDistribution": asset_type_distribution,
            "vendorDistribution": vendor_distribution,
            "exports": {
                "confirmedExposures": {
                    "file": "confirmed-exposures.json.gz",
                    "records": confirmed_count,
                },
                "reviewQueue": {
                    "file": "review-queue.json.gz",
                    "records": review_count,
                },
            },
            "sourceSummary": {
                "phase3ExposureRows": int(phase3_summary.get("exposure_rows", exposure_count)),
                "confirmedInstallationCvePairs": int(
                    phase3_summary.get("confirmed_installation_cve_pairs", 0)
                ),
                "inventoryDirectory": phase3_summary.get("inventory_directory"),
            },
        }
        summary_path = staging_dir / "dashboard-summary.json"
        summary_path.write_text(
            json.dumps(exported, separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        os.rename(staging_dir, output_dir)
        published = True
        result = {
            "output_directory": str(output_dir),
            "summary": str(output_dir / "dashboard-summary.json"),
            "confirmed_exposures": confirmed_count,
            "review_records": review_count,
            "assets": len(assets),
            "cves": len(cve_records),
            "products": len(product_records),
            "files": {
                path.name: path.stat().st_size
                for path in output_dir.iterdir()
                if path.is_file()
            },
        }
        print(json.dumps(result, indent=2), flush=True)
        return result
    finally:
        if not published and staging_dir.exists():
            shutil.rmtree(staging_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export current PRIORIS risk Parquet outputs for the Vite dashboard."
    )
    parser.add_argument("--risk-dir", type=Path, default=DEFAULT_RISK_DIR)
    parser.add_argument(
        "--exposure-summary",
        type=Path,
        default=DEFAULT_EXPOSURE_SUMMARY,
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    export_dashboard_data(
        risk_dir=args.risk_dir,
        exposure_summary_path=args.exposure_summary,
        output_dir=args.output_dir,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
