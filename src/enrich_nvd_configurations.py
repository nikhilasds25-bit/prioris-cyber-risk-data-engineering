"""Retrieve provenance-preserving NVD evidence for CVEs missing staged configuration trees."""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

if __package__:
    from .match_vulnerabilities import (
        ROOT,
        all_cpe_terms,
        load_raw_configuration_map,
        read_jsonl,
        term_criteria,
    )
else:
    from match_vulnerabilities import (
        ROOT,
        all_cpe_terms,
        load_raw_configuration_map,
        read_jsonl,
        term_criteria,
    )

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPEMATCH_API = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
MIN_REQUEST_INTERVAL_SECONDS = 6.2
MAX_ATTEMPTS = 5


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    os.replace(temporary_path, path)


def write_classification_report(output_dir: Path, manifest: dict[str, Any]) -> Path:
    path = output_dir / "cve_classification.csv"
    fields = [
        "cve_id",
        "classification",
        "http_status",
        "retrieved_at_utc",
        "sha256",
        "configuration_count",
        "affected_product_count",
        "match_criteria_ids",
        "file",
        "url",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in manifest.get("records", []):
            row = {field: record.get(field, "") for field in fields}
            row["match_criteria_ids"] = json.dumps(
                record.get("match_criteria_ids", []), separators=(",", ":")
            )
            writer.writerow(row)
    return path


def affected_products(cve: dict[str, Any]) -> list[Any]:
    containers = cve.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict) and isinstance(cna.get("affected"), list):
            return cna["affected"]
    direct = cve.get("affected")
    return direct if isinstance(direct, list) else []


def criterion_ids_without_configurations(record: dict[str, Any]) -> list[str]:
    found: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "matchCriteriaId" and isinstance(item, str):
                    if re.fullmatch(
                        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                        item,
                    ):
                        found.add(item.lower())
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(record)
    return sorted(found)


def classify_record(
    cve: dict[str, Any] | None,
    criteria_records: list[dict[str, Any]],
    *,
    response_error: bool = False,
) -> tuple[str, list[dict[str, Any]], int]:
    if response_error or cve is None:
        return "api_error", [], 0

    configurations = cve.get("configurations")
    if isinstance(configurations, dict):
        configurations = [configurations]
    if isinstance(configurations, list):
        usable = [
            config for config in configurations
            if isinstance(config, dict)
            and isinstance(config.get("nodes"), list)
            and bool(config.get("nodes"))
        ]
        if usable and any(
            term_criteria(term)
            for config in usable
            for term in all_cpe_terms(config)
        ):
            return "configuration_recovered", usable, len(affected_products(cve))

    if criteria_records:
        return "criteria_only", [], 0
    if configurations not in (None, [], {}):
        return "pending_review", [], 0
    products = affected_products(cve)
    if products:
        return "affected_products_only", [], len(products)
    return "no_usable_configuration", [], 0


def load_missing_cves(snapshot_date: str) -> list[str]:
    processed = ROOT / "data" / "processed" / snapshot_date / "nvd_cves.jsonl"
    raw_dir = ROOT / "data" / "raw" / snapshot_date
    raw_paths = [
        raw_dir / "nvd_general.json",
        raw_dir / "nvd_known_exploited.json",
    ]
    configs, _, _, _ = load_raw_configuration_map(raw_paths)
    normalized = read_jsonl(processed)
    missing = sorted({
        str(row["cve_id"])
        for row in normalized
        if row.get("cve_id") and str(row["cve_id"]) not in configs
    })
    invalid_ids = [cve_id for cve_id in missing if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)]
    if invalid_ids:
        raise ValueError(f"Invalid CVE identifiers in staged input: {invalid_ids[:5]}")
    return missing


def load_json_response(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


class NvdClient:
    def __init__(self, headers: dict[str, str]):
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.last_request_at = 0.0

    def get(self, url: str, params: dict[str, str]) -> tuple[int | None, bytes, str, str | None]:
        last_error: str | None = None
        for attempt in range(MAX_ATTEMPTS):
            wait_for_slot = MIN_REQUEST_INTERVAL_SECONDS - (
                time.monotonic() - self.last_request_at
            )
            if wait_for_slot > 0:
                time.sleep(wait_for_slot)
            requested_at = utc_now()
            try:
                response = self.session.get(url, params=params, timeout=60)
                self.last_request_at = time.monotonic()
                body = response.content
                if response.status_code == 200:
                    return response.status_code, body, response.url, requested_at
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in {429, 500, 502, 503, 504}:
                    return response.status_code, body, response.url, requested_at
                retry_after = response.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 30.0 * (attempt + 1)
                except ValueError:
                    delay = 30.0 * (attempt + 1)
            except requests.RequestException as exc:
                self.last_request_at = time.monotonic()
                last_error = f"{type(exc).__name__}: {exc}"
                delay = 10.0 * (attempt + 1)
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(min(delay, 300.0))
        return None, (last_error or "request failed").encode("utf-8"), url, utc_now()


def save_response(
    path: Path,
    status: int | None,
    body: bytes,
    url: str,
    requested_at: str,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return {
        "file": str(path.relative_to(path.parents[2])).replace("\\", "/"),
        "url": url,
        "http_status": status,
        "retrieved_at_utc": requested_at,
        "saved_at_utc": utc_now(),
        "sha256": sha256_bytes(body),
        "response_bytes": len(body),
    }


def enrich(
    snapshot_date: str,
    enrichment_date: str,
    output_dir: Path,
    *,
    resume: bool = False,
) -> dict[str, Any]:
    missing = load_missing_cves(snapshot_date)
    if not missing:
        raise ValueError("No CVEs are missing structured configurations in the selected snapshot.")
    if output_dir.exists() and not resume:
        raise FileExistsError(
            f"Enrichment output already exists at {output_dir}; use --resume to continue "
            "without replacing saved responses."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    responses_dir = output_dir / "responses"
    cve_response_dir = responses_dir / "cve"
    criteria_response_dir = responses_dir / "cpematch"
    manifest_path = output_dir / "manifest.json"
    previous: dict[str, Any] = {}
    if manifest_path.is_file():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        if previous.get("source_snapshot_date") != snapshot_date:
            raise ValueError("Existing enrichment manifest belongs to another source snapshot.")
        if previous.get("enrichment_date") != enrichment_date:
            raise ValueError("Existing enrichment manifest has a different enrichment date.")
        if previous.get("requested_cve_ids") != missing:
            raise ValueError("Missing-CVE set changed; use a new enrichment directory.")

    api_key = os.getenv("NVD_API_KEY")
    headers = {"User-Agent": "PRIORIS academic capstone configuration evidence retrieval"}
    if api_key:
        headers["apiKey"] = api_key
    client = NvdClient(headers)
    entries: dict[str, dict[str, Any]] = {
        item["cve_id"]: item for item in previous.get("records", [])
        if isinstance(item, dict) and item.get("cve_id")
    }
    criterion_entries: dict[str, dict[str, Any]] = {
        item["match_criteria_id"].lower(): item
        for item in previous.get("criteria_records", [])
        if isinstance(item, dict) and item.get("match_criteria_id")
    }

    for index, cve_id in enumerate(missing, start=1):
        entry = entries.get(cve_id)
        response_path = cve_response_dir / f"{cve_id}.json"
        if resume and entry and entry.get("http_status") == 200 and response_path.is_file():
            if sha256_bytes(response_path.read_bytes()) != entry.get("sha256"):
                raise ValueError(f"Saved NVD response hash mismatch; refusing resume: {response_path}")
            print(f"[{index}/{len(missing)}] Resume: saved NVD record for {cve_id}", flush=True)
            continue
        print(f"[{index}/{len(missing)}] Requesting official NVD record {cve_id}", flush=True)
        status, body, url, requested_at = client.get(
            NVD_CVE_API, {"cveId": cve_id}
        )
        metadata = save_response(response_path, status, body, url, requested_at)
        document = load_json_response(response_path) if status == 200 else None
        records = document.get("vulnerabilities", []) if document else []
        cve = None
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict) and isinstance(record.get("cve"), dict):
                    if record["cve"].get("id") == cve_id:
                        cve = record["cve"]
                        break
        if status == 200 and cve is None:
            classification = "pending_review"
            config_count = 0
            product_count = 0
            criteria_ids: list[str] = []
            metadata["response_parse_status"] = "expected_cve_record_not_found"
        elif status != 200:
            classification = "api_error"
            config_count = 0
            product_count = 0
            criteria_ids = []
            metadata["response_parse_status"] = "http_or_transport_error"
        else:
            classification, configs, product_count = classify_record(cve, [])
            config_count = len(configs)
            criteria_ids = criterion_ids_without_configurations(cve or {}) if not configs else []
            metadata["response_parse_status"] = "parsed"
        entries[cve_id] = {
            "cve_id": cve_id,
            **metadata,
            "classification": classification,
            "configuration_count": config_count,
            "affected_product_count": product_count,
            "match_criteria_ids": criteria_ids,
        }
        manifest = make_manifest(
            snapshot_date, enrichment_date, missing, entries, criterion_entries
        )
        write_manifest(manifest_path, manifest)

    criterion_ids = sorted({
        criterion_id
        for cve_id in missing
        for criterion_id in entries.get(cve_id, {}).get("match_criteria_ids", [])
    })
    for index, criterion_id in enumerate(criterion_ids, start=1):
        existing = criterion_entries.get(criterion_id)
        criterion_path = criteria_response_dir / f"{criterion_id}.json"
        if resume and existing and existing.get("http_status") == 200 and criterion_path.is_file():
            continue
        print(
            f"[CPE criteria {index}/{len(criterion_ids)}] Requesting {criterion_id}",
            flush=True,
        )
        status, body, url, requested_at = client.get(
            NVD_CPEMATCH_API, {"matchCriteriaId": criterion_id}
        )
        metadata = save_response(criterion_path, status, body, url, requested_at)
        document = load_json_response(criterion_path) if status == 200 else None
        criterion_records = document.get("matchStrings", []) if document else []
        criteria_entry = {
            "match_criteria_id": criterion_id,
            **metadata,
            "classification": (
                "criteria_only"
                if status == 200 and isinstance(criterion_records, list) and criterion_records
                else "api_error"
                if status != 200
                else "no_usable_configuration"
            ),
        }
        criterion_entries[criterion_id] = criteria_entry
        for cve_id in missing:
            entry = entries.get(cve_id, {})
            if criterion_id not in entry.get("match_criteria_ids", []):
                continue
            if entry.get("classification") not in {
                "configuration_recovered", "api_error"
            }:
                related = [
                    criterion_entries.get(item, {})
                    for item in entry.get("match_criteria_ids", [])
                ]
                has_criteria = any(
                    item.get("http_status") == 200
                    and item.get("classification") == "criteria_only"
                    for item in related
                )
                if has_criteria:
                    entry["classification"] = "criteria_only"
        write_manifest(
            manifest_path,
            make_manifest(snapshot_date, enrichment_date, missing, entries, criterion_entries),
        )

    manifest = make_manifest(snapshot_date, enrichment_date, missing, entries, criterion_entries)
    manifest["completed_at_utc"] = utc_now()
    write_manifest(manifest_path, manifest)
    write_classification_report(output_dir, manifest)
    return manifest


def make_manifest(
    snapshot_date: str,
    enrichment_date: str,
    requested_cves: list[str],
    entries: dict[str, dict[str, Any]],
    criteria_entries: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "project": "PRIORIS",
        "purpose": "Recover authoritative NVD evidence without changing the staged snapshot.",
        "source_snapshot_date": snapshot_date,
        "enrichment_date": enrichment_date,
        "started_or_updated_at_utc": utc_now(),
        "source_api": NVD_CVE_API,
        "criteria_api": NVD_CPEMATCH_API,
        "request_policy": {
            "sequential": True,
            "minimum_seconds_between_requests": MIN_REQUEST_INTERVAL_SECONDS,
            "maximum_attempts_per_request": MAX_ATTEMPTS,
            "retry_statuses": [429, 500, 502, 503, 504],
        },
        "requested_cve_count": len(requested_cves),
        "requested_cve_ids": requested_cves,
        "records": [entries[cve_id] for cve_id in requested_cves if cve_id in entries],
        "criteria_records": [
            criteria_entries[key] for key in sorted(criteria_entries)
        ],
        "classification_counts": {
            classification: sum(
                entry.get("classification") == classification
                for entry in entries.values()
            )
            for classification in (
                "configuration_recovered",
                "affected_products_only",
                "criteria_only",
                "no_usable_configuration",
                "api_error",
                "pending_review",
            )
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Retrieve official NVD CVE evidence for missing staged configurations."
    )
    parser.add_argument("--date", default="2026-10-19", help="Source snapshot date.")
    parser.add_argument(
        "--enrichment-date",
        default=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        help="UTC retrieval folder date.",
    )
    parser.add_argument("--output-dir", type=Path, help="Separate enrichment output directory.")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume an existing enrichment directory without replacing successful responses.",
    )
    args = parser.parse_args(argv)
    for label, value in (("--date", args.date), ("--enrichment-date", args.enrichment_date)):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parser.error(f"{label} must use YYYY-MM-DD format.")
    output_dir = args.output_dir or Path("data") / "enrichment" / args.enrichment_date
    if not output_dir.is_absolute():
        output_dir = ROOT / output_dir
    output_dir = output_dir.resolve()
    try:
        manifest = enrich(args.date, args.enrichment_date, output_dir, resume=args.resume)
    except (OSError, ValueError, requests.RequestException, json.JSONDecodeError) as exc:
        print(f"ERROR: NVD enrichment failed: {exc}", file=sys.stderr)
        return 2
    print(f"Saved enrichment evidence under {output_dir}")
    print(f"Classification counts: {json.dumps(manifest['classification_counts'], sort_keys=True)}")
    print(
        f"Successfully retrieved configuration trees: "
        f"{manifest['classification_counts']['configuration_recovered']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
