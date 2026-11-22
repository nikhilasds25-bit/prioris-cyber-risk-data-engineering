"""PRIORIS Phase 1: fetch fixed NVD/CISA snapshots and prepare simple JSONL tables.

Run: python src/download_data.py
Notes:
- NVD 'hasKev' sample is deliberately enriched with KEV cases.
- A second date-bounded NVD sample adds comparison cases.
- This is NOT a representative statistical sample of all vulnerabilities.
- Raw NVD configurations are retained for later, correct CPE/version matching.
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_OFFICIAL_MIRROR = (
    "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/develop/"
    "known_exploited_vulnerabilities.json"
)


def get_json(url, *, params=None, headers=None):
    """A small request helper; avoid hammering public endpoints."""
    for attempt in range(3):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=90)
            r.raise_for_status()
            return r.json(), r.url
        except (requests.RequestException, ValueError) as exc:
            if attempt == 2:
                raise RuntimeError(f"Could not retrieve {url}: {exc}") from exc
            time.sleep(10 * (attempt + 1))
    raise AssertionError("unreachable")


def cvss_score(cve):
    """Return a single CVSS score in preferred version order, or (None, None)."""
    metrics = cve.get("metrics") or {}
    for field, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(field) or []
        if entries:
            selected = next((v for v in entries if v.get("type") == "Primary"), entries[0])
            val = (selected.get("cvssData") or {}).get("baseScore")
            if val is not None:
                return float(val), version
    return None, None


def normalize_nvd(data):
    records = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        identifier = cve.get("id")
        if not identifier:
            continue
        descriptions = cve.get("descriptions") or []
        description = next((v.get("value") for v in descriptions if v.get("lang") == "en"), None)
        score, version = cvss_score(cve)
        records.append({
            "cve_id": identifier,
            "description": description,
            "cvss_score": score,
            "cvss_version": version,
            "published": cve.get("published"),
            "has_configurations": bool(cve.get("configurations")),
        })
    return records


def write_jsonl(path, rows):
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def main():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    raw = ROOT / "data" / "raw" / today
    processed = ROOT / "data" / "processed" / today
    if raw.exists():
        raise FileExistsError(
            f"Raw snapshot already exists at {raw}; refusing to overwrite it. "
            "Use the existing snapshot or choose a different retrieval date."
        )

    api_key = os.getenv("NVD_API_KEY")
    nvd_headers = {"User-Agent": "Prioris academic capstone (NVD/CISA snapshot)"}
    if api_key:
        nvd_headers["apiKey"] = api_key

    print("Downloading NVD sample containing known-exploited CVEs...")
    # NVD 2.0 supports a valueless 'hasKev' query flag.
    nvd_kev, url_kev = get_json(
        f"{NVD_API}?hasKev&resultsPerPage=200", headers=nvd_headers
    )
    time.sleep(7)  # Be considerate of NVD's public rate limits.

    print("Downloading a second NVD sample from a fixed publication window...")
    nvd_general, url_general = get_json(
        NVD_API,
        params={
            "pubStartDate": "2025-01-01T00:00:00.000",
            "pubEndDate": "2025-01-15T23:59:59.999",
            "resultsPerPage": "200",
        },
        headers=nvd_headers,
    )
    print("Downloading official CISA KEV catalog...")
    try:
        kev, url_cisa = get_json(CISA_URL)
    except RuntimeError:
        print("CISA feed unavailable; trying its official GitHub mirror...")
        kev, url_cisa = get_json(CISA_OFFICIAL_MIRROR)

    raw.mkdir(parents=True)
    processed.mkdir(parents=True, exist_ok=True)
    for name, content in (
        ("nvd_known_exploited.json", nvd_kev),
        ("nvd_general.json", nvd_general),
        ("cisa_kev.json", kev),
    ):
        (raw / name).write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")

    nvd_rows = list({
        row["cve_id"]: row
        for doc in (nvd_kev, nvd_general)
        for row in normalize_nvd(doc)
    }.values())
    kev_rows = [
        {
            "cve_id": item["cveID"],
            "date_added": item.get("dateAdded"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
        }
        for item in kev.get("vulnerabilities", [])
        if item.get("cveID")
    ]
    write_jsonl(processed / "nvd_cves.jsonl", nvd_rows)
    write_jsonl(processed / "cisa_kev.jsonl", kev_rows)

    manifest = {
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
        "snapshot_folder": today,
        "urls": {
            "nvd_kev_sample": url_kev,
            "nvd_general_sample": url_general,
            "cisa_kev": url_cisa,
        },
        "cisa_catalog_version": kev.get("catalogVersion"),
        "nvd_known_exploited_records": len(nvd_kev.get("vulnerabilities", [])),
        "nvd_general_records": len(nvd_general.get("vulnerabilities", [])),
        "nvd_records": len(nvd_rows),
        "cisa_records": len(kev_rows),
        "important_note": (
            "First-stage mixed sample selected to demonstrate the join, not a "
            "representative population. Keep original JSON for product/version matching."
        ),
    }
    (raw / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Success: {len(nvd_rows)} NVD CVEs, {len(kev_rows)} CISA KEV entries.")
    print(f"Snapshot date: {today}")
    print(f"Raw snapshot: {raw}")
    print(f"Processed records: {processed}")
    print("Next: python src/first_join.py --date", today)


if __name__ == "__main__":
    main()
