"""Import the existing static dashboard export into PostgreSQL.

Run from the backend directory:
    python -m app.importer --input-dir ../web/public/data

The importer is idempotent by SHA-256 of the three export files. It streams
compressed exposure arrays in bounded batches and preserves each source row.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterator
import ijson

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Base, DashboardSnapshot, ExposureRecord


def sha256_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def iter_records(path: Path) -> Iterator[dict]:
    with gzip.open(path, "rb") as handle:
        yield from ijson.items(handle, "item", use_float=True)


def import_snapshot(input_dir: Path, batch_size: int = 1000) -> str:
    if SessionLocal is None:
        raise RuntimeError("DATABASE_URL is not configured")
    summary_path = input_dir / "dashboard-summary.json"
    confirmed_path = input_dir / "confirmed-exposures.json.gz"
    review_path = input_dir / "review-queue.json.gz"
    for path in (summary_path, confirmed_path, review_path):
        if not path.is_file():
            raise FileNotFoundError(f"Required dashboard export is missing: {path}")

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    required = {"product", "generatedAt", "synthetic", "metrics", "assets", "cves"}
    missing = sorted(required - summary.keys())
    if missing:
        raise ValueError(f"Dashboard summary is missing required fields: {', '.join(missing)}")
    if summary["product"] != "PRIORIS":
        raise ValueError("Input summary does not identify the PRIORIS product")

    fingerprint = sha256_files([summary_path, confirmed_path, review_path])
    generated_at = parse_datetime(summary.get("generatedAt"))
    snapshot_date = date.fromisoformat(summary["snapshotDate"]) if summary.get("snapshotDate") else None

    with SessionLocal() as db:
        existing = db.scalar(select(DashboardSnapshot).where(DashboardSnapshot.snapshot_hash == fingerprint))
        if existing:
            return f"Already imported snapshot {existing.id}; no changes made."

        snapshot = DashboardSnapshot(
            snapshot_hash=fingerprint,
            snapshot_date=snapshot_date,
            generated_at=generated_at,
            is_synthetic=bool(summary.get("synthetic", False)),
            summary=summary,
        )
        db.add(snapshot)
        db.flush()

        for view_name, path in (("confirmed", confirmed_path), ("review", review_path)):
            batch: list[ExposureRecord] = []
            count = 0
            for index, record in enumerate(iter_records(path)):
                if not isinstance(record, dict):
                    raise ValueError(f"{path.name} contains a non-object record at index {index}")
                record_id = record.get("recordId", index)
                try:
                    record_id = int(record_id)
                except (TypeError, ValueError):
                    raise ValueError(f"Invalid recordId in {path.name} at index {index}")
                score = record.get("riskScore")
                batch.append(ExposureRecord(
                    snapshot_id=snapshot.id,
                    view_name=view_name,
                    record_id=record_id,
                    asset_id=record.get("assetId"),
                    cve_id=record.get("cveId"),
                    risk_tier=record.get("riskTier"),
                    risk_score=float(score) if score is not None else None,
                    known_exploited=record.get("knownExploited"),
                    payload=record,
                ))
                if len(batch) >= batch_size:
                    db.add_all(batch)
                    db.flush()
                    count += len(batch)
                    batch.clear()
            if batch:
                db.add_all(batch)
                db.flush()
                count += len(batch)
            print(f"Imported {count:,} {view_name} records")

        db.commit()
        return f"Imported snapshot {snapshot.id} ({fingerprint[:12]})"


def main():
    parser = argparse.ArgumentParser(description="Import PRIORIS dashboard exports into PostgreSQL.")
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--batch-size", type=int, default=1000)
    args = parser.parse_args()
    if args.batch_size < 1 or args.batch_size > 10000:
        parser.error("--batch-size must be between 1 and 10000")
    print(import_snapshot(args.input_dir.resolve(), args.batch_size))


if __name__ == "__main__":
    main()
