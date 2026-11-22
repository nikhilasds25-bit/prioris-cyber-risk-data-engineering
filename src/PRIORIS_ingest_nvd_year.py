#!/usr/bin/env python3
"""Stream one official NVD yearly CVE feed into relational Parquet datasets.

PRIORIS historical NVD pilot. The source ZIP and META files are read-only.
Intermediate JSONL files are temporary. Parquet output is published atomically
only after source checksum and output row-count checks pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import ijson
import pyarrow as pa
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data" / "external" / "nvd_cve_yearly"
DEFAULT_OUTPUT_ROOT = ROOT / "data" / "processed" / "nvd_historical"
DEFAULT_YEAR = 2026
DEFAULT_CHUNK_RECORDS = 2500
DEFAULT_ARROW_BATCH_SIZE = 5000

# Each table uses primitive columns plus a source-JSON column where appropriate.
# Full raw CVE JSON is also retained in cve_core, so extraction does not discard
# source fields that are not yet part of the analytical schema.
TABLE_FIELDS: dict[str, list[tuple[str, str]]] = {
    "cve_core": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("source_identifier", "string"),
        ("published", "string"),
        ("last_modified", "string"),
        ("vuln_status", "string"),
        ("description_en", "string"),
        ("cvss_version", "string"),
        ("cvss_score", "double"),
        ("cvss_severity", "string"),
        ("cvss_vector", "string"),
        ("has_configurations", "bool"),
        ("configuration_count", "int"),
        ("has_affected_data", "bool"),
        ("affected_record_count", "int"),
        ("cve_tags_json", "string"),
        ("raw_cve_json", "string"),
    ],
    "cve_descriptions": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("description_index", "int"),
        ("language", "string"),
        ("value", "string"),
        ("raw_description_json", "string"),
    ],
    "cve_configurations": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("configuration_index", "int"),
        ("top_level_node_count", "int"),
        ("raw_configuration_json", "string"),
    ],
    "cve_nodes": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("configuration_index", "int"),
        ("node_path", "string"),
        ("parent_node_path", "string"),
        ("operator", "string"),
        ("negate", "bool"),
        ("cpe_match_count", "int"),
        ("child_node_count", "int"),
        ("raw_node_json", "string"),
    ],
    "cve_cpe_matches": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("configuration_index", "int"),
        ("node_path", "string"),
        ("match_index", "int"),
        ("vulnerable", "bool"),
        ("criteria", "string"),
        ("match_criteria_id", "string"),
        ("status", "string"),
        ("version_start_including", "string"),
        ("version_start_excluding", "string"),
        ("version_end_including", "string"),
        ("version_end_excluding", "string"),
        ("raw_match_json", "string"),
    ],
    "cve_affected_records": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("affected_record_index", "int"),
        ("source", "string"),
        ("affected_data_count", "int"),
        ("raw_affected_record_json", "string"),
    ],
    "cve_affected_products": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("affected_record_index", "int"),
        ("affected_data_index", "int"),
        ("source", "string"),
        ("vendor", "string"),
        ("product", "string"),
        ("cpes_json", "string"),
        ("versions_json", "string"),
        ("raw_affected_data_json", "string"),
    ],
    "cve_metrics": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("metric_field", "string"),
        ("metric_index", "int"),
        ("metric_version", "string"),
        ("metric_type", "string"),
        ("source", "string"),
        ("base_score", "double"),
        ("base_severity", "string"),
        ("vector_string", "string"),
        ("raw_metric_json", "string"),
    ],
    "cve_weaknesses": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("weakness_index", "int"),
        ("source", "string"),
        ("weakness_type", "string"),
        ("descriptions_json", "string"),
        ("raw_weakness_json", "string"),
    ],
    "cve_references": [
        ("source_year", "int"),
        ("cve_id", "string"),
        ("reference_index", "int"),
        ("url", "string"),
        ("source", "string"),
        ("tags_json", "string"),
        ("raw_reference_json", "string"),
    ],
}

SPARK_TYPE_NAMES = {
    "string": "StringType",
    "int": "IntegerType",
    "double": "DoubleType",
    "bool": "BooleanType",
}


def json_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def parse_meta(meta_path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    with meta_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise ValueError(f"Invalid META line {line_number}: {line!r}")
            key, value = (piece.strip() for piece in line.split(":", 1))
            fields[key] = value

    for required in ("size", "zipSize", "sha256"):
        if required not in fields:
            raise ValueError(f"META file is missing {required!r}")
    if not fields["size"].isdigit() or not fields["zipSize"].isdigit():
        raise ValueError("META size and zipSize must be non-negative integers")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", fields["sha256"]):
        raise ValueError("META sha256 must be 64 hexadecimal characters")
    return fields


class HashingReader:
    """Read-through wrapper that hashes/counts the uncompressed ZIP member."""

    def __init__(self, raw: Any) -> None:
        self.raw = raw
        self.digest = hashlib.sha256()
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self.raw.read(size)
        if chunk:
            self.digest.update(chunk)
            self.bytes_read += len(chunk)
        return chunk

    def readinto(self, buffer: Any) -> int:
        data = self.raw.read(len(buffer))
        count = len(data)
        if count:
            buffer[:count] = data
            self.digest.update(data)
            self.bytes_read += count
        return count

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw, name)


class JsonlChunkWriter:
    """Write bounded JSONL chunks so Spark can read several moderate files."""

    def __init__(self, directory: Path, chunk_records: int) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.chunk_records = chunk_records
        self.total_records = 0
        self.chunk_index = 0
        self.records_in_chunk = 0
        self.handle = None

    def _open_next(self) -> None:
        if self.handle is not None:
            self.handle.close()
        path = self.directory / f"part-{self.chunk_index:05d}.jsonl"
        self.handle = path.open("w", encoding="utf-8", newline="\n")
        self.chunk_index += 1
        self.records_in_chunk = 0

    def write(self, row: dict[str, Any]) -> None:
        if self.handle is None or self.records_in_chunk >= self.chunk_records:
            self._open_next()
        self.handle.write(json_compact(row))
        self.handle.write("\n")
        self.records_in_chunk += 1
        self.total_records += 1

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


def format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0 or seconds == float("inf"):
        return "calculating"
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"


def progress_line(label: str, done: int, total: int, started: float, unit: str) -> None:
    pct = 100.0 if total <= 0 else min(100.0, (done / total) * 100.0)
    filled = min(30, int(pct / 100.0 * 30))
    bar = "#" * filled + "-" * (30 - filled)
    elapsed = time.perf_counter() - started
    rate = done / elapsed if elapsed > 0 and done > 0 else 0.0
    remaining = max(0, total - done)
    eta = remaining / rate if rate > 0 else None
    print(
        f"\r[{bar}] {pct:6.2f}% | {done:,}/{total:,} {unit} | "
        f"Elapsed {format_duration(elapsed)} | ETA {format_duration(eta)} | {label}",
        end="",
        flush=True,
    )


def complete_progress() -> None:
    print("", flush=True)


def iter_node_tree(nodes: list[dict[str, Any]], parent_path: str = "") -> Iterator[tuple[dict[str, Any], str, str | None]]:
    for index, node in enumerate(nodes):
        node_path = f"{parent_path}/{index}" if parent_path else str(index)
        yield node, node_path, parent_path or None
        children = node.get("nodes") or []
        if isinstance(children, list) and children:
            yield from iter_node_tree(children, node_path)


def iter_metric_values(value: Any) -> Iterator[tuple[int, dict[str, Any]]]:
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, dict):
                yield index, item
    elif isinstance(value, dict):
        yield 0, value


def metric_version(field_name: str) -> str | None:
    if field_name.lower() == "cvssmetricv2":
        return "2.0"
    match = re.search(r"cvssMetricV(\d)(\d+)$", field_name, flags=re.IGNORECASE)
    if not match:
        return None
    return f"{match.group(1)}.{match.group(2)}"


def select_primary_cvss(metrics: dict[str, Any]) -> tuple[str | None, float | None, str | None, str | None]:
    for field_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = list(iter_metric_values(metrics.get(field_name)))
        if not values:
            continue
        selected = next((item for _, item in values if item.get("type") == "Primary"), values[0][1])
        cvss_data = selected.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        try:
            score_value = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_value = None
        return (
            metric_version(field_name),
            score_value,
            cvss_data.get("baseSeverity") or selected.get("baseSeverity"),
            cvss_data.get("vectorString"),
        )
    return None, None, None, None


def extract_records(
    zip_path: Path,
    meta: dict[str, str],
    year: int,
    staging_root: Path,
    chunk_records: int,
) -> tuple[dict[str, int], dict[str, Any]]:
    expected_json_bytes = int(meta["size"])
    expected_zip_bytes = int(meta["zipSize"])
    expected_sha = meta["sha256"].lower()
    actual_zip_bytes = zip_path.stat().st_size
    if actual_zip_bytes != expected_zip_bytes:
        raise ValueError(
            f"ZIP size mismatch before ingestion: expected {expected_zip_bytes}, got {actual_zip_bytes}"
        )

    with zipfile.ZipFile(zip_path, "r") as archive:
        json_members = [
            item for item in archive.infolist()
            if not item.is_dir() and item.filename.lower().endswith(".json")
        ]
        if len(json_members) != 1:
            raise ValueError(f"Expected exactly one JSON member in {zip_path.name}, found {len(json_members)}")
        json_member = json_members[0]

        writers = {
            name: JsonlChunkWriter(staging_root / name, chunk_records)
            for name in TABLE_FIELDS
        }
        totals: Counter[str] = Counter()
        extraction_started = time.perf_counter()
        last_update = extraction_started
        record_number = 0
        hashing_reader = None

        try:
            with archive.open(json_member, "r") as raw_stream:
                hashing_reader = HashingReader(raw_stream)
                for wrapper in ijson.items(hashing_reader, "vulnerabilities.item", use_float=True):
                    record_number += 1
                    cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
                    if not isinstance(cve, dict):
                        totals["records_without_cve_object"] += 1
                        continue
                    cve_id = cve.get("id")
                    if not isinstance(cve_id, str) or not cve_id.strip():
                        totals["records_without_cve_id"] += 1
                        continue
                    cve_id = cve_id.strip()
                    totals["cve_records"] += 1

                    descriptions = cve.get("descriptions") or []
                    configurations = cve.get("configurations") or []
                    affected = cve.get("affected") or []
                    if isinstance(affected, dict):
                        affected = [affected]
                    elif not isinstance(affected, list):
                        affected = []
                    metrics = cve.get("metrics") or {}
                    weaknesses = cve.get("weaknesses") or []
                    references = cve.get("references") or []

                    description_en = next(
                        (item.get("value") for item in descriptions
                         if isinstance(item, dict) and item.get("lang") == "en"),
                        None,
                    )
                    cvss_ver, cvss_score, cvss_severity, cvss_vector = select_primary_cvss(metrics)

                    writers["cve_core"].write({
                        "source_year": year,
                        "cve_id": cve_id,
                        "source_identifier": cve.get("sourceIdentifier"),
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "vuln_status": cve.get("vulnStatus"),
                        "description_en": description_en,
                        "cvss_version": cvss_ver,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "cvss_vector": cvss_vector,
                        "has_configurations": bool(configurations),
                        "configuration_count": len(configurations),
                        "has_affected_data": bool(affected),
                        "affected_record_count": len(affected),
                        "cve_tags_json": json_compact(cve.get("cveTags") or []),
                        "raw_cve_json": json_compact(cve),
                    })

                    for desc_index, description in enumerate(descriptions):
                        if isinstance(description, dict):
                            writers["cve_descriptions"].write({
                                "source_year": year,
                                "cve_id": cve_id,
                                "description_index": desc_index,
                                "language": description.get("lang"),
                                "value": description.get("value"),
                                "raw_description_json": json_compact(description),
                            })

                    for config_index, configuration in enumerate(configurations):
                        if not isinstance(configuration, dict):
                            continue
                        top_nodes = configuration.get("nodes") or []
                        if not isinstance(top_nodes, list):
                            top_nodes = []
                        writers["cve_configurations"].write({
                            "source_year": year,
                            "cve_id": cve_id,
                            "configuration_index": config_index,
                            "top_level_node_count": len(top_nodes),
                            "raw_configuration_json": json_compact(configuration),
                        })

                        for node, node_path, parent_path in iter_node_tree(top_nodes):
                            cpe_matches = node.get("cpeMatch") or []
                            if not isinstance(cpe_matches, list):
                                cpe_matches = []
                            child_nodes = node.get("nodes") or []
                            writers["cve_nodes"].write({
                                "source_year": year,
                                "cve_id": cve_id,
                                "configuration_index": config_index,
                                "node_path": node_path,
                                "parent_node_path": parent_path,
                                "operator": node.get("operator"),
                                "negate": node.get("negate"),
                                "cpe_match_count": len(cpe_matches),
                                "child_node_count": len(child_nodes) if isinstance(child_nodes, list) else 0,
                                "raw_node_json": json_compact(node),
                            })
                            for match_index, match in enumerate(cpe_matches):
                                if not isinstance(match, dict):
                                    continue
                                writers["cve_cpe_matches"].write({
                                    "source_year": year,
                                    "cve_id": cve_id,
                                    "configuration_index": config_index,
                                    "node_path": node_path,
                                    "match_index": match_index,
                                    "vulnerable": match.get("vulnerable"),
                                    "criteria": match.get("criteria"),
                                    "match_criteria_id": match.get("matchCriteriaId"),
                                    "status": match.get("status"),
                                    "version_start_including": match.get("versionStartIncluding"),
                                    "version_start_excluding": match.get("versionStartExcluding"),
                                    "version_end_including": match.get("versionEndIncluding"),
                                    "version_end_excluding": match.get("versionEndExcluding"),
                                    "raw_match_json": json_compact(match),
                                })

                    for affected_index, affected_record in enumerate(affected):
                        if not isinstance(affected_record, dict):
                            continue
                        affected_data = affected_record.get("affectedData") or []
                        if not isinstance(affected_data, list):
                            affected_data = []
                        source = affected_record.get("source")
                        writers["cve_affected_records"].write({
                            "source_year": year,
                            "cve_id": cve_id,
                            "affected_record_index": affected_index,
                            "source": source,
                            "affected_data_count": len(affected_data),
                            "raw_affected_record_json": json_compact(affected_record),
                        })
                        product_items = affected_data
                        if not product_items and any(k in affected_record for k in ("vendor", "product", "versions", "cpes")):
                            product_items = [affected_record]
                        for product_index, product_item in enumerate(product_items):
                            if not isinstance(product_item, dict):
                                continue
                            writers["cve_affected_products"].write({
                                "source_year": year,
                                "cve_id": cve_id,
                                "affected_record_index": affected_index,
                                "affected_data_index": product_index,
                                "source": source,
                                "vendor": product_item.get("vendor"),
                                "product": product_item.get("product"),
                                "cpes_json": json_compact(product_item.get("cpes") or []),
                                "versions_json": json_compact(product_item.get("versions") or []),
                                "raw_affected_data_json": json_compact(product_item),
                            })

                    if isinstance(metrics, dict):
                        for metric_field, metric_value in metrics.items():
                            for metric_index, metric in iter_metric_values(metric_value):
                                cvss_data = metric.get("cvssData") or {}
                                base_score = cvss_data.get("baseScore")
                                try:
                                    base_score_value = float(base_score) if base_score is not None else None
                                except (TypeError, ValueError):
                                    base_score_value = None
                                writers["cve_metrics"].write({
                                    "source_year": year,
                                    "cve_id": cve_id,
                                    "metric_field": metric_field,
                                    "metric_index": metric_index,
                                    "metric_version": metric_version(metric_field),
                                    "metric_type": metric.get("type"),
                                    "source": metric.get("source"),
                                    "base_score": base_score_value,
                                    "base_severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                                    "vector_string": cvss_data.get("vectorString"),
                                    "raw_metric_json": json_compact(metric),
                                })

                    for weakness_index, weakness in enumerate(weaknesses):
                        if isinstance(weakness, dict):
                            writers["cve_weaknesses"].write({
                                "source_year": year,
                                "cve_id": cve_id,
                                "weakness_index": weakness_index,
                                "source": weakness.get("source"),
                                "weakness_type": weakness.get("type"),
                                "descriptions_json": json_compact(weakness.get("description") or []),
                                "raw_weakness_json": json_compact(weakness),
                            })

                    for reference_index, reference in enumerate(references):
                        if isinstance(reference, dict):
                            writers["cve_references"].write({
                                "source_year": year,
                                "cve_id": cve_id,
                                "reference_index": reference_index,
                                "url": reference.get("url"),
                                "source": reference.get("source"),
                                "tags_json": json_compact(reference.get("tags") or []),
                                "raw_reference_json": json_compact(reference),
                            })

                    now = time.perf_counter()
                    if record_number % 1000 == 0 or now - last_update >= 1.5:
                        progress_line(
                            "Streaming NVD JSON",
                            hashing_reader.bytes_read,
                            expected_json_bytes,
                            extraction_started,
                            "uncompressed bytes",
                        )
                        last_update = now

                # Ensure the digest covers the complete uncompressed JSON member,
                # including any trailing whitespace after the vulnerabilities array.
                while hashing_reader.read(8 * 1024 * 1024):
                    pass

            complete_progress()
            actual_json_bytes = hashing_reader.bytes_read
            actual_json_sha = hashing_reader.digest.hexdigest()
            if actual_json_bytes != expected_json_bytes:
                raise ValueError(
                    f"Uncompressed JSON size mismatch: META={expected_json_bytes}, actual={actual_json_bytes}"
                )
            if actual_json_sha.lower() != expected_sha:
                raise ValueError(
                    f"Uncompressed JSON SHA-256 mismatch: META={expected_sha}, actual={actual_json_sha}"
                )
        finally:
            for writer in writers.values():
                writer.close()

    table_counts = {name: writer.total_records for name, writer in writers.items()}
    extraction_summary = {
        "json_member": json_member.filename,
        "uncompressed_json_bytes": actual_json_bytes,
        "uncompressed_json_sha256": actual_json_sha,
        "zip_bytes": actual_zip_bytes,
        "vulnerability_items_seen": record_number,
        "cve_records_with_id": totals["cve_records"],
        "records_without_cve_object": totals["records_without_cve_object"],
        "records_without_cve_id": totals["records_without_cve_id"],
    }
    return table_counts, {**extraction_summary, "table_counts": table_counts}


def build_spark_and_arrow_schemas(table_name: str):
    from pyspark.sql.types import (
        BooleanType,
        DoubleType,
        IntegerType,
        StringType,
        StructField,
        StructType,
    )

    spark_types = {
        "string": StringType,
        "int": IntegerType,
        "double": DoubleType,
        "bool": BooleanType,
    }
    arrow_types = {
        "string": pa.string(),
        "int": pa.int32(),
        "double": pa.float64(),
        "bool": pa.bool_(),
    }
    fields = TABLE_FIELDS[table_name]
    spark_schema = StructType([
        StructField(name, spark_types[kind](), nullable=True)
        for name, kind in fields
    ])
    arrow_schema = pa.schema([
        pa.field(name, arrow_types[kind], nullable=True)
        for name, kind in fields
    ])
    return spark_schema, arrow_schema


def read_jsonl_file(file_path: str) -> Iterator[dict[str, Any]]:
    with open(file_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON in {file_path} at line {line_number}: {error.msg}"
                ) from error
            if not isinstance(row, dict):
                raise ValueError(
                    f"Expected a JSON object in {file_path} at line {line_number}"
                )
            yield row


def export_table_with_spark_arrow(
    spark: Any,
    table_name: str,
    jsonl_dir: Path,
    parquet_root: Path,
    expected_rows: int,
    batch_size: int,
) -> int:
    from pyspark.sql import functions as F

    if expected_rows == 0:
        print(f"  {table_name}: no rows; no Parquet file created.")
        return 0

    spark_schema, arrow_schema = build_spark_and_arrow_schemas(table_name)
    jsonl_files = sorted(str(path.resolve()) for path in jsonl_dir.glob("*.jsonl"))
    if not jsonl_files:
        raise FileNotFoundError(f"No JSONL chunk files found for {table_name}: {jsonl_dir}")
    jsonl_partitions = len(jsonl_files)
    records = spark.sparkContext.parallelize(
        jsonl_files, numSlices=jsonl_partitions
    ).flatMap(read_jsonl_file)
    dataframe = (
        spark.createDataFrame(records, schema=spark_schema)
        .filter(F.col("cve_id").isNotNull() & (F.length(F.trim(F.col("cve_id"))) > 0))
        .withColumn("cve_id", F.upper(F.trim(F.col("cve_id"))))
    )

    output_dir = parquet_root / table_name
    output_dir.mkdir(parents=True, exist_ok=True)
    parquet_file = output_dir / "part-00000.parquet"
    parquet_writer = None
    batch: list[dict[str, Any]] = []
    written = 0
    started = time.perf_counter()

    print(
        f"\n  {table_name}: Spark processing {expected_rows:,} extracted rows "
        f"from {len(jsonl_files):,} JSONL chunk files across "
        f"{jsonl_partitions:,} Spark input partitions, in Arrow batches of "
        f"{batch_size:,}...",
        flush=True,
    )

    def flush_batch() -> None:
        nonlocal parquet_writer, written, batch
        if not batch:
            return
        table = pa.Table.from_pylist(batch, schema=arrow_schema)
        if parquet_writer is None:
            parquet_writer = pq.ParquetWriter(
                parquet_file,
                arrow_schema,
                compression="zstd",
                use_dictionary=True,
            )
        parquet_writer.write_table(table, row_group_size=batch_size)
        written += len(batch)
        batch = []
        progress_line(
            f"Writing {table_name}", written, expected_rows, started, "rows"
        )

    try:
        for row in dataframe.toLocalIterator(prefetchPartitions=False):
            batch.append(row.asDict(recursive=True))
            if len(batch) >= batch_size:
                flush_batch()
        flush_batch()
    finally:
        if parquet_writer is not None:
            parquet_writer.close()

    complete_progress()
    if written != expected_rows:
        raise RuntimeError(
            f"{table_name} row-count mismatch: extracted {expected_rows}, wrote {written}"
        )
    if not parquet_file.is_file():
        raise RuntimeError(f"Expected Parquet output was not created: {parquet_file}")

    metadata_rows = pq.ParquetFile(parquet_file).metadata.num_rows
    if metadata_rows != written:
        raise RuntimeError(
            f"{table_name} Parquet metadata row-count mismatch: expected {written}, got {metadata_rows}"
        )
    print(
        f"  PASS {table_name}: {metadata_rows:,} rows, "
        f"{parquet_file.stat().st_size:,} bytes, "
        f"elapsed {format_duration(time.perf_counter() - started)}",
        flush=True,
    )
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Stream one verified NVD yearly feed into PRIORIS Parquet datasets."
    )
    parser.add_argument("--year", type=int, default=DEFAULT_YEAR, help="NVD feed year (default: 2026)")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--chunk-records", type=int, default=DEFAULT_CHUNK_RECORDS)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_ARROW_BATCH_SIZE)
    parser.add_argument("--master", default="local[2]", help="Spark master (default: local[2])")
    args = parser.parse_args()

    if args.year < 2002 or args.year > 2026:
        parser.error("--year must be between 2002 and 2026")
    if args.chunk_records < 100 or args.batch_size < 100:
        parser.error("--chunk-records and --batch-size must be at least 100")

    zip_path = args.data_dir / f"nvdcve-2.0-{args.year}.json.zip"
    meta_path = args.data_dir / f"nvdcve-2.0-{args.year}.meta"
    final_output = args.output_root / f"year={args.year}"

    if not zip_path.is_file() or not meta_path.is_file():
        raise FileNotFoundError(f"Missing NVD feed ZIP or META for year {args.year}: {args.data_dir}")
    if final_output.exists():
        raise FileExistsError(
            f"Output already exists: {final_output}. Choose a new output root; existing output is never overwritten."
        )

    args.output_root.mkdir(parents=True, exist_ok=True)
    meta = parse_meta(meta_path)
    expected_zip_bytes = int(meta["zipSize"])
    actual_zip_bytes = zip_path.stat().st_size
    if actual_zip_bytes != expected_zip_bytes:
        raise ValueError(
            f"ZIP size mismatch: META={expected_zip_bytes}, actual={actual_zip_bytes}"
        )

    print("\n========== PRIORIS HISTORICAL NVD INGESTION ==========")
    print(f"Year: {args.year}")
    print(f"Source ZIP: {zip_path}")
    print(f"META last modified: {meta.get('lastModifiedDate', 'not supplied')}")
    print(f"Expected uncompressed JSON: {int(meta['size']):,} bytes")
    print(f"Output: {final_output}")
    print(f"Spark master: {args.master}")
    print("Existing source files and existing processed snapshots will not be modified.")

    total_started = time.perf_counter()
    workspace_name = tempfile.mkdtemp(prefix=f".prioris-nvd-{args.year}-", dir=args.output_root)
    workspace = Path(workspace_name)
    staging_root = workspace / "jsonl_staging"
    parquet_temp_root = workspace / "parquet_output"
    staging_root.mkdir(parents=True)
    parquet_temp_root.mkdir(parents=True)
    spark = None

    try:
        print("\n[1/5] Preflight passed: ZIP and META files found; ZIP byte size matches.")
        print("\n[2/5] Streaming extraction and source SHA-256 verification starts.")
        table_counts, extraction = extract_records(
            zip_path=zip_path,
            meta=meta,
            year=args.year,
            staging_root=staging_root,
            chunk_records=args.chunk_records,
        )
        print(
            f"\nExtraction verified: {extraction['cve_records_with_id']:,} CVEs; "
            f"JSON SHA-256 {extraction['uncompressed_json_sha256']}"
        )

        print("\n[3/5] Starting PySpark transformations and bounded Arrow/Parquet export.")
        python_executable = sys.executable
        if not Path(python_executable).is_file():
            raise FileNotFoundError(
                f"Python interpreter does not exist: {python_executable}"
            )
        os.environ["PYSPARK_PYTHON"] = python_executable
        os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable
        from pyspark.sql import SparkSession

        spark = (
            SparkSession.builder
            .appName(f"PRIORIS-NVD-Historical-{args.year}")
            .master(args.master)
            .config("spark.pyspark.python", python_executable)
            .config("spark.pyspark.driver.python", python_executable)
            .config("spark.sql.shuffle.partitions", "4")
            .config("spark.sql.session.timeZone", "UTC")
            .getOrCreate()
        )
        spark.sparkContext.setLogLevel("ERROR")
        spark_version = spark.version
        exported_counts: dict[str, int] = {}
        table_names = list(TABLE_FIELDS)
        table_started = time.perf_counter()

        for index, table_name in enumerate(table_names, start=1):
            expected_rows = table_counts[table_name]
            print(
                f"\n[3/5] Dataset {index}/{len(table_names)}: {table_name} "
                f"({expected_rows:,} rows extracted)",
                flush=True,
            )
            exported_counts[table_name] = export_table_with_spark_arrow(
                spark=spark,
                table_name=table_name,
                jsonl_dir=staging_root / table_name,
                parquet_root=parquet_temp_root,
                expected_rows=expected_rows,
                batch_size=args.batch_size,
            )

        spark.stop()
        spark = None
        print(
            f"\nSpark dataset export finished in {format_duration(time.perf_counter() - table_started)}."
        )

        print("\n[4/5] Checking Parquet metadata and total row reconciliation.")
        for table_name, expected_rows in table_counts.items():
            actual_rows = exported_counts.get(table_name, 0)
            if actual_rows != expected_rows:
                raise RuntimeError(
                    f"Final reconciliation failed for {table_name}: {expected_rows} != {actual_rows}"
                )
        total_cves = extraction["cve_records_with_id"]
        core_rows = exported_counts.get("cve_core", 0)
        if core_rows != total_cves:
            raise RuntimeError(f"CVE core count mismatch: extracted {total_cves}, exported {core_rows}")

        manifest = {
            "project": "PRIORIS",
            "dataset": "NVD CVE historical yearly feed",
            "source_year": args.year,
            "processed_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": {
                "zip_file": zip_path.name,
                "meta_file": meta_path.name,
                "last_modified_date": meta.get("lastModifiedDate"),
                "expected_zip_bytes": int(meta["zipSize"]),
                "actual_zip_bytes": extraction["zip_bytes"],
                "expected_uncompressed_json_bytes": int(meta["size"]),
                "actual_uncompressed_json_bytes": extraction["uncompressed_json_bytes"],
                "expected_uncompressed_json_sha256": meta["sha256"].lower(),
                "actual_uncompressed_json_sha256": extraction["uncompressed_json_sha256"],
                "source_checksum_verified": True,
            },
            "extraction": {
                "json_member": extraction["json_member"],
                "vulnerability_items_seen": extraction["vulnerability_items_seen"],
                "cve_records_with_id": extraction["cve_records_with_id"],
                "records_without_cve_object": extraction["records_without_cve_object"],
                "records_without_cve_id": extraction["records_without_cve_id"],
            },
            "parquet_tables": exported_counts,
            "processing": {
                "python_version": sys.version.split()[0],
                "ijson_version": getattr(ijson, "__version__", "unknown"),
                "ijson_backend": getattr(ijson, "backend", "unknown"),
                "pyarrow_version": pa.__version__,
                "spark_version": spark_version,
                "spark_master": args.master,
                "jsonl_chunk_records": args.chunk_records,
                "arrow_batch_size": args.batch_size,
                "parquet_compression": "zstd",
            },
            "limitations": [
                "local[2] is local parallel execution, not multi-machine distributed execution.",
                "CPE configuration relationships are preserved; this ingestion job does not decide enterprise applicability.",
                "CVSS selection in cve_core is a convenience summary; all metric entries are retained in cve_metrics and raw_cve_json.",
            ],
        }
        manifest_path = parquet_temp_root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        print("\n[5/5] Publishing completed output directory.")
        final_output.parent.mkdir(parents=True, exist_ok=True)
        if final_output.exists():
            raise FileExistsError(f"Output appeared during processing; refusing to overwrite: {final_output}")
        os.replace(parquet_temp_root, final_output)

        elapsed = time.perf_counter() - total_started
        print("\n========== INGESTION COMPLETE ==========")
        print(f"Year: {args.year}")
        print(f"CVE records: {total_cves:,}")
        print(f"Parquet datasets: {sum(1 for value in exported_counts.values() if value > 0)}")
        for name, count in exported_counts.items():
            print(f"  {name}: {count:,}")
        print(f"Manifest: {final_output / 'manifest.json'}")
        print(f"Output directory: {final_output}")
        print(f"Elapsed: {format_duration(elapsed)}")
        print("SUCCESS: source checksum and Parquet row counts verified.")
        return 0

    finally:
        if spark is not None:
            spark.stop()
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Temporary staging will be cleaned; source archives remain unchanged.", file=sys.stderr)
        raise SystemExit(130)
