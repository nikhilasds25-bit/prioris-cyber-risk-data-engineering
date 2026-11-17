
import argparse
import json
import logging
import re
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import ijson
import pyarrow as pa
import pyarrow.parquet as pq


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "nvdcpe-2.0.zip"
DEFAULT_OUTPUT = ROOT / "data" / "processed"
TEMP_DIR = ROOT / "data" / "temp"
LOG_DIR = ROOT / "logs"

BATCH_SIZE = 5000

TITLE_SCHEMA = pa.list_(
    pa.struct([
        ("title", pa.string()),
        ("lang", pa.string()),
    ])
)

RELATION_SCHEMA = pa.list_(
    pa.struct([
        ("cpeName", pa.string()),
        ("cpeNameId", pa.string()),
    ])
)

REF_SCHEMA = pa.list_(
    pa.struct([
        ("ref", pa.string()),
        ("type", pa.string()),
    ])
)

DICTIONARY_SCHEMA = pa.schema([
    ("cpeName", pa.string()),
    ("cpeNameId", pa.string()),
    ("deprecated", pa.bool_()),
    ("created", pa.string()),
    ("lastModified", pa.string()),
    ("titles", TITLE_SCHEMA),
    ("deprecatedBy", RELATION_SCHEMA),
    ("deprecates", RELATION_SCHEMA),
    ("refs", REF_SCHEMA),
])


def get_string(value, field):
    if value is None:
        return None

    if not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"Invalid value for {field}")

    return str(value)


def clean_titles(items):

    if items is None:
        return []

    if not isinstance(items, list):
        raise ValueError("Expected titles to be a list")

    result = []

    for item in items:

        if not isinstance(item, dict):
            raise ValueError("Invalid title entry")

        result.append({
            "title": get_string(item.get("title"), "title"),
            "lang": get_string(item.get("lang"), "lang"),
        })

    return result


def clean_relations(items):

    if items is None:
        return []

    if not isinstance(items, list):
        raise ValueError("Expected relations to be a list")

    result = []

    for item in items:

        if not isinstance(item, dict):
            raise ValueError("Invalid CPE relation")

        result.append({
            "cpeName": get_string(
                item.get("cpeName"), "relation cpeName"
            ),
            "cpeNameId": get_string(
                item.get("cpeNameId"), "relation cpeNameId"
            ),
        })

    return result


def clean_refs(items):

    if items is None:
        return []

    if not isinstance(items, list):
        raise ValueError("Expected refs to be a list")

    result = []

    for item in items:

        if not isinstance(item, dict):
            raise ValueError("Invalid reference entry")

        result.append({
            "ref": get_string(item.get("ref"), "ref"),
            "type": get_string(item.get("type"), "ref type"),
        })

    return result


def write_batch(batch, writer, output_path):

    if not batch:
        return writer, 0

    table = pa.Table.from_pylist(
        batch,
        schema=DICTIONARY_SCHEMA,
    )

    row_count = table.num_rows

    if writer is None:
        writer = pq.ParquetWriter(
            str(output_path),
            DICTIONARY_SCHEMA,
            compression="snappy",
        )

    writer.write_table(table)
    batch.clear()

    return writer, row_count


def close_writer(writer):

    if writer is not None:
        writer.close()


def process_archive(archive_path, output_dir, limit=None):

    archive_path = Path(archive_path)
    output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    suffix = "_sample" if limit is not None else ""

    output_final = (
        output_dir / f"cpe_dictionary{suffix}.parquet"
    )

    output_temp = Path(str(output_final) + ".partial")

    database_path = (
        TEMP_DIR / f"cpe_dictionary_seen_ids{suffix}.sqlite"
    )

    log_path = LOG_DIR / "cpe_dictionary_processing.log"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
        force=True,
    )

    if not archive_path.exists():
        raise FileNotFoundError(archive_path)

    # Remove temporary files from previous failed runs.
    for path in [
        output_temp,
        database_path,
        Path(str(database_path) + "-journal"),
    ]:
        if path.exists():
            path.unlink()

    writer = None
    db = None
    batch = []

    total_records = 0
    rows_written = 0
    deprecated_records = 0
    records_with_titles = 0
    records_with_refs = 0
    records_with_deprecated_by = 0
    records_with_deprecates = 0
    duplicate_ids = 0
    chunks_processed = 0

    success = False
    members = []

    try:

        # Explicitly manage the SQLite connection.
        db = sqlite3.connect(str(database_path))

        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=NORMAL")

        db.execute(
            "CREATE TABLE seen_ids (id TEXT PRIMARY KEY)"
        )

        db.commit()

        with zipfile.ZipFile(archive_path, "r") as archive:

            bad_member = archive.testzip()

            if bad_member:
                raise RuntimeError(
                    f"Corrupt ZIP member: {bad_member}"
                )

            members = sorted(
                name for name in archive.namelist()
                if name.endswith(".json")
            )

            if not members:
                raise RuntimeError("No JSON chunks found")

            # Confirm that all numbered chunks are present.
            chunk_numbers = []

            for member in members:

                match = re.search(
                    r"chunk-(\d+)\.json$",
                    member,
                )

                if not match:
                    raise RuntimeError(
                        f"Unexpected chunk filename: {member}"
                    )

                chunk_numbers.append(int(match.group(1)))

            expected = list(
                range(1, len(chunk_numbers) + 1)
            )

            if chunk_numbers != expected:
                raise RuntimeError(
                    "Missing or incorrectly numbered chunks"
                )

            logging.info(
                "Found %d consecutive JSON chunks",
                len(members),
            )

            for member in members:

                logging.info("Processing %s", member)

                with archive.open(member) as stream:

                    records = ijson.items(
                        stream,
                        "products.item",
                    )

                    for wrapper in records:

                        if not isinstance(wrapper, dict):
                            raise ValueError(
                                f"Invalid product wrapper in {member}"
                            )

                        record = wrapper.get("cpe")

                        if not isinstance(record, dict):
                            raise ValueError(
                                f"Invalid CPE object in {member}"
                            )

                        cpe_name = get_string(
                            record.get("cpeName"),
                            "cpeName",
                        )

                        cpe_id = get_string(
                            record.get("cpeNameId"),
                            "cpeNameId",
                        )

                        if not cpe_name or not cpe_id:
                            raise ValueError(
                                "Missing CPE name or CPE ID"
                            )

                        # Disk-backed duplicate detection.
                        try:

                            db.execute(
                                "INSERT INTO seen_ids VALUES (?)",
                                (cpe_id,),
                            )

                        except sqlite3.IntegrityError:

                            duplicate_ids += 1

                            raise ValueError(
                                f"Duplicate CPE ID: {cpe_id}"
                            )

                        deprecated = record.get(
                            "deprecated", False
                        )

                        if not isinstance(deprecated, bool):
                            raise ValueError(
                                "Invalid deprecated value"
                            )

                        titles = clean_titles(
                            record.get("titles")
                        )

                        deprecated_by = clean_relations(
                            record.get("deprecatedBy")
                        )

                        deprecates = clean_relations(
                            record.get("deprecates")
                        )

                        refs = clean_refs(
                            record.get("refs")
                        )

                        row = {
                            "cpeName": cpe_name,
                            "cpeNameId": cpe_id,
                            "deprecated": deprecated,
                            "created": get_string(
                                record.get("created"), "created"
                            ),
                            "lastModified": get_string(
                                record.get("lastModified"),
                                "lastModified",
                            ),
                            "titles": titles,
                            "deprecatedBy": deprecated_by,
                            "deprecates": deprecates,
                            "refs": refs,
                        }

                        batch.append(row)
                        total_records += 1

                        if deprecated:
                            deprecated_records += 1

                        if titles:
                            records_with_titles += 1

                        if refs:
                            records_with_refs += 1

                        if deprecated_by:
                            records_with_deprecated_by += 1

                        if deprecates:
                            records_with_deprecates += 1

                        if len(batch) >= BATCH_SIZE:

                            writer, written = write_batch(
                                batch,
                                writer,
                                output_temp,
                            )

                            rows_written += written

                        if (
                            limit is not None
                            and total_records >= limit
                        ):
                            break

                chunks_processed += 1

                if (
                    limit is not None
                    and total_records >= limit
                ):
                    break

        # Write the remaining batch.
        writer, written = write_batch(
            batch,
            writer,
            output_temp,
        )

        rows_written += written

        # Create a valid empty Parquet file if needed.
        if writer is None:
            pq.write_table(
                pa.Table.from_pylist(
                    [],
                    schema=DICTIONARY_SCHEMA,
                ),
                output_temp,
                compression="snappy",
            )

        # Close resources before validation and publishing.
        close_writer(writer)
        writer = None

        db.commit()
        db.close()
        db = None

        actual_rows = pq.read_metadata(
            str(output_temp)
        ).num_rows

        if actual_rows != total_records:
            raise RuntimeError(
                f"Dictionary row count mismatch: "
                f"expected {total_records}, "
                f"written {rows_written}, "
                f"found {actual_rows}"
            )

        if rows_written != total_records:
            raise RuntimeError(
                f"Batch row count mismatch: "
                f"expected {total_records}, "
                f"written {rows_written}"
            )

        # Publish only after validation.
        output_temp.replace(output_final)

        success = True

    finally:

        close_writer(writer)

        if db is not None:
            db.close()

        if not success and output_temp.exists():
            try:
                output_temp.unlink()
            except PermissionError:
                logging.error(
                    "Could not remove temporary output"
                )

        if database_path.exists():
            try:
                database_path.unlink()
            except PermissionError:
                logging.warning(
                    "Could not remove temporary SQLite database"
                )

    summary = {
        "status": "SUCCESS",
        "archive": str(archive_path),
        "chunks_processed": chunks_processed,
        "records_processed": total_records,
        "rows_written": rows_written,
        "deprecated_records": deprecated_records,
        "records_with_titles": records_with_titles,
        "records_with_refs": records_with_refs,
        "records_with_deprecatedBy": records_with_deprecated_by,
        "records_with_deprecates": records_with_deprecates,
        "duplicate_cpe_ids": duplicate_ids,
        "output": str(output_final),
        "completed_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    summary_path = (
        output_dir / f"cpe_dictionary_summary{suffix}.json"
    )

    summary_path.write_text(
        json.dumps(summary, indent=4),
        encoding="utf-8",
    )

    print("\nPROCESSING SUMMARY")
    print(json.dumps(summary, indent=4))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Process NVD CPE Dictionary 2.0 into Parquet"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional record limit for testing",
    )

    args = parser.parse_args()

    process_archive(
        DEFAULT_ARCHIVE,
        DEFAULT_OUTPUT,
        limit=args.limit,
    )
