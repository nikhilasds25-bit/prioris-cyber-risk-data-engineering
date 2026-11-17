
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

DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "nvdcpematch-2.0.zip"
DEFAULT_OUTPUT = ROOT / "data" / "processed"
TEMP_DIR = ROOT / "data" / "temp"
LOG_DIR = ROOT / "logs"

BATCH_SIZE = 5000

CRITERIA_SCHEMA = pa.schema([
    ("matchCriteriaId", pa.string()),
    ("criteria", pa.string()),
    ("status", pa.string()),
    ("created", pa.string()),
    ("lastModified", pa.string()),
    ("cpeLastModified", pa.string()),
    ("versionStartIncluding", pa.string()),
    ("versionStartExcluding", pa.string()),
    ("versionEndIncluding", pa.string()),
    ("versionEndExcluding", pa.string()),
])

NAMES_SCHEMA = pa.schema([
    ("matchCriteriaId", pa.string()),
    ("cpeName", pa.string()),
    ("cpeNameId", pa.string()),
])


def get_string(value, field):
    """Validate scalar values and convert them to strings."""
    if value is None:
        return None

    if not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"Invalid value for {field}")

    return str(value)


def write_batch(batch, writer, schema, output_path):
    """Write a batch and return the writer and number of rows written."""

    if not batch:
        return writer, 0

    table = pa.Table.from_pylist(batch, schema=schema)
    row_count = table.num_rows

    if writer is None:
        writer = pq.ParquetWriter(
            str(output_path),
            schema,
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

    criteria_final = (
        output_dir / f"cpe_match_criteria{suffix}.parquet"
    )
    names_final = (
        output_dir / f"cpe_match_names{suffix}.parquet"
    )

    criteria_temp = Path(str(criteria_final) + ".partial")
    names_temp = Path(str(names_final) + ".partial")

    database_path = (
        TEMP_DIR / f"cpe_match_seen_ids{suffix}.sqlite"
    )

    log_path = LOG_DIR / "cpe_match_processing.log"

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

    # Remove leftovers from a previous failed run.
    for path in [
        criteria_temp,
        names_temp,
        database_path,
        Path(str(database_path) + "-journal"),
    ]:
        if path.exists():
            path.unlink()

    criteria_writer = None
    names_writer = None
    db = None

    criteria_batch = []
    names_batch = []

    total_criteria = 0
    total_names = 0
    criteria_rows_written = 0
    names_rows_written = 0

    criteria_without_matches = 0
    missing_matches_field = 0
    null_matches_field = 0
    duplicate_criteria = 0
    chunks_processed = 0

    # cpeLastModified is intentionally optional.
    # Its column remains in CRITERIA_SCHEMA and receives null
    # when it is absent from a source record.
    required_fields = [
        "matchCriteriaId",
        "criteria",
        "created",
        "lastModified",
        "status",
    ]

    success = False
    members = []

    try:

        # Use an explicitly managed SQLite connection.
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

            # Verify numbered chunks are consecutive.
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
                        "matchStrings.item",
                    )

                    for wrapper in records:

                        if not isinstance(wrapper, dict):
                            raise ValueError(
                                f"Invalid record wrapper in {member}"
                            )

                        record = wrapper.get("matchString")

                        if not isinstance(record, dict):
                            raise ValueError(
                                f"Invalid matchString in {member}"
                            )

                        for field in required_fields:

                            if record.get(field) is None:
                                raise ValueError(
                                    f"Missing required field {field} "
                                    f"in {member}"
                                )

                        criteria_id = get_string(
                            record["matchCriteriaId"],
                            "matchCriteriaId",
                        )

                        # Detect duplicate criteria IDs on disk.
                        try:

                            db.execute(
                                "INSERT INTO seen_ids VALUES (?)",
                                (criteria_id,),
                            )

                        except sqlite3.IntegrityError:

                            duplicate_criteria += 1

                            raise ValueError(
                                f"Duplicate criteria ID: {criteria_id}"
                            )

                        criteria_row = {
                            field: get_string(
                                record.get(field),
                                field,
                            )
                            for field in CRITERIA_SCHEMA.names
                        }

                        criteria_batch.append(criteria_row)
                        total_criteria += 1

                        # Preserve criteria even when matches are absent.
                        if "matches" not in record:

                            missing_matches_field += 1
                            matches = []

                        elif record["matches"] is None:

                            null_matches_field += 1
                            matches = []

                        else:
                            matches = record["matches"]

                        if not isinstance(matches, list):
                            raise ValueError(
                                f"Invalid matches array in {member}"
                            )

                        if not matches:
                            criteria_without_matches += 1

                        for item in matches:

                            if not isinstance(item, dict):
                                raise ValueError(
                                    "Invalid CPE match entry"
                                )

                            cpe_name = get_string(
                                item.get("cpeName"),
                                "cpeName",
                            )

                            cpe_id = get_string(
                                item.get("cpeNameId"),
                                "cpeNameId",
                            )

                            if not cpe_name or not cpe_id:
                                raise ValueError(
                                    "Missing CPE name or CPE ID"
                                )

                            names_batch.append({
                                "matchCriteriaId": criteria_id,
                                "cpeName": cpe_name,
                                "cpeNameId": cpe_id,
                            })

                            total_names += 1

                        # Write criteria in bounded batches.
                        if len(criteria_batch) >= BATCH_SIZE:

                            criteria_writer, written = write_batch(
                                criteria_batch,
                                criteria_writer,
                                CRITERIA_SCHEMA,
                                criteria_temp,
                            )

                            criteria_rows_written += written

                        # Write associations in bounded batches.
                        if len(names_batch) >= BATCH_SIZE:

                            names_writer, written = write_batch(
                                names_batch,
                                names_writer,
                                NAMES_SCHEMA,
                                names_temp,
                            )

                            names_rows_written += written

                        if (
                            limit is not None
                            and total_criteria >= limit
                        ):
                            break

                chunks_processed += 1

                if (
                    limit is not None
                    and total_criteria >= limit
                ):
                    break

        # Write any remaining rows.
        criteria_writer, written = write_batch(
            criteria_batch,
            criteria_writer,
            CRITERIA_SCHEMA,
            criteria_temp,
        )

        criteria_rows_written += written

        names_writer, written = write_batch(
            names_batch,
            names_writer,
            NAMES_SCHEMA,
            names_temp,
        )

        names_rows_written += written

        # Create valid empty Parquet outputs if necessary.
        if criteria_writer is None:
            pq.write_table(
                pa.Table.from_pylist([], schema=CRITERIA_SCHEMA),
                criteria_temp,
                compression="snappy",
            )

        if names_writer is None:
            pq.write_table(
                pa.Table.from_pylist([], schema=NAMES_SCHEMA),
                names_temp,
                compression="snappy",
            )

        # Close Parquet writers before reading or renaming files.
        close_writer(criteria_writer)
        criteria_writer = None

        close_writer(names_writer)
        names_writer = None

        # Close SQLite before deleting its database file.
        db.commit()
        db.close()
        db = None

        # Verify actual Parquet row counts.
        criteria_actual = pq.read_metadata(
            str(criteria_temp)
        ).num_rows

        names_actual = pq.read_metadata(
            str(names_temp)
        ).num_rows

        if criteria_actual != total_criteria:
            raise RuntimeError(
                f"Criteria row count mismatch: "
                f"expected {total_criteria}, "
                f"written {criteria_rows_written}, "
                f"found {criteria_actual}"
            )

        if criteria_rows_written != total_criteria:
            raise RuntimeError(
                f"Criteria batch count mismatch: "
                f"expected {total_criteria}, "
                f"written {criteria_rows_written}"
            )

        if names_actual != total_names:
            raise RuntimeError(
                f"Names row count mismatch: "
                f"expected {total_names}, "
                f"written {names_rows_written}, "
                f"found {names_actual}"
            )

        if names_rows_written != total_names:
            raise RuntimeError(
                f"Names batch count mismatch: "
                f"expected {total_names}, "
                f"written {names_rows_written}"
            )

        # Publish files only after validation.
        criteria_temp.replace(criteria_final)
        names_temp.replace(names_final)

        success = True

    finally:

        close_writer(criteria_writer)
        close_writer(names_writer)

        if db is not None:
            db.close()

        if not success:

            for path in [criteria_temp, names_temp]:

                if path.exists():
                    try:
                        path.unlink()
                    except PermissionError:
                        logging.error(
                            "Could not remove temporary file: %s",
                            path,
                        )

        if database_path.exists():
            try:
                database_path.unlink()
            except PermissionError:
                logging.warning(
                    "Could not remove SQLite database: %s",
                    database_path,
                )

    summary = {
        "status": "SUCCESS",
        "archive": str(archive_path),
        "chunks_processed": chunks_processed,
        "criteria_records": total_criteria,
        "criteria_rows_written": criteria_rows_written,
        "cpe_name_associations": total_names,
        "names_rows_written": names_rows_written,
        "criteria_without_matches": criteria_without_matches,
        "missing_matches_field": missing_matches_field,
        "null_matches_field": null_matches_field,
        "duplicate_criteria": duplicate_criteria,
        "criteria_output": str(criteria_final),
        "names_output": str(names_final),
        "completed_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    summary_path = (
        output_dir / f"cpe_match_summary{suffix}.json"
    )

    summary_path.write_text(
        json.dumps(summary, indent=4),
        encoding="utf-8",
    )

    print("\nPROCESSING SUMMARY")
    print(json.dumps(summary, indent=4))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Process NVD CPE Match 2.0 into Parquet"
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
