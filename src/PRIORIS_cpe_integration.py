#!/usr/bin/env python3
"""Join NVD CPE match terms to the processed CPE Match and Dictionary data."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from pyspark.sql import DataFrame, SparkSession, functions as F

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CPE_DICTIONARY = ROOT / "data" / "processed" / "cpe_dictionary.parquet"
DEFAULT_CPE_MATCH_CRITERIA = ROOT / "data" / "processed" / "cpe_match_criteria.parquet"
DEFAULT_CPE_MATCH_NAMES = ROOT / "data" / "processed" / "cpe_match_names.parquet"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "processed" / "cpe_integration"

NVD_REQUIRED_COLUMNS = {
    "cve_id",
    "source_year",
    "configuration_index",
    "node_path",
    "match_index",
    "match_criteria_id",
    "criteria",
    "vulnerable",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
}
NVD_OUTPUT_COLUMNS = (
    "cve_id",
    "source_year",
    "configuration_index",
    "node_path",
    "match_index",
    "match_criteria_id",
    "criteria",
    "vulnerable",
    "version_start_including",
    "version_start_excluding",
    "version_end_including",
    "version_end_excluding",
    "status",
    "raw_match_json",
)
CRITERIA_REQUIRED_COLUMNS = {
    "matchCriteriaId",
    "criteria",
    "status",
    "created",
    "lastModified",
    "cpeLastModified",
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
}
NAMES_REQUIRED_COLUMNS = {"matchCriteriaId", "cpeName", "cpeNameId"}
DICTIONARY_REQUIRED_COLUMNS = {"cpeName", "cpeNameId"}
DICTIONARY_OPTIONAL_COLUMNS = {
    "deprecated",
    "created",
    "lastModified",
    "titles",
    "deprecatedBy",
    "deprecates",
}


def discover_nvd_matches(root: Path = ROOT) -> Path | None:
    """Prefer a published yearly dataset, otherwise use the newest staging output."""
    historical_root = root / "data" / "processed" / "nvd_historical"
    published = sorted(
        path
        for path in historical_root.glob("year=*/cve_cpe_matches")
        if path.is_dir()
    )
    if published:
        return published[-1]

    staged = [
        path
        for path in historical_root.glob(
            ".prioris-nvd-*/parquet_output/cve_cpe_matches"
        )
        if path.is_dir()
    ]
    if staged:
        return max(staged, key=lambda path: path.stat().st_mtime)
    return None


def _require_columns(dataframe: DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(dataframe.columns))
    if missing:
        raise ValueError(f"{label} is missing required columns: {', '.join(missing)}")


def build_integrated_dataframes(
    nvd_matches: DataFrame,
    cpe_match_criteria: DataFrame,
    cpe_match_names: DataFrame,
    cpe_dictionary: DataFrame,
) -> tuple[DataFrame, DataFrame]:
    """Return one enriched row per NVD term and its resolved name associations."""
    _require_columns(nvd_matches, NVD_REQUIRED_COLUMNS, "NVD cve_cpe_matches")
    _require_columns(cpe_match_criteria, CRITERIA_REQUIRED_COLUMNS, "CPE Match Criteria")
    _require_columns(cpe_match_names, NAMES_REQUIRED_COLUMNS, "CPE Match Names")
    _require_columns(cpe_dictionary, DICTIONARY_REQUIRED_COLUMNS, "CPE Dictionary")

    criteria_columns = [
        F.col("matchCriteriaId").alias("cpe_match_matchCriteriaId"),
        F.col("criteria").alias("cpe_match_criteria"),
        F.col("status").alias("cpe_match_status"),
        F.col("created").alias("cpe_match_created"),
        F.col("lastModified").alias("cpe_match_last_modified"),
        F.col("cpeLastModified").alias("cpe_match_cpe_last_modified"),
        F.col("versionStartIncluding").alias("criteria_version_start_including"),
        F.col("versionStartExcluding").alias("criteria_version_start_excluding"),
        F.col("versionEndIncluding").alias("criteria_version_end_including"),
        F.col("versionEndExcluding").alias("criteria_version_end_excluding"),
    ]
    criteria = cpe_match_criteria.select(*criteria_columns)

    nvd = nvd_matches.alias("nvd")
    criteria = criteria.alias("criteria")
    terms = nvd.join(
        criteria,
        F.col("nvd.match_criteria_id") == F.col("criteria.cpe_match_matchCriteriaId"),
        "left",
    ).select(
        *[F.col(f"nvd.{column}") for column in nvd_matches.columns],
        *[
            F.col(f"criteria.{column}")
            for column in (
                "cpe_match_matchCriteriaId",
                "cpe_match_criteria",
                "cpe_match_status",
                "cpe_match_created",
                "cpe_match_last_modified",
                "cpe_match_cpe_last_modified",
                "criteria_version_start_including",
                "criteria_version_start_excluding",
                "criteria_version_end_including",
                "criteria_version_end_excluding",
            )
        ],
    )

    names = cpe_match_names.select(
        F.col("matchCriteriaId").alias("_names_matchCriteriaId"),
        F.col("cpeNameId").alias("cpeNameId"),
        F.col("cpeName").alias("cpe_match_names_cpeName"),
    ).alias("names")
    terms_for_names = terms.alias("terms")
    with_names = terms_for_names.join(
        names,
        F.col("terms.cpe_match_matchCriteriaId")
        == F.col("names._names_matchCriteriaId"),
        "inner",
    )

    dictionary_fields = [
        F.col("cpeNameId").alias("_dictionary_cpeNameId"),
        F.col("cpeName").alias("cpeName"),
    ]
    dictionary_aliases = {
        "deprecated": "deprecated",
        "created": "dictionary_created",
        "lastModified": "dictionary_last_modified",
        "titles": "titles",
        "deprecatedBy": "deprecatedBy",
        "deprecates": "deprecates",
    }
    selected_dictionary_aliases = ["cpeName"] + [
        alias
        for source, alias in dictionary_aliases.items()
        if source in cpe_dictionary.columns
    ]
    dictionary_fields.extend(
        F.col(source).alias(alias)
        for source, alias in dictionary_aliases.items()
        if source in cpe_dictionary.columns
    )
    dictionary = cpe_dictionary.select(*dictionary_fields).alias("dictionary")

    return terms, with_names.join(
        dictionary,
        F.col("names.cpeNameId") == F.col("dictionary._dictionary_cpeNameId"),
        "left",
    ).select(
        *[F.col(f"terms.{column}") for column in terms.columns],
        F.col("names.cpeNameId").alias("cpeNameId"),
        F.col("names.cpe_match_names_cpeName").alias("cpe_match_names_cpeName"),
        *[
            F.col(f"dictionary.{alias}")
            for alias in selected_dictionary_aliases
        ],
        F.col("dictionary._dictionary_cpeNameId")
        .isNotNull()
        .alias("dictionary_resolved"),
    )


def _validate_unique_key(dataframe: DataFrame, key: str, label: str) -> None:
    if dataframe.where(F.col(key).isNull()).limit(1).count():
        raise ValueError(f"{label} contains null values in key {key}")
    if (
        dataframe.groupBy(key)
        .count()
        .where(F.col("count") > 1)
        .limit(1)
        .count()
    ):
        raise ValueError(f"{label} contains duplicate values in key {key}")


def _parquet_row_count(output_path: Path) -> int:
    import pyarrow.parquet as pq

    return sum(
        pq.ParquetFile(path).metadata.num_rows
        for path in output_path.rglob("*.parquet")
    )


def _arrow_type_for_spark(data_type: Any) -> Any:
    import pyarrow as pa
    from pyspark.sql import types as spark_types

    if isinstance(data_type, spark_types.StringType):
        return pa.string()
    if isinstance(data_type, spark_types.BooleanType):
        return pa.bool_()
    if isinstance(
        data_type,
        (spark_types.ByteType, spark_types.ShortType, spark_types.IntegerType),
    ):
        return pa.int32()
    if isinstance(data_type, spark_types.LongType):
        return pa.int64()
    if isinstance(data_type, spark_types.FloatType):
        return pa.float32()
    if isinstance(data_type, spark_types.DoubleType):
        return pa.float64()
    if isinstance(data_type, spark_types.BinaryType):
        return pa.binary()
    if isinstance(data_type, spark_types.DateType):
        return pa.date32()
    if isinstance(data_type, spark_types.TimestampType):
        return pa.timestamp("us")
    if isinstance(data_type, spark_types.DecimalType):
        return pa.decimal128(data_type.precision, data_type.scale)
    if isinstance(data_type, spark_types.ArrayType):
        return pa.list_(_arrow_type_for_spark(data_type.elementType))
    if isinstance(data_type, spark_types.StructType):
        return pa.struct([
            pa.field(field.name, _arrow_type_for_spark(field.dataType), field.nullable)
            for field in data_type.fields
        ])
    if isinstance(data_type, spark_types.MapType):
        return pa.map_(
            _arrow_type_for_spark(data_type.keyType),
            _arrow_type_for_spark(data_type.valueType),
        )
    raise TypeError(f"Unsupported Spark output type: {data_type}")


def _write_dataframe_bounded(
    dataframe: DataFrame,
    output_dir: Path,
    expected_rows: int,
    *,
    partitions: int,
    batch_size: int = 5_000,
) -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq

    output_dir.mkdir(parents=True, exist_ok=False)
    arrow_schema = pa.schema([
        pa.field(
            field.name,
            _arrow_type_for_spark(field.dataType),
            field.nullable,
        )
        for field in dataframe.schema.fields
    ])
    schema_payload = arrow_schema.serialize().to_pybytes()
    output_path = str(output_dir)

    def write_partition(
        partition_index: int,
        rows: Any,
    ) -> Any:
        import pyarrow as partition_pa
        import pyarrow.parquet as partition_pq

        schema = partition_pa.ipc.read_schema(
            partition_pa.BufferReader(schema_payload)
        )
        output_file = Path(output_path) / f"part-{partition_index:05d}.parquet"
        writer = partition_pq.ParquetWriter(
            output_file,
            schema,
            compression="snappy",
            use_dictionary=True,
        )
        written = 0
        batch: list[dict[str, Any]] = []

        def flush_partition_batch() -> None:
            nonlocal written, batch
            if not batch:
                return
            table = partition_pa.Table.from_pylist(batch, schema=schema)
            writer.write_table(table, row_group_size=batch_size)
            written += len(batch)
            batch = []

        try:
            for row in rows:
                batch.append(row.asDict(recursive=True))
                if len(batch) >= batch_size:
                    flush_partition_batch()
            flush_partition_batch()
        finally:
            writer.close()
        yield written

    print(
        f"Streaming {expected_rows:,} rows from {partitions} Spark partitions "
        f"in PyArrow batches of {batch_size:,}.",
        flush=True,
    )
    written = (
        dataframe.repartition(partitions)
        .rdd.mapPartitionsWithIndex(write_partition)
        .sum()
    )
    if written != expected_rows:
        raise RuntimeError(
            f"Parquet output row-count mismatch at {output_dir}: "
            f"expected {expected_rows:,}, wrote {written:,}"
        )
    return written


def _format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _announce_progress(
    stage: str,
    completed_stages: int,
    total_stages: int,
    started: float,
    stage_durations: list[float],
) -> None:
    elapsed = time.perf_counter() - started
    if stage_durations:
        average = sum(stage_durations) / len(stage_durations)
        eta = _format_duration(average * (total_stages - completed_stages))
        eta_text = f"approximate ETA {eta}"
    else:
        eta_text = "ETA calculating"
    print(
        f"[{completed_stages + 1}/{total_stages}] {stage}; "
        f"elapsed {_format_duration(elapsed)}; {eta_text}",
        flush=True,
    )


def _run_stage(
    label: str,
    operation: Any,
    started: float,
    completed_stages: int,
    total_stages: int,
    stage_durations: list[float],
) -> tuple[Any, float]:
    _announce_progress(
        label,
        completed_stages,
        total_stages,
        started,
        stage_durations,
    )
    stage_started = time.perf_counter()
    result = operation()
    duration = time.perf_counter() - stage_started
    stage_durations.append(duration)
    print(
        f"Completed {label}; elapsed {_format_duration(time.perf_counter() - started)}; "
        f"stage duration {_format_duration(duration)}",
        flush=True,
    )
    return result, duration


def run_integration(
    nvd_matches_path: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> tuple[int, int]:
    """Integrate the datasets and atomically publish both outputs without overwrite."""
    input_paths = {
        "NVD matches": nvd_matches_path,
        "CPE Match Criteria": DEFAULT_CPE_MATCH_CRITERIA,
        "CPE Match Names": DEFAULT_CPE_MATCH_NAMES,
        "CPE Dictionary": DEFAULT_CPE_DICTIONARY,
    }
    for label, path in input_paths.items():
        if not path.exists():
            raise FileNotFoundError(f"{label} input does not exist: {path}")
    if output_dir.exists():
        raise FileExistsError(
            f"Output already exists; refusing to overwrite: {output_dir}"
        )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(
            prefix=".prioris-cpe-integration-",
            dir=output_dir.parent,
        )
    )
    python_executable = sys.executable
    if not Path(python_executable).is_file():
        raise FileNotFoundError(f"Python interpreter does not exist: {python_executable}")
    os.environ["PYSPARK_PYTHON"] = python_executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable

    spark: SparkSession | None = (
        SparkSession.builder.appName("PRIORIS-NVD-CPE-Integration")
        .master("local[2]")
        .config("spark.pyspark.python", python_executable)
        .config("spark.pyspark.driver.python", python_executable)
        .config("spark.sql.shuffle.partitions", "16")
        .config("spark.sql.files.maxPartitionBytes", str(64 * 1024 * 1024))
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.autoBroadcastJoinThreshold", "-1")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    started = time.perf_counter()
    stage_durations: list[float] = []
    completed_stages = 0
    total_stages = 7
    published = False
    try:
        print(f"Spark master: local[2]; Spark version: {spark.version}", flush=True)
        print(f"NVD match input: {nvd_matches_path}", flush=True)
        print(f"Temporary output staging directory: {staging_dir}", flush=True)
        print(
            "Automatic broadcast joins disabled; adaptive execution enabled; "
            "shuffle partitions=16; file partition target=64 MiB.",
            flush=True,
        )

        def read_nvd_matches() -> DataFrame:
            source = spark.read.parquet(str(nvd_matches_path))
            return source.select(
                *[
                    column
                    for column in NVD_OUTPUT_COLUMNS
                    if column in source.columns
                ]
            )

        nvd, _ = _run_stage(
            "reading NVD CPE match terms",
            read_nvd_matches,
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        nvd_count, _ = _run_stage(
            "counting NVD CPE match terms",
            nvd.count,
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        print(f"Input NVD CPE match terms: {nvd_count:,}", flush=True)

        criteria = spark.read.parquet(str(DEFAULT_CPE_MATCH_CRITERIA)).select(
            *sorted(CRITERIA_REQUIRED_COLUMNS)
        )
        names = spark.read.parquet(str(DEFAULT_CPE_MATCH_NAMES)).select(
            *sorted(NAMES_REQUIRED_COLUMNS)
        )
        dictionary_source = spark.read.parquet(str(DEFAULT_CPE_DICTIONARY))
        dictionary_columns = sorted(
            DICTIONARY_REQUIRED_COLUMNS
            | (DICTIONARY_OPTIONAL_COLUMNS & set(dictionary_source.columns))
        )
        dictionary = dictionary_source.select(*dictionary_columns)
        _, _ = _run_stage(
            "validating CPE dimension keys",
            lambda: (
                _validate_unique_key(
                    criteria.select("matchCriteriaId"),
                    "matchCriteriaId",
                    "CPE Match Criteria",
                ),
                _validate_unique_key(
                    dictionary.select("cpeNameId"),
                    "cpeNameId",
                    "CPE Dictionary",
                ),
            ),
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        terms, associations = build_integrated_dataframes(
            nvd, criteria, names, dictionary
        )

        identity_columns = [
            "source_year",
            "cve_id",
            "configuration_index",
            "node_path",
            "match_index",
        ]
        criteria_counts, _ = _run_stage(
            "counting resolved criteria and product associations",
            lambda: (
                terms.agg(
                    F.count(F.lit(1)).alias("term_rows"),
                    F.sum(
                        F.when(
                            F.col("cpe_match_matchCriteriaId").isNotNull(), 1
                        ).otherwise(0)
                    ).alias("resolved_term_rows"),
                    F.countDistinct(
                        F.when(
                            F.col("cpe_match_matchCriteriaId").isNotNull(),
                            F.col("cpe_match_matchCriteriaId"),
                        )
                    ).alias("resolved_criteria_ids"),
                ).first(),
                associations.count(),
            ),
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        counts_row, association_count = criteria_counts
        completed_stages += 1
        print(
            f"Resolved criteria: {counts_row['resolved_term_rows']:,} NVD terms, "
            f"{counts_row['resolved_criteria_ids']:,} distinct criteria IDs; "
            f"terms with metadata unresolved: "
            f"{nvd_count - counts_row['resolved_term_rows']:,}; "
            f"product associations: {association_count:,}.",
            flush=True,
        )

        association_term_keys = associations.select(*identity_columns).distinct()
        terms_without_associations, _ = _run_stage(
            "counting terms without CPE name associations",
            lambda: (
                terms.select(*identity_columns)
                .join(association_term_keys, identity_columns, "left_anti")
                .count()
            ),
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        print(
            f"Terms without CPE name associations: "
            f"{terms_without_associations:,}.",
            flush=True,
        )

        terms_dir = staging_dir / "cve_cpe_terms"
        term_output_count, _ = _run_stage(
            "writing cve_cpe_terms",
            lambda: _write_dataframe_bounded(
                terms,
                terms_dir,
                nvd_count,
                partitions=16,
            ),
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        print(
            f"Processed cve_cpe_terms: {term_output_count:,} rows "
            f"(input terms: {nvd_count:,}).",
            flush=True,
        )

        associations_dir = staging_dir / "cve_cpe_product_associations"
        association_output_count, _ = _run_stage(
            "writing cve_cpe_product_associations",
            lambda: _write_dataframe_bounded(
                associations,
                associations_dir,
                association_count,
                partitions=64,
            ),
            started,
            completed_stages,
            total_stages,
            stage_durations,
        )
        completed_stages += 1
        print(
            "Processed cve_cpe_product_associations: "
            f"{association_output_count:,} rows.",
            flush=True,
        )

        if term_output_count != nvd_count:
            raise RuntimeError(
                "Term output row count differs from the NVD input: "
                f"{term_output_count:,} != {nvd_count:,}. "
                "The criteria key may not be unique."
            )
        spark.stop()
        spark = None
        os.rename(staging_dir, output_dir)
        published = True
        print(
            f"Published outputs to {output_dir}; total elapsed "
            f"{_format_duration(time.perf_counter() - started)}.",
            flush=True,
        )
        return term_output_count, association_output_count
    finally:
        if spark is not None:
            spark.stop()
        if not published and staging_dir.exists():
            shutil.rmtree(staging_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Join NVD CPE match terms to the processed CPE datasets."
    )
    parser.add_argument(
        "--nvd-matches",
        type=Path,
        help="NVD cve_cpe_matches Parquet file or directory; discovered automatically when omitted.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"New output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args(argv)

    nvd_matches_path = args.nvd_matches or discover_nvd_matches()
    if nvd_matches_path is None:
        raise FileNotFoundError(
            "No existing cve_cpe_matches Parquet dataset was found. "
            "Supply --nvd-matches; historical ingestion will not be run automatically."
        )
    if not nvd_matches_path.exists():
        raise FileNotFoundError(f"NVD matches input does not exist: {nvd_matches_path}")

    run_integration(nvd_matches_path, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
