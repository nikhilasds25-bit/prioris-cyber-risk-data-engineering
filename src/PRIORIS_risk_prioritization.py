#!/usr/bin/env python3
"""Prioritize the local enterprise exposure evidence using PRIORIS scoring rules."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pyspark.sql import DataFrame, SparkSession, functions as F, types as T
from pyspark.sql.window import Window
from pyspark.storagelevel import StorageLevel

from src.PRIORIS_cpe_integration import _write_dataframe_bounded
from src.score_risks import RiskScoringConfig, score_components

DEFAULT_EXPOSURE_DIR = ROOT / "data" / "processed" / "enterprise_exposure" / "enterprise_exposure"
DEFAULT_EXPOSURE_SUMMARY = ROOT / "data" / "processed" / "enterprise_exposure" / "summary.json"
DEFAULT_INVENTORY_DIR = ROOT / "data" / "synthetic"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "processed" / "risk_prioritization"
OUTPUT_PARTITIONS = 8
WRITE_BATCH_SIZE = 2_000
TOP_RANK_LIMIT = 10

EXPOSURE_REQUIRED_COLUMNS = {
    "asset_id",
    "installation_id",
    "software_name",
    "software_product",
    "installed_version",
    "cve_id",
    "vulnerable",
    "cvss_score",
    "known_exploited",
    "kev_date_added",
    "applicability_status",
    "match_evidence",
}
ASSET_REQUIRED_COLUMNS = {
    "asset_id",
    "criticality",
    "exposure",
    "asset_type",
    "business_unit",
    "environment",
}

SCORE_SCHEMA = T.StructType([
    T.StructField("risk_score", T.DoubleType(), True),
    T.StructField("risk_tier", T.StringType(), True),
    T.StructField("missing_score_evidence", T.StringType(), True),
    T.StructField("risk_factor_components", T.StringType(), True),
])


def _parquet_parts(path: Path) -> list[str]:
    if path.is_file():
        return [str(path)]
    if not path.is_dir():
        raise FileNotFoundError(f"Parquet input does not exist: {path}")
    parts = sorted(str(item) for item in path.rglob("*.parquet") if item.is_file())
    if not parts:
        raise FileNotFoundError(f"No Parquet part files found under: {path}")
    return parts


def _read_parquet(spark: SparkSession, path: Path) -> DataFrame:
    return spark.read.parquet(*_parquet_parts(path))


def _require_columns(dataframe: DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(dataframe.columns))
    if missing:
        raise ValueError(f"{label} is missing required columns: {', '.join(missing)}")


def _score_udf(config: RiskScoringConfig):
    @F.udf(returnType=SCORE_SCHEMA)
    def score_one(cvss_score, known_exploited, criticality, exposure):
        result = score_components(
            cvss_score,
            known_exploited,
            criticality,
            exposure,
            config,
        )
        if result["missing_evidence"]:
            return (
                None,
                None,
                json.dumps(result["missing_evidence"], separators=(",", ":")),
                None,
            )
        return (
            float(result["score"]),
            str(result["tier"]),
            "[]",
            json.dumps(result["components"], separators=(",", ":"), sort_keys=True),
        )

    return score_one


def build_scored_exposures(
    exposure_df: DataFrame,
    asset_context_df: DataFrame,
    config: RiskScoringConfig = RiskScoringConfig(),
) -> DataFrame:
    """Apply the existing score_components formula only to confirmed vulnerable rows."""
    config.validate()
    _require_columns(exposure_df, EXPOSURE_REQUIRED_COLUMNS, "Enterprise exposure")
    _require_columns(asset_context_df, ASSET_REQUIRED_COLUMNS, "Enterprise asset context")

    context = asset_context_df.select(
        "asset_id",
        "criticality",
        "exposure",
        "asset_type",
        "business_unit",
        "environment",
    )
    joined = exposure_df.join(context, "asset_id", "left")
    confirmed = (
        (F.col("applicability_status") == "confirmed_match")
        & (F.col("vulnerable") == F.lit(True))
    )
    scored = joined.withColumn(
        "_score_result",
        F.when(
            confirmed,
            _score_udf(config)(
                F.col("cvss_score"),
                F.col("known_exploited"),
                F.col("criticality"),
                F.col("exposure"),
            ),
        ),
    )
    scored = (
        scored
        .withColumn("risk_score", F.col("_score_result.risk_score"))
        .withColumn("risk_tier", F.col("_score_result.risk_tier"))
        .withColumn(
            "missing_score_evidence",
            F.coalesce(F.col("_score_result.missing_score_evidence"), F.lit("[]")),
        )
        .withColumn(
            "risk_factor_components",
            F.col("_score_result.risk_factor_components"),
        )
        .withColumn(
            "risk_factor_evidence",
            F.to_json(F.struct(
                F.col("cvss_score").alias("cvss_score"),
                F.lit("NVD-normalized severity in Phase 3 exposure evidence").alias(
                    "cvss_source"
                ),
                F.col("known_exploited").alias("known_exploited"),
                F.col("kev_date_added").alias("kev_date_added"),
                F.lit("Phase 3 local CISA KEV snapshot").alias("kev_source"),
                F.col("criticality").alias("asset_criticality"),
                F.col("exposure").alias("network_exposure"),
                F.lit("enterprise_assets.csv").alias("asset_context_source"),
            )),
        )
        .withColumn(
            "scoring_status",
            F.when(
                F.col("applicability_status") != "confirmed_match",
                F.lit("not_scored_applicability_unconfirmed"),
            )
            .when(
                F.col("vulnerable") != F.lit(True),
                F.lit("not_scored_term_not_vulnerable"),
            )
            .when(
                F.size(F.from_json(
                    F.col("missing_score_evidence"),
                    T.ArrayType(T.StringType()),
                )) > 0,
                F.lit("withheld_missing_score_evidence"),
            )
            .otherwise(F.lit("scored")),
        )
        .drop("_score_result")
    )
    ranking = Window.orderBy(
        F.col("risk_score").desc_nulls_last(),
        F.col("known_exploited").desc_nulls_last(),
        F.col("cvss_score").cast("double").desc_nulls_last(),
        F.col("asset_id").asc(),
        F.col("cve_id").asc_nulls_last(),
        F.col("installation_id").asc(),
    )
    return scored.withColumn(
        "exposure_priority_rank",
        F.when(F.col("scoring_status") == "scored", F.row_number().over(ranking)),
    )


def build_asset_risk_summary(
    scored_df: DataFrame,
    asset_context_df: DataFrame,
) -> DataFrame:
    scored_relations = scored_df.where(F.col("scoring_status") == "scored")
    asset_top_window = Window.partitionBy("asset_id").orderBy(
        F.col("risk_score").desc(),
        F.col("known_exploited").desc(),
        F.col("cvss_score").cast("double").desc(),
        F.col("cve_id").asc(),
        F.col("installation_id").asc(),
    )
    top_risks = (
        scored_relations
        .withColumn("_asset_top_row", F.row_number().over(asset_top_window))
        .where(F.col("_asset_top_row") == 1)
        .select(
            "asset_id",
            F.col("risk_score").alias("max_risk_score"),
            F.col("risk_tier").alias("top_risk_tier"),
            F.col("cve_id").alias("top_risk_cve_id"),
            F.col("installation_id").alias("top_installation_id"),
            F.col("risk_factor_components").alias("top_risk_factor_components"),
        )
    )
    relationship_counts = scored_relations.groupBy("asset_id").agg(
        F.count(F.lit(1)).alias("scored_exposure_rows"),
        F.countDistinct("installation_id").alias("scored_installation_count"),
        F.countDistinct("cve_id").alias("scored_cve_count"),
        F.sum(F.when(F.col("known_exploited"), 1).otherwise(0)).alias(
            "kev_exposure_rows"
        ),
        F.sum(F.when(F.col("risk_tier") == "critical", 1).otherwise(0)).alias(
            "critical_exposure_rows"
        ),
        F.sum(F.when(F.col("risk_tier") == "high", 1).otherwise(0)).alias(
            "high_exposure_rows"
        ),
        F.sum(F.when(F.col("risk_tier") == "medium", 1).otherwise(0)).alias(
            "medium_exposure_rows"
        ),
        F.sum(F.when(F.col("risk_tier") == "low", 1).otherwise(0)).alias(
            "low_exposure_rows"
        ),
    )
    summary = (
        asset_context_df
        .join(relationship_counts, "asset_id", "left")
        .join(top_risks, "asset_id", "left")
        .fillna({
            "scored_exposure_rows": 0,
            "scored_installation_count": 0,
            "scored_cve_count": 0,
            "kev_exposure_rows": 0,
            "critical_exposure_rows": 0,
            "high_exposure_rows": 0,
            "medium_exposure_rows": 0,
            "low_exposure_rows": 0,
        })
        .withColumn(
            "asset_risk_status",
            F.when(
                F.col("scored_exposure_rows") > 0,
                F.lit("scored_confirmed_exposure"),
            ).otherwise(F.lit("no_scored_confirmed_exposure")),
        )
    )
    rank_window = Window.orderBy(
        F.col("max_risk_score").desc_nulls_last(),
        F.col("kev_exposure_rows").desc(),
        F.when(F.col("criticality") == "critical", 3)
        .when(F.col("criticality") == "high", 2)
        .when(F.col("criticality") == "medium", 1)
        .otherwise(0)
        .desc(),
        F.col("asset_id").asc(),
    )
    return summary.withColumn(
        "asset_priority_rank",
        F.when(
            F.col("scored_exposure_rows") > 0,
            F.row_number().over(rank_window),
        ),
    )


def _top_rows(dataframe: DataFrame, columns: list[str], limit: int = TOP_RANK_LIMIT) -> list[dict[str, Any]]:
    return [
        row.asDict(recursive=True)
        for row in dataframe.limit(limit).collect()
    ]


def _jsonable_top(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        result.append({
            key: value
            for key, value in row.items()
            if key not in {"risk_factor_components", "top_risk_factor_components"}
        })
    return result


def _write_dataset(dataframe: DataFrame, output_path: Path, label: str) -> int:
    count = dataframe.count()
    print(f"{label}: {count:,} rows; writing bounded Parquet batches...", flush=True)
    written = _write_dataframe_bounded(
        dataframe,
        output_path,
        count,
        partitions=OUTPUT_PARTITIONS,
        batch_size=WRITE_BATCH_SIZE,
    )
    if written != count:
        raise RuntimeError(f"{label} row-count mismatch: counted {count}, wrote {written}")
    return count


def run_prioritization(
    exposure_dir: Path = DEFAULT_EXPOSURE_DIR,
    exposure_summary_path: Path = DEFAULT_EXPOSURE_SUMMARY,
    inventory_dir: Path = DEFAULT_INVENTORY_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    config: RiskScoringConfig = RiskScoringConfig(),
) -> dict[str, Any]:
    exposure_dir = exposure_dir.resolve()
    exposure_summary_path = exposure_summary_path.resolve()
    inventory_dir = inventory_dir.resolve()
    output_dir = output_dir.resolve()
    assets_path = inventory_dir / "enterprise_assets.csv"

    config.validate()
    if output_dir.exists():
        raise FileExistsError(f"Output exists; refusing to overwrite: {output_dir}")
    if not exposure_summary_path.is_file():
        raise FileNotFoundError(f"Exposure summary is missing: {exposure_summary_path}")
    if not assets_path.is_file():
        raise FileNotFoundError(f"Enterprise asset context is missing: {assets_path}")
    exposure_summary = json.loads(exposure_summary_path.read_text(encoding="utf-8"))
    if exposure_summary.get("dataset") != "enterprise inventory vulnerability exposure candidates":
        raise ValueError("Exposure summary does not identify the expected Phase 3 dataset")

    python_executable = sys.executable
    if not Path(python_executable).is_file():
        raise FileNotFoundError(f"Python interpreter does not exist: {python_executable}")
    os.environ["PYSPARK_PYTHON"] = python_executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable
    spark = (
        SparkSession.builder.appName("PRIORIS-Risk-Prioritization")
        .master("local[2]")
        .config("spark.pyspark.python", python_executable)
        .config("spark.pyspark.driver.python", python_executable)
        .config("spark.sql.shuffle.partitions", "16")
        .config("spark.sql.adaptive.enabled", "true")
        .config("spark.sql.autoBroadcastJoinThreshold", "-1")
        .config("spark.sql.files.maxPartitionBytes", str(64 * 1024 * 1024))
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    started = time.perf_counter()
    staging_dir: Path | None = None
    published = False
    scored_df: DataFrame | None = None

    try:
        print(
            f"Spark {spark.version}, master local[2], Python {python_executable}; "
            "automatic broadcast joins disabled.",
            flush=True,
        )
        print(f"Exposure input: {exposure_dir}", flush=True)
        print(f"Asset context: {assets_path}", flush=True)
        exposure_df = _read_parquet(spark, exposure_dir)
        asset_context = (
            spark.read.option("header", True)
            .option("inferSchema", False)
            .csv(str(assets_path))
        )
        _require_columns(exposure_df, EXPOSURE_REQUIRED_COLUMNS, "Enterprise exposure")
        _require_columns(asset_context, ASSET_REQUIRED_COLUMNS, "Enterprise asset context")
        asset_context = asset_context.select(
            "asset_id",
            "criticality",
            "exposure",
            "asset_type",
            "business_unit",
            "environment",
        ).persist(StorageLevel.DISK_ONLY)

        print("[1/6] Verifying asset context and exposure input...", flush=True)
        duplicate_assets = (
            asset_context.groupBy("asset_id").count().where(F.col("count") > 1).limit(1).count()
        )
        if duplicate_assets:
            raise ValueError("Enterprise asset context has duplicate asset_id values")
        input_count = exposure_df.count()
        expected_exposure_count = exposure_summary.get("exposure_rows")
        if (
            expected_exposure_count is not None
            and input_count != int(expected_exposure_count)
        ):
            raise ValueError(
                f"Exposure row count differs from summary: "
                f"{input_count} != {expected_exposure_count}"
            )
        missing_assets = (
            exposure_df.select("asset_id").distinct()
            .join(asset_context.select("asset_id"), "asset_id", "left_anti")
            .limit(1)
            .count()
        )
        if missing_assets:
            raise ValueError("Exposure records reference assets absent from enterprise_assets.csv")
        print(
            f"Validated {input_count:,} exposure rows and "
            f"{asset_context.count():,} unique assets.",
            flush=True,
        )

        print("[2/6] Applying existing PRIORIS risk formula...", flush=True)
        scored_df = build_scored_exposures(
            exposure_df,
            asset_context,
            config,
        ).persist(StorageLevel.DISK_ONLY)
        status_counts = {
            row["scoring_status"]: int(row["count"])
            for row in scored_df.groupBy("scoring_status").count().collect()
        }
        applicability_counts = {
            row["applicability_status"]: int(row["count"])
            for row in scored_df.groupBy("applicability_status").count().collect()
        }
        tier_counts = {
            row["risk_tier"]: int(row["count"])
            for row in scored_df.where(F.col("scoring_status") == "scored")
            .groupBy("risk_tier").count().collect()
        }
        scored_count = int(status_counts.get("scored", 0))
        print(
            f"Scored {scored_count:,} confirmed vulnerable records; "
            f"scoring statuses={status_counts}; risk tiers={tier_counts}",
            flush=True,
        )

        print("[3/6] Aggregating asset, CVE and installation rankings...", flush=True)
        asset_summary_df = build_asset_risk_summary(scored_df, asset_context)
        scored = scored_df.where(F.col("scoring_status") == "scored")
        scored_distinct_counts = scored.agg(
            F.countDistinct("installation_id").alias("installations"),
            F.countDistinct(F.concat_ws("::", "asset_id", "cve_id")).alias(
                "asset_cve_relationships"
            ),
        ).first().asDict()
        cve_ranking = (
            scored.groupBy("cve_id")
            .agg(
                F.max("risk_score").alias("max_risk_score"),
                F.max(F.col("cvss_score").cast("double")).alias("cvss_score"),
                F.max(F.col("known_exploited").cast("int")).cast("boolean").alias("known_exploited"),
                F.countDistinct("asset_id").alias("affected_asset_count"),
                F.countDistinct("installation_id").alias("affected_installation_count"),
                F.max_by("risk_tier", "risk_score").alias("max_score_risk_tier"),
            )
            .orderBy(
                F.col("max_risk_score").desc(),
                F.col("known_exploited").desc(),
                F.col("cvss_score").desc(),
                F.col("cve_id").asc(),
            )
        )
        installation_ranking = (
            scored.groupBy(
                "installation_id",
                "asset_id",
                "software_name",
                "software_product",
                "installed_version",
            )
            .agg(
                F.max("risk_score").alias("max_risk_score"),
                F.max(F.col("cvss_score").cast("double")).alias("cvss_score"),
                F.max(F.col("known_exploited").cast("int")).cast("boolean").alias("known_exploited"),
                F.countDistinct("cve_id").alias("affected_cve_count"),
                F.max_by("risk_tier", "risk_score").alias("max_score_risk_tier"),
                F.max_by("cve_id", F.struct(
                    "risk_score",
                    F.col("known_exploited").cast("int"),
                    F.col("cvss_score").cast("double"),
                )).alias("top_cve_id"),
            )
            .orderBy(
                F.col("max_risk_score").desc(),
                F.col("known_exploited").desc(),
                F.col("cvss_score").desc(),
                F.col("installation_id").asc(),
            )
        )

        top_assets = _top_rows(
            asset_summary_df.where(F.col("asset_priority_rank").isNotNull())
            .orderBy("asset_priority_rank"),
            [
                "asset_priority_rank", "asset_id", "asset_type", "criticality",
                "exposure", "max_risk_score", "top_risk_tier", "top_risk_cve_id",
                "scored_installation_count", "scored_cve_count", "kev_exposure_rows",
            ],
        )
        top_cves = _top_rows(
            cve_ranking,
            [
                "cve_id", "max_risk_score", "max_score_risk_tier", "cvss_score",
                "known_exploited", "affected_asset_count", "affected_installation_count",
            ],
        )
        top_installations = _top_rows(
            installation_ranking,
            [
                "installation_id", "asset_id", "software_name", "software_product",
                "installed_version", "max_risk_score", "max_score_risk_tier",
                "top_cve_id", "cvss_score", "known_exploited", "affected_cve_count",
            ],
        )

        summary = {
            "project": "PRIORIS",
            "phase": 4,
            "dataset": "enterprise risk prioritization",
            "input_exposure_directory": str(exposure_dir),
            "input_exposure_summary": str(exposure_summary_path),
            "inventory_directory": str(inventory_dir),
            "execution": {
                "spark_master": "local[2]",
                "spark_version": spark.version,
                "python_executable": python_executable,
                "automatic_broadcast_joins": False,
                "bounded_output_partitions": OUTPUT_PARTITIONS,
                "output_batch_size": WRITE_BATCH_SIZE,
                "scoring_implementation": "src.score_risks.score_components",
            },
            "scoring_method": {
                "formula": (
                    "CVSS + KEV bonus * membership + criticality step * level "
                    "+ network exposure bonus"
                ),
                "configuration": {
                    "kev_bonus": config.kev_bonus,
                    "criticality_step": config.criticality_step,
                    "internet_facing_bonus": config.internet_facing_bonus,
                    "internal_bonus": config.internal_bonus,
                    "medium_threshold": config.medium_threshold,
                    "high_threshold": config.high_threshold,
                    "critical_threshold": config.critical_threshold,
                    "score_bounds": [0.0, config.maximum_score],
                },
                "risk_tiers": {
                    "critical": f"score >= {config.critical_threshold}",
                    "high": f"{config.high_threshold} <= score < {config.critical_threshold}",
                    "medium": f"{config.medium_threshold} <= score < {config.high_threshold}",
                    "low": f"score < {config.medium_threshold}",
                },
                "missing_evidence_policy": (
                    "No score or tier is assigned if CVSS, explicit KEV membership, "
                    "criticality, or network exposure is missing or invalid."
                ),
            },
            "counts": {
                "input_exposure_rows": input_count,
                "scored_confirmed_vulnerable_rows": scored_count,
                "scoring_status_counts": status_counts,
                "applicability_status_counts": applicability_counts,
                "risk_tier_counts": tier_counts,
                "assets_in_asset_context": asset_context.count(),
                "assets_with_scored_exposure": asset_summary_df.where(
                    F.col("scored_exposure_rows") > 0
                ).count(),
                "distinct_scored_cves": cve_ranking.count(),
                "distinct_scored_installations": installation_ranking.count(),
                "distinct_scored_asset_cve_relationships": int(
                    scored_distinct_counts["asset_cve_relationships"] or 0
                ),
            },
            "top_assets": _jsonable_top(top_assets),
            "top_cves": _jsonable_top(top_cves),
            "top_installations": _jsonable_top(top_installations),
            "evidence_and_limitations": [
                "Asset criticality and network exposure are loaded from the project synthetic enterprise inventory.",
                "The source project scoring formula is an illustrative prototype, not a calibrated organizational loss model.",
                "Only confirmed_match rows with vulnerable=true are scored.",
                "Unresolved, unsupported, manual-review, and other non-confirmed statuses remain unscored and are not classified as safe.",
                "KEV absence is interpreted only against the Phase 3 local snapshot and is not evidence that exploitation is absent.",
            ],
            "elapsed_seconds_before_output": round(time.perf_counter() - started, 3),
        }

        print("[4/6] Preparing non-overwriting staged outputs...", flush=True)
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(
            prefix=".prioris-risk-prioritization-",
            dir=output_dir.parent,
        ))
        scored_rows = _write_dataset(
            scored_df,
            staging_dir / "prioritized_exposures",
            "Prioritized exposure records",
        )
        assets_written = _write_dataset(
            asset_summary_df,
            staging_dir / "asset_risk_summary",
            "Asset risk summary",
        )
        (staging_dir / "risk_summary.json").write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )
        print("[5/6] Publishing completed staged outputs...", flush=True)
        os.rename(staging_dir, output_dir)
        published = True
        summary["output_directory"] = str(output_dir)
        summary["outputs"] = {
            "prioritized_exposure_rows": scored_rows,
            "asset_summary_rows": assets_written,
        }
        summary["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        (output_dir / "risk_summary.json").write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )
        print(
            f"[6/6] Published risk prioritization in "
            f"{summary['elapsed_seconds']:.1f}s: {output_dir}",
            flush=True,
        )
        return summary
    finally:
        if scored_df is not None:
            scored_df.unpersist()
        if "asset_context" in locals():
            asset_context.unpersist()
        spark.stop()
        if not published and staging_dir is not None and staging_dir.exists():
            shutil.rmtree(staging_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prioritize confirmed enterprise exposures using the existing PRIORIS risk formula."
    )
    parser.add_argument("--exposure-dir", type=Path, default=DEFAULT_EXPOSURE_DIR)
    parser.add_argument(
        "--exposure-summary",
        type=Path,
        default=DEFAULT_EXPOSURE_SUMMARY,
    )
    parser.add_argument("--inventory-dir", type=Path, default=DEFAULT_INVENTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    result = run_prioritization(
        exposure_dir=args.exposure_dir,
        exposure_summary_path=args.exposure_summary,
        inventory_dir=args.inventory_dir,
        output_dir=args.output_dir,
    )
    print(json.dumps(result, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
