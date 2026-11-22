"""PRIORIS Phase 1: distributed CVE-to-KEV join using PySpark DataFrames and SQL.

Run: python src/first_join.py --date YYYY-MM-DD
Requires staged files prepared by download_data.py.
Does NOT yet identify which company assets are affected.
"""
import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
import pyarrow.parquet as pq


os.environ["PYSPARK_PYTHON"] = sys.executable

from pyspark.sql import SparkSession, functions as F

ROOT = Path(__file__).resolve().parents[1]


def main(date):
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError as exc:
        raise SystemExit(f"Invalid snapshot date {date!r}; use YYYY-MM-DD.") from exc

    processed = ROOT / "data" / "processed" / date
    nvd_path = processed / "nvd_cves.jsonl"
    kev_path = processed / "cisa_kev.jsonl"
    if not (nvd_path.is_file() and kev_path.is_file()):
        raise SystemExit(
            f"Processed files missing for {date}. Run python src/download_data.py first."
        )

    spark = (
        SparkSession.builder.appName("PriorisPhase1")
        .master("local[2]")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    try:
        nvd = (spark.read.json(str(nvd_path))
               .filter(F.col("cve_id").isNotNull())
               .dropDuplicates(["cve_id"]))
        kev = (spark.read.json(str(kev_path))
               .filter(F.col("cve_id").isNotNull())
               .select("cve_id", "date_added")
               .dropDuplicates(["cve_id"]))

        enriched = (
            nvd.join(F.broadcast(kev), on="cve_id", how="left")
            .withColumn("in_kev", F.col("date_added").isNotNull())
        )
        print("\nFIRST JOIN — CVSS severity and known exploitation:\n")
        enriched.select(
            "cve_id", "cvss_score", "cvss_version", "in_kev", "date_added"
        ).orderBy(F.desc("in_kev"), F.desc_nulls_last("cvss_score")).show(20, truncate=False)

        print("\nHow many NVD records are in the CISA KEV catalog?\n")
        enriched.groupBy("in_kev").count().show()

        enriched.createOrReplaceTempView("prioris_cves")
        print("\nSpark SQL example: CVSS summary grouped by KEV presence:\n")
        spark.sql("""
            SELECT in_kev, COUNT(*) AS cve_count,
                   ROUND(AVG(cvss_score), 2) AS mean_cvss
            FROM prioris_cves
            GROUP BY in_kev
            ORDER BY in_kev DESC
        """).show()

               # Save the small Spark result using PyArrow
        output_path = ROOT / "results" / date / "enriched_cves.parquet"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_path.exists():
            raise FileExistsError(
                f"Output already exists: {output_path}"
            )

        # Convert Spark DataFrame to Apache Arrow
        arrow_table = enriched.toArrow()

        # Save as Parquet without Hadoop's Windows file writer
        pq.write_table(arrow_table, str(output_path))

        # Verify the saved file
        verified = pq.read_table(str(output_path))

        assert verified.num_rows == arrow_table.num_rows

        print("\nSUCCESS! Parquet file saved.")
        print(f"Location: {output_path}")
        print(f"Verified records: {verified.num_rows}")
        print("IMPORTANT: this table joins CVE records, not affected enterprise assets.")
    finally:
        spark.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--date", required=True, help="Snapshot folder YYYY-MM-DD")
    main(parser.parse_args().date)
