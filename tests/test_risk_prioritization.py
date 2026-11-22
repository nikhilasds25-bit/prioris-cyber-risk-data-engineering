import os
import sys
import unittest

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    BooleanType,
    StringType,
    StructField,
    StructType,
)

from src.PRIORIS_risk_prioritization import (
    build_asset_risk_summary,
    build_scored_exposures,
)


class RiskPrioritizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        python_executable = sys.executable
        os.environ["PYSPARK_PYTHON"] = python_executable
        os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable
        cls.spark = (
            SparkSession.builder.appName("PRIORIS-Risk-Prioritization-Tests")
            .master("local[2]")
            .config("spark.pyspark.python", python_executable)
            .config("spark.pyspark.driver.python", python_executable)
            .config("spark.sql.shuffle.partitions", "2")
            .config("spark.sql.autoBroadcastJoinThreshold", "-1")
            .getOrCreate()
        )
        cls.spark.sparkContext.setLogLevel("ERROR")

    @classmethod
    def tearDownClass(cls):
        cls.spark.stop()

    def setUp(self):
        exposure_schema = StructType([
            StructField("asset_id", StringType(), False),
            StructField("installation_id", StringType(), False),
            StructField("software_name", StringType(), False),
            StructField("software_product", StringType(), False),
            StructField("installed_version", StringType(), False),
            StructField("cve_id", StringType(), True),
            StructField("vulnerable", BooleanType(), True),
            StructField("cvss_score", StringType(), True),
            StructField("known_exploited", BooleanType(), True),
            StructField("kev_date_added", StringType(), True),
            StructField("applicability_status", StringType(), False),
            StructField("match_evidence", StringType(), False),
        ])
        self.exposures = self.spark.createDataFrame([
            (
                "asset-1", "install-1", "Product One", "one", "1.0",
                "CVE-TEST-1", True, "9.2", True, "2024-01-01",
                "confirmed_match", "{}",
            ),
            (
                "asset-1", "install-2", "Product Two", "two", "2.0",
                "CVE-TEST-2", True, None, False, None,
                "confirmed_match", "{}",
            ),
            (
                "asset-2", "install-3", "Product Three", "three", "3.0",
                "CVE-TEST-3", True, "10.0", False, None,
                "unsupported_matching", "{}",
            ),
            (
                "asset-2", "install-4", "Product Four", "four", "4.0",
                "CVE-TEST-4", False, "8.0", False, None,
                "confirmed_match", "{}",
            ),
        ], exposure_schema)
        asset_schema = StructType([
            StructField("asset_id", StringType(), False),
            StructField("criticality", StringType(), False),
            StructField("exposure", StringType(), False),
            StructField("asset_type", StringType(), False),
            StructField("business_unit", StringType(), False),
            StructField("environment", StringType(), False),
        ])
        self.assets = self.spark.createDataFrame([
            ("asset-1", "high", "internet-facing", "server", "Engineering", "production"),
            ("asset-2", "critical", "restricted", "server", "IT", "production"),
        ], asset_schema)

    def test_only_confirmed_vulnerable_rows_with_complete_evidence_are_scored(self):
        scored = build_scored_exposures(self.exposures, self.assets)
        rows = {
            row["installation_id"]: row
            for row in scored.select(
                "installation_id",
                "risk_score",
                "risk_tier",
                "scoring_status",
                "risk_factor_components",
                "risk_factor_evidence",
                "missing_score_evidence",
            ).collect()
        }

        self.assertEqual(rows["install-1"]["risk_score"], 15.2)
        self.assertEqual(rows["install-1"]["risk_tier"], "critical")
        self.assertEqual(rows["install-1"]["scoring_status"], "scored")
        self.assertEqual(rows["install-2"]["risk_score"], None)
        self.assertEqual(
            rows["install-2"]["scoring_status"],
            "withheld_missing_score_evidence",
        )
        self.assertEqual(
            rows["install-3"]["scoring_status"],
            "not_scored_applicability_unconfirmed",
        )
        self.assertEqual(
            rows["install-4"]["scoring_status"],
            "not_scored_term_not_vulnerable",
        )
        self.assertIn('"severity":9.2', rows["install-1"]["risk_factor_components"])
        self.assertIn('"asset_criticality":"high"', rows["install-1"]["risk_factor_evidence"])
        self.assertIn('"known_exploited":true', rows["install-1"]["risk_factor_evidence"])
        self.assertEqual(
            rows["install-2"]["missing_score_evidence"],
            '["valid_cvss_score_0_to_10"]',
        )

    def test_asset_summary_keeps_assets_without_scored_exposure(self):
        scored = build_scored_exposures(self.exposures, self.assets)
        summary = build_asset_risk_summary(scored, self.assets)
        rows = {
            row["asset_id"]: row
            for row in summary.select(
                "asset_id",
                "max_risk_score",
                "top_risk_tier",
                "asset_risk_status",
                "asset_priority_rank",
            ).collect()
        }

        self.assertEqual(rows["asset-1"]["max_risk_score"], 15.2)
        self.assertEqual(rows["asset-1"]["top_risk_tier"], "critical")
        self.assertEqual(rows["asset-1"]["asset_priority_rank"], 1)
        self.assertEqual(
            rows["asset-2"]["asset_risk_status"],
            "no_scored_confirmed_exposure",
        )
        self.assertIsNone(rows["asset-2"]["asset_priority_rank"])


if __name__ == "__main__":
    unittest.main()
