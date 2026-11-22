import os
import sys
import unittest

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

from src.PRIORIS_cpe_integration import build_integrated_dataframes


class CpeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        python_executable = sys.executable
        os.environ["PYSPARK_PYTHON"] = python_executable
        os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable
        cls.spark = (
            SparkSession.builder.appName("PRIORIS-CPE-Integration-Tests")
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
        nvd_schema = StructType([
            StructField("source_year", IntegerType(), False),
            StructField("cve_id", StringType(), False),
            StructField("configuration_index", IntegerType(), False),
            StructField("node_path", StringType(), False),
            StructField("match_index", IntegerType(), False),
            StructField("vulnerable", BooleanType(), False),
            StructField("criteria", StringType(), False),
            StructField("match_criteria_id", StringType(), False),
            StructField("status", StringType(), False),
            StructField("version_start_including", StringType(), True),
            StructField("version_start_excluding", StringType(), True),
            StructField("version_end_including", StringType(), True),
            StructField("version_end_excluding", StringType(), True),
            StructField("raw_match_json", StringType(), False),
        ])
        self.nvd = self.spark.createDataFrame([
            (
                2026, "CVE-TEST-1", 0, "0", 0, True,
                "nvd-criteria-one", "criterion-one", "Active",
                "1.0", None, "2.0", None, '{"vulnerable":true}',
            ),
            (
                2026, "CVE-TEST-2", 1, "0/1", 2, False,
                "nvd-criteria-two", "criterion-two", "Active",
                None, "3.0", None, "4.0", '{"vulnerable":false}',
            ),
            (
                2025, "CVE-TEST-3", 2, "1", 1, True,
                "nvd-criteria-three", "criterion-three", "Active",
                None, None, None, None, '{"vulnerable":true}',
            ),
        ], nvd_schema)

        criteria_schema = StructType([
            StructField("matchCriteriaId", StringType(), False),
            StructField("criteria", StringType(), False),
            StructField("status", StringType(), False),
            StructField("created", StringType(), False),
            StructField("lastModified", StringType(), False),
            StructField("cpeLastModified", StringType(), False),
            StructField("versionStartIncluding", StringType(), True),
            StructField("versionStartExcluding", StringType(), True),
            StructField("versionEndIncluding", StringType(), True),
            StructField("versionEndExcluding", StringType(), True),
        ])
        self.criteria = self.spark.createDataFrame([
            ("criterion-one", "criteria-one", "Active", "created-1", "modified-1", "cpe-1",
             "0.5", None, "2.5", None),
            ("criterion-two", "criteria-two", "Active", "created-2", "modified-2", "cpe-2",
             None, "2.5", None, "4.5"),
            ("criterion-three", "criteria-three", "Active", "created-3", "modified-3", "cpe-3",
             None, None, None, None),
        ], criteria_schema)

        names_schema = StructType([
            StructField("matchCriteriaId", StringType(), False),
            StructField("cpeName", StringType(), False),
            StructField("cpeNameId", StringType(), False),
        ])
        self.names = self.spark.createDataFrame([
            ("criterion-one", "cpe:2.3:a:vendor:one:1.0:*:*:*:*:*:*:*", "cpe-id-1"),
            ("criterion-two", "cpe:2.3:a:vendor:two:1:*:*:*:*:*:*:*", "cpe-id-2a"),
            ("criterion-two", "cpe:2.3:a:vendor:two:2:*:*:*:*:*:*:*", "cpe-id-2b"),
        ], names_schema)

        titles_schema = ArrayType(StructType([
            StructField("title", StringType(), True),
            StructField("lang", StringType(), True),
        ]))
        dictionary_schema = StructType([
            StructField("cpeNameId", StringType(), False),
            StructField("cpeName", StringType(), False),
            StructField("deprecated", BooleanType(), True),
            StructField("titles", titles_schema, True),
        ])
        self.dictionary = self.spark.createDataFrame([
            ("cpe-id-1", "cpe:2.3:a:vendor:one:1.0:*:*:*:*:*:*:*", False,
             [{"title": "Product One", "lang": "en"}]),
            ("cpe-id-2a", "cpe:2.3:a:vendor:two:1:*:*:*:*:*:*:*", True,
             [{"title": "Product Two A", "lang": "en"}]),
            ("cpe-id-2b", "cpe:2.3:a:vendor:two:2:*:*:*:*:*:*:*", False,
             [{"title": "Product Two B", "lang": "en"}]),
        ], dictionary_schema)

    def test_builds_one_term_row_and_expected_name_associations(self):
        terms, associations = build_integrated_dataframes(
            self.nvd, self.criteria, self.names, self.dictionary
        )

        self.assertEqual(terms.count(), 3)
        self.assertEqual(associations.count(), 3)
        associations_by_id = {
            row["match_criteria_id"]: row.asDict(recursive=True)
            for row in associations.select(
                "match_criteria_id", "cpeNameId", "cpeName", "titles"
            ).collect()
        }
        self.assertEqual(associations_by_id["criterion-one"]["cpeNameId"], "cpe-id-1")
        criterion_two = associations.where(
            associations.match_criteria_id == "criterion-two"
        )
        self.assertEqual(criterion_two.count(), 2)
        self.assertEqual(
            associations.where(
                associations.match_criteria_id == "criterion-three"
            ).count(),
            0,
        )
        self.assertEqual(
            associations_by_id["criterion-one"]["titles"][0]["title"],
            "Product One",
        )

    def test_preserves_nvd_and_criteria_boundaries_separately(self):
        terms, _ = build_integrated_dataframes(
            self.nvd, self.criteria, self.names, self.dictionary
        )
        row = terms.where(terms.match_criteria_id == "criterion-one").first()

        self.assertEqual(row["version_start_including"], "1.0")
        self.assertEqual(row["version_end_including"], "2.0")
        self.assertEqual(row["criteria_version_start_including"], "0.5")
        self.assertEqual(row["criteria_version_end_including"], "2.5")
        self.assertEqual(row["criteria"], "nvd-criteria-one")
        self.assertEqual(row["cpe_match_criteria"], "criteria-one")

    def test_preserves_vulnerable_flag_and_configuration_provenance(self):
        terms, associations = build_integrated_dataframes(
            self.nvd, self.criteria, self.names, self.dictionary
        )
        row = terms.where(terms.match_criteria_id == "criterion-two").first()

        self.assertFalse(row["vulnerable"])
        self.assertEqual(row["cve_id"], "CVE-TEST-2")
        self.assertEqual(row["source_year"], 2026)
        self.assertEqual(row["configuration_index"], 1)
        self.assertEqual(row["node_path"], "0/1")
        self.assertEqual(row["match_index"], 2)
        self.assertEqual(row["raw_match_json"], '{"vulnerable":false}')

        association = associations.where(
            associations.match_criteria_id == "criterion-two"
        ).first()
        self.assertFalse(association["vulnerable"])
        self.assertEqual(association["configuration_index"], 1)
        self.assertEqual(association["node_path"], "0/1")


if __name__ == "__main__":
    unittest.main()
