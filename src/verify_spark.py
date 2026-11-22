"""Test that Apache Spark can run on this Windows laptop."""
import os
import sys

os.environ["PYSPARK_PYTHON"] = sys.executable

from pyspark.sql import SparkSession

spark = (SparkSession.builder
         .appName("PriorisSetupCheck")
         .master("local[2]")
         .getOrCreate())
spark.sparkContext.setLogLevel("ERROR")

rows = [("CVE-TEST-1", 9.8), ("CVE-TEST-2", 7.5), ("CVE-TEST-3", 8.4)]
df = spark.createDataFrame(rows, ["cve_id", "cvss_score"])
df.show(truncate=False)
assert df.count() == 3
print("SUCCESS: PySpark is working locally (3 test rows).")
spark.stop()
