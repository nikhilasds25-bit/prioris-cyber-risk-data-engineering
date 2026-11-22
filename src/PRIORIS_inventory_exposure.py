#!/usr/bin/env python3
"""Match the local enterprise inventory against integrated NVD/CPE evidence."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pyspark.sql import DataFrame, SparkSession, functions as F
from pyspark.storagelevel import StorageLevel
from pyspark.sql.types import (
    BooleanType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

from src.PRIORIS_cpe_integration import _write_dataframe_bounded
from src.match_vulnerabilities import (
    InventoryIndex,
    _matches_non_version_cpe_parts,
    _unsupported_version_comparison,
    configuration_manual_review_reasons,
    evaluate_configuration_indexed,
    split_cpe,
    unescape_cpe_component,
)

DEFAULT_INVENTORY_DIR = ROOT / "data" / "synthetic"
DEFAULT_INTEGRATION_DIR = ROOT / "data" / "processed" / "cpe_integration"
DEFAULT_NVD_TABLES_DIR = (
    ROOT
    / "data"
    / "processed"
    / "nvd_historical"
    / ".prioris-nvd-2026-6_2kmi7p"
    / "parquet_output"
)
DEFAULT_KEV_JSONL = ROOT / "data" / "processed" / "2026-10-19" / "cisa_kev.jsonl"
DEFAULT_OUTPUT_DIR = ROOT / "data" / "processed" / "enterprise_exposure"

INVENTORY_COLUMNS = {
    "installation_id",
    "asset_id",
    "software_name",
    "software_product",
    "software_version",
    "cpe23_uri",
}
ASSET_COLUMNS = {"asset_id"}
EXPOSURE_SCHEMA = StructType([
    StructField("asset_id", StringType(), True),
    StructField("installation_id", StringType(), True),
    StructField("software_name", StringType(), True),
    StructField("software_product", StringType(), True),
    StructField("installed_version", StringType(), True),
    StructField("installed_cpe_name", StringType(), True),
    StructField("cpe_name_id", StringType(), True),
    StructField("cpe_name", StringType(), True),
    StructField("matched_product", StringType(), True),
    StructField("product_deprecated", BooleanType(), True),
    StructField("product_titles", StringType(), True),
    StructField("cve_id", StringType(), True),
    StructField("cpe_name_association_count", IntegerType(), True),
    StructField("vulnerable", BooleanType(), True),
    StructField("source_year", IntegerType(), True),
    StructField("configuration_index", IntegerType(), True),
    StructField("node_path", StringType(), True),
    StructField("match_index", IntegerType(), True),
    StructField("match_criteria_id", StringType(), True),
    StructField("criteria", StringType(), True),
    StructField("raw_match_json", StringType(), True),
    StructField("version_start_including", StringType(), True),
    StructField("version_start_excluding", StringType(), True),
    StructField("version_end_including", StringType(), True),
    StructField("version_end_excluding", StringType(), True),
    StructField("cvss_score", StringType(), True),
    StructField("known_exploited", BooleanType(), True),
    StructField("kev_date_added", StringType(), True),
    StructField("applicability_status", StringType(), False),
    StructField("match_evidence", StringType(), False),
])

# Escaped CPE colons are part of a component, not a component separator.
_CPE_PARTS_REGEX = (
    r"^cpe:2\.3:((?:\\.|[^:])*)"
    r":((?:\\.|[^:])*)"
    r":((?:\\.|[^:])*)"
)
_TERM_KEY_COLUMNS = [
    "cve_id",
    "source_year",
    "configuration_index",
    "node_path",
    "match_index",
    "match_criteria_id",
]


def _progress(label: str, started: float, detail: str = "") -> None:
    elapsed = time.perf_counter() - started
    suffix = f"; {detail}" if detail else ""
    print(f"[{elapsed:,.1f}s] {label}{suffix}", flush=True)


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


def _validate_columns(dataframe: DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(dataframe.columns))
    if missing:
        raise ValueError(f"{label} is missing required columns: {', '.join(missing)}")


def _read_csv_rows(path: Path, label: str) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(f"{label} is missing: {path}")
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def _cpe_product_parts(cpe: str) -> tuple[str, str, str] | None:
    parts = split_cpe(cpe or "")
    if parts is None:
        return None
    return tuple(
        unescape_cpe_component(parts[index]).lower()
        for index in (2, 3, 4)
    )


def _matcher_term(row: dict[str, Any]) -> dict[str, Any]:
    term = dict(row)
    term["matchCriteriaId"] = row.get("match_criteria_id") or ""
    return term


def _term_signature(term: dict[str, Any]) -> tuple[Any, ...]:
    return (
        term.get("criteria"),
        term.get("matchCriteriaId") or term.get("match_criteria_id"),
        term.get("vulnerable"),
        term.get("versionStartIncluding") or term.get("version_start_including"),
        term.get("versionStartExcluding") or term.get("version_start_excluding"),
        term.get("versionEndIncluding") or term.get("version_end_including"),
        term.get("versionEndExcluding") or term.get("version_end_excluding"),
    )


def _term_applicability(term: dict[str, Any], installation: dict[str, str]) -> str:
    """Classify a term with the existing matcher semantics."""
    from src.match_vulnerabilities import (
        _matches_cpe_parts,
        _unsupported_version_comparison,
    )

    pattern = split_cpe(str(term.get("criteria") or ""))
    actual = split_cpe(installation.get("cpe23_uri", ""))
    if pattern is None or actual is None:
        return "unsupported_matching"
    if _matches_cpe_parts(term, pattern, actual):
        return "matched"
    if (
        _matches_non_version_cpe_parts(pattern, actual)
        and _unsupported_version_comparison(term, pattern[5], actual[5])
    ):
        return "unsupported_matching"
    return "not_matching"


def _exposure_record(
    installation: dict[str, str],
    *,
    cve_id: str | None,
    status: str,
    term_row: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    term_row = term_row or {}
    return {
        "asset_id": installation.get("asset_id"),
        "installation_id": installation.get("installation_id"),
        "software_name": installation.get("software_name"),
        "software_product": installation.get("software_product"),
        "installed_version": installation.get("software_version"),
        "installed_cpe_name": installation.get("cpe23_uri"),
        "cpe_name_id": None,
        "cpe_name": None,
        "matched_product": installation.get("software_product"),
        "product_deprecated": None,
        "product_titles": None,
        "cve_id": cve_id,
        "cpe_name_association_count": None,
        "vulnerable": term_row.get("vulnerable"),
        "source_year": term_row.get("source_year"),
        "configuration_index": term_row.get("configuration_index"),
        "node_path": term_row.get("node_path"),
        "match_index": term_row.get("match_index"),
        "match_criteria_id": term_row.get("match_criteria_id"),
        "criteria": term_row.get("criteria"),
        "raw_match_json": term_row.get("raw_match_json"),
        "version_start_including": term_row.get("version_start_including"),
        "version_start_excluding": term_row.get("version_start_excluding"),
        "version_end_including": term_row.get("version_end_including"),
        "version_end_excluding": term_row.get("version_end_excluding"),
        "cvss_score": None,
        "known_exploited": None,
        "kev_date_added": None,
        "applicability_status": status,
        "match_evidence": json.dumps(evidence or {}, separators=(",", ":"), sort_keys=True),
    }


def _make_output_dataframe(
    spark: SparkSession,
    records: list[dict[str, Any]],
) -> DataFrame:
    if records:
        return spark.createDataFrame(records, schema=EXPOSURE_SCHEMA)
    return spark.createDataFrame([], schema=EXPOSURE_SCHEMA)


def _write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def run_exposure_matching(
    inventory_dir: Path = DEFAULT_INVENTORY_DIR,
    integration_dir: Path = DEFAULT_INTEGRATION_DIR,
    nvd_tables_dir: Path = DEFAULT_NVD_TABLES_DIR,
    kev_jsonl: Path = DEFAULT_KEV_JSONL,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    inventory_dir = inventory_dir.resolve()
    integration_dir = integration_dir.resolve()
    nvd_tables_dir = nvd_tables_dir.resolve()
    output_dir = output_dir.resolve()
    assets_path = inventory_dir / "enterprise_assets.csv"
    software_path = inventory_dir / "software_inventory.csv"
    terms_path = integration_dir / "cve_cpe_terms"
    associations_path = integration_dir / "cve_cpe_product_associations"
    configurations_path = nvd_tables_dir / "cve_configurations"
    core_path = nvd_tables_dir / "cve_core"

    if output_dir.exists():
        raise FileExistsError(
            f"Output exists; refusing to overwrite: {output_dir}"
        )
    for label, path in (
        ("CPE integration directory", integration_dir),
        ("NVD tables directory", nvd_tables_dir),
        ("NVD configurations", configurations_path),
        ("NVD core", core_path),
    ):
        if not path.exists():
            raise FileNotFoundError(f"{label} is missing: {path}")

    software_rows = _read_csv_rows(software_path, "Enterprise software inventory")
    asset_rows = _read_csv_rows(assets_path, "Enterprise asset inventory")
    missing_inventory_fields = sorted(
        INVENTORY_COLUMNS - set(software_rows[0] if software_rows else ())
    )
    if missing_inventory_fields:
        raise ValueError(
            f"Enterprise software inventory is missing required columns: "
            f"{', '.join(missing_inventory_fields)}"
        )
    if not software_rows:
        raise ValueError(f"Enterprise software inventory is empty: {software_path}")
    if len(software_rows) > 50_000:
        raise ValueError(
            "The existing matcher evaluates inventory rows in a local index; "
            f"{len(software_rows):,} installations exceeds the safe 50,000-row cap."
        )
    if any(not row.get("asset_id") or not row.get("installation_id") for row in software_rows):
        raise ValueError("Enterprise software inventory has missing asset or installation IDs.")
    if any(not row.get("asset_id") for row in asset_rows):
        raise ValueError("Enterprise asset inventory has an empty asset_id.")
    if len({row["installation_id"] for row in software_rows}) != len(software_rows):
        raise ValueError("Enterprise software inventory has duplicate installation_id values.")
    asset_ids = {row["asset_id"] for row in asset_rows}
    orphaned = sorted(
        {row["asset_id"] for row in software_rows if row["asset_id"] not in asset_ids}
    )
    if orphaned:
        raise ValueError(f"Software inventory references unknown assets: {orphaned[:5]}")

    python_executable = sys.executable
    if not Path(python_executable).is_file():
        raise FileNotFoundError(f"Python interpreter does not exist: {python_executable}")
    os.environ["PYSPARK_PYTHON"] = python_executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = python_executable
    spark = (
        SparkSession.builder.appName("PRIORIS-Enterprise-Exposure-Matching")
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

    try:
        print(
            f"Spark {spark.version}, master local[2], interpreter {python_executable}; "
            "automatic broadcast joins disabled.",
            flush=True,
        )
        print(f"Inventory: {inventory_dir}", flush=True)
        print(f"CPE integration: {integration_dir}", flush=True)
        print(f"NVD tables: {nvd_tables_dir}", flush=True)
        assets_df = spark.read.option("header", True).option(
            "inferSchema", False
        ).csv(str(assets_path))
        software_df = spark.read.option("header", True).option(
            "inferSchema", False
        ).csv(str(software_path))
        _validate_columns(assets_df, ASSET_COLUMNS, "Enterprise assets")
        _validate_columns(software_df, INVENTORY_COLUMNS, "Enterprise software inventory")

        print("[1/7] Counting enterprise inventory...", flush=True)
        total_assets = assets_df.select("asset_id").distinct().count()
        total_software = software_df.count()
        _progress(
            "Inventory loaded",
            started,
            f"{total_assets:,} assets; {total_software:,} software records",
        )

        matcher_inventory = InventoryIndex(software_rows)
        software_by_asset: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in software_rows:
            software_by_asset[row["asset_id"]].append(row)

        inventory_key_values = sorted({
            parts for row in software_rows
            if (parts := _cpe_product_parts(row.get("cpe23_uri", ""))) is not None
        })
        if not inventory_key_values:
            raise ValueError("No valid CPE 2.3 product keys in enterprise inventory.")
        key_schema = StructType([
            StructField("_cpe_part", StringType(), False),
            StructField("_cpe_vendor", StringType(), False),
            StructField("_cpe_product", StringType(), False),
        ])
        inventory_keys = spark.createDataFrame(inventory_key_values, key_schema)

        terms_df = _read_parquet(spark, terms_path)
        _validate_columns(
            terms_df,
            {
                "cve_id", "source_year", "configuration_index", "node_path",
                "match_index", "match_criteria_id", "criteria", "vulnerable",
                "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding",
            },
            "Integrated cve_cpe_terms",
        )
        terms_df = terms_df.select(
            "cve_id", "source_year", "configuration_index", "node_path",
            "match_index", "match_criteria_id", "criteria", "vulnerable",
            "version_start_including", "version_start_excluding",
            "version_end_including", "version_end_excluding",
            *(
                ["raw_match_json"]
                if "raw_match_json" in terms_df.columns
                else []
            ),
        )
        if "raw_match_json" not in terms_df.columns:
            terms_df = terms_df.withColumn(
                "raw_match_json", F.lit(None).cast(StringType())
            )

        def add_cpe_fields(dataframe: DataFrame, source: str) -> DataFrame:
            return (
                dataframe
                .withColumn(
                    "_cpe_part",
                    F.lower(F.regexp_replace(
                        F.regexp_extract(source, _CPE_PARTS_REGEX, 1),
                        r"\\(.)",
                        "$1",
                    )),
                )
                .withColumn(
                    "_cpe_vendor",
                    F.lower(F.regexp_replace(
                        F.regexp_extract(source, _CPE_PARTS_REGEX, 2),
                        r"\\(.)",
                        "$1",
                    )),
                )
                .withColumn(
                    "_cpe_product",
                    F.lower(F.regexp_replace(
                        F.regexp_extract(source, _CPE_PARTS_REGEX, 3),
                        r"\\(.)",
                        "$1",
                    )),
                )
            )

        print("[2/7] Filtering NVD terms by installed CPE product keys...", flush=True)
        parsed_terms = add_cpe_fields(terms_df, F.col("criteria"))
        exact_candidate_terms = (
            parsed_terms
            .filter(
                ~F.col("_cpe_vendor").rlike(r"[*?]")
                & ~F.col("_cpe_product").rlike(r"[*?]")
            )
            .join(F.broadcast(inventory_keys), ["_cpe_part", "_cpe_vendor", "_cpe_product"])
            .drop("_cpe_part", "_cpe_vendor", "_cpe_product")
        )
        candidate_term_rows = [row.asDict(recursive=True) for row in exact_candidate_terms.toLocalIterator()]
        wildcard_rows = [
            row.asDict(recursive=True)
            for row in (
                parsed_terms
                .filter(
                    (F.col("_cpe_vendor").rlike(r"[*?]"))
                    | (F.col("_cpe_product").rlike(r"[*?]"))
                )
                .drop("_cpe_part", "_cpe_vendor", "_cpe_product")
                .toLocalIterator()
            )
        ]
        candidate_term_rows.extend(wildcard_rows)
        _progress(
            "Candidate terms filtered",
            started,
            f"{len(candidate_term_rows):,} inventory-family term rows; "
            f"{len(inventory_key_values):,} distinct inventory product keys",
        )

        term_matches: dict[
            tuple[str, int, str, int],
            list[tuple[dict[str, Any], list[dict[str, str]], set[str]]],
        ] = defaultdict(list)
        terms_by_cve: dict[
            str,
            list[tuple[dict[str, Any], list[dict[str, str]], set[str]]],
        ] = defaultdict(list)
        terms_by_cve_config: dict[
            tuple[str, int],
            list[tuple[dict[str, Any], list[dict[str, str]], set[str]]],
        ] = defaultdict(list)
        candidate_cves: set[str] = set()
        potential_unsupported_terms: list[
            tuple[dict[str, Any], list[dict[str, str]], set[str]]
        ] = []
        seen_term_keys: set[tuple[Any, ...]] = set()
        for row in candidate_term_rows:
            term = _matcher_term(row)
            term_key = (
                row["cve_id"],
                int(row["configuration_index"]),
                row["node_path"],
                int(row["match_index"]),
            )
            dedupe_key = term_key + (row.get("match_criteria_id"),)
            if dedupe_key in seen_term_keys:
                continue
            seen_term_keys.add(dedupe_key)
            matched_installations = [
                installation
                for rows in matcher_inventory.matches(term).values()
                for installation in rows
            ]
            unsupported_asset_ids = matcher_inventory.unsupported_version_asset_ids(term)
            unsupported_installations: list[dict[str, str]] = []
            if unsupported_asset_ids:
                pattern = split_cpe(str(term.get("criteria") or ""))
                for asset_id in unsupported_asset_ids:
                    for installation in software_by_asset.get(asset_id, []):
                        actual = split_cpe(installation.get("cpe23_uri", ""))
                        if (
                            pattern is not None
                            and actual is not None
                            and _matches_non_version_cpe_parts(pattern, actual)
                            and _unsupported_version_comparison(
                                term, pattern[5], actual[5]
                            )
                        ):
                            unsupported_installations.append(installation)
            if matched_installations or unsupported_installations:
                term_matches[term_key].append(
                    (row, matched_installations, set(unsupported_asset_ids))
                )
                terms_by_cve[str(row["cve_id"])].append(
                    (row, matched_installations, set(unsupported_asset_ids))
                )
                terms_by_cve_config[
                    (str(row["cve_id"]), int(row["configuration_index"]))
                ].append((row, matched_installations, set(unsupported_asset_ids)))
                candidate_cves.add(str(row["cve_id"]))
                if unsupported_installations:
                    potential_unsupported_terms.append(
                        (row, unsupported_installations, set(unsupported_asset_ids))
                    )

        print(
            f"Version matcher identified {len(candidate_cves):,} candidate CVEs "
            f"across {sum(map(len, term_matches.values())):,} terms; "
            f"{len(potential_unsupported_terms):,} terms need unsupported-version review.",
            flush=True,
        )

        print("[3/7] Loading candidate configuration trees...", flush=True)
        cve_id_schema = StructType([StructField("cve_id", StringType(), False)])
        candidate_cve_df = spark.createDataFrame(
            [(cve_id,) for cve_id in sorted(candidate_cves)],
            cve_id_schema,
        )
        configurations_df = _read_parquet(spark, configurations_path).select(
            "cve_id", "configuration_index", "raw_configuration_json"
        )
        candidate_configs = (
            configurations_df.join(F.broadcast(candidate_cve_df), "cve_id", "inner")
            .collect()
        )
        configs_by_cve: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for row in candidate_configs:
            configs_by_cve[row["cve_id"]].append(
                (
                    int(row["configuration_index"]),
                    json.loads(row["raw_configuration_json"]),
                )
            )
        _progress(
            "Candidate configuration trees loaded",
            started,
            f"{len(candidate_configs):,} trees for {len(configs_by_cve):,} CVEs",
        )

        records: list[dict[str, Any]] = []
        represented_installations: set[str] = set()
        cves_with_unsupported_versions = {
            str(row["cve_id"])
            for row, unsupported_installations, _ in potential_unsupported_terms
            if unsupported_installations
        }
        for cve_id in sorted(candidate_cves):
            for config_index, config in sorted(configs_by_cve.get(cve_id, [])):
                config_terms = terms_by_cve_config.get(
                    (cve_id, config_index), []
                )
                candidate_installations_by_asset: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
                for row, matched, _ in config_terms:
                    for installation in matched:
                        candidate_installations_by_asset[installation["asset_id"]][
                            installation["installation_id"]
                        ] = installation
                manual_reasons = configuration_manual_review_reasons(config)
                if cve_id in cves_with_unsupported_versions:
                    manual_reasons = sorted({
                        *manual_reasons,
                        "cve_has_unsupported_version_comparison",
                    })
                for asset_id, installations in candidate_installations_by_asset.items():
                    if manual_reasons:
                        for row, matched, _ in config_terms:
                            for installation in matched:
                                if installation["asset_id"] != asset_id:
                                    continue
                                represented_installations.add(installation["installation_id"])
                                records.append(_exposure_record(
                                    installation,
                                    cve_id=cve_id,
                                    status="pending_manual_review",
                                    term_row=row,
                                    evidence={
                                        "reason": "configuration_requires_manual_review",
                                        "review_reasons": manual_reasons,
                                        "configuration_evaluation": "not_confirmed",
                                    },
                                ))
                        continue

                    passed, pairs = evaluate_configuration_indexed(
                        config, asset_id, matcher_inventory
                    )
                    if passed and pairs:
                        for installation, matched_term in pairs:
                            signature = _term_signature(matched_term)
                            term_rows = [
                                row
                                for row, _, _ in config_terms
                                if _term_signature(_matcher_term(row)) == signature
                            ]
                            for row in term_rows:
                                represented_installations.add(installation["installation_id"])
                                records.append(_exposure_record(
                                    installation,
                                    cve_id=cve_id,
                                    status="confirmed_match",
                                    term_row=row,
                                    evidence={
                                        "configuration_evaluation": "passed",
                                        "criteria": row.get("criteria"),
                                        "match_criteria_id": row.get("match_criteria_id"),
                                        "version_boundaries_source": "NVD cve_cpe_matches",
                                    },
                                ))
                    elif passed:
                        for row, matched, _ in config_terms:
                            for installation in matched:
                                if installation["asset_id"] != asset_id:
                                    continue
                                represented_installations.add(installation["installation_id"])
                                records.append(_exposure_record(
                                    installation,
                                    cve_id=cve_id,
                                    status="configuration_satisfied_no_vulnerable_term",
                                    term_row=row,
                                    evidence={
                                        "configuration_evaluation": "passed",
                                        "reason": "no vulnerable CPE term was satisfied",
                                    },
                                ))
                    else:
                        for row, matched, _ in config_terms:
                            for installation in matched:
                                if installation["asset_id"] != asset_id:
                                    continue
                                represented_installations.add(installation["installation_id"])
                                records.append(_exposure_record(
                                    installation,
                                    cve_id=cve_id,
                                    status="configuration_not_satisfied",
                                    term_row=row,
                                    evidence={
                                        "configuration_evaluation": "not_satisfied",
                                        "reason": "complete configuration tree did not pass",
                                    },
                                ))

            if not configs_by_cve.get(cve_id):
                for row, matched, _ in terms_by_cve.get(cve_id, []):
                    for installation in matched:
                        represented_installations.add(installation["installation_id"])
                        records.append(_exposure_record(
                            installation,
                            cve_id=cve_id,
                            status="missing_configuration",
                            term_row=row,
                            evidence={"reason": "NVD configuration tree unavailable"},
                        ))

        for row, unsupported_installations, _ in potential_unsupported_terms:
            for installation in unsupported_installations:
                represented_installations.add(installation["installation_id"])
                records.append(_exposure_record(
                    installation,
                    cve_id=str(row["cve_id"]),
                    status="unsupported_matching",
                    term_row=row,
                    evidence={
                        "reason": "existing matcher cannot compare the installed version",
                        "version_boundaries_source": "NVD cve_cpe_matches",
                    },
                ))

        for installation in software_rows:
            if installation["installation_id"] in represented_installations:
                continue
            parts = _cpe_product_parts(installation.get("cpe23_uri", ""))
            status = "unresolved_product" if parts is None else "no_candidate_match_not_cleared"
            records.append(_exposure_record(
                installation,
                cve_id=None,
                status=status,
                evidence={
                    "reason": (
                        "invalid or unsupported installed CPE 2.3 value"
                        if parts is None
                        else "no supported local NVD term match; this is not a safety determination"
                    )
                },
            ))

        _progress(
            "Configuration evaluation complete",
            started,
            f"{len(records):,} output evidence rows; "
            f"{len(represented_installations):,} installations have candidate evidence",
        )
        exposure_df = _make_output_dataframe(spark, records)

        print("[4/7] Filtering CPE product associations to matched inventory terms...", flush=True)
        associations_source = _read_parquet(spark, associations_path)
        association_required = {*_TERM_KEY_COLUMNS, "cpeNameId", "cpeName"}
        _validate_columns(
            associations_source,
            association_required,
            "Integrated CPE product associations",
        )
        association_columns = [
            *_TERM_KEY_COLUMNS,
            "cpeNameId",
            "cpeName",
            *(
                ["deprecated"]
                if "deprecated" in associations_source.columns
                else []
            ),
            *(["titles"] if "titles" in associations_source.columns else []),
        ]
        association_df = associations_source.select(
            *association_columns,
        )
        installed_cpes = spark.createDataFrame(
            [
                (row["installation_id"], row.get("cpe23_uri", "").lower())
                for row in software_rows
                if row.get("cpe23_uri")
            ],
            ["installation_id", "_installed_cpe_name"],
        ).distinct()
        output_keys = exposure_df.filter(F.col("cve_id").isNotNull()).select(
            *_TERM_KEY_COLUMNS
        ).distinct()
        associated_products = (
            add_cpe_fields(association_df, F.col("cpeName"))
            .join(
                F.broadcast(inventory_keys),
                ["_cpe_part", "_cpe_vendor", "_cpe_product"],
                "inner",
            )
            .join(
                F.broadcast(installed_cpes),
                F.lower(F.col("cpeName")) == F.col("_installed_cpe_name"),
                "inner",
            )
            .join(F.broadcast(output_keys), _TERM_KEY_COLUMNS, "inner")
        )
        print("Physical plan for inventory-matched CPE association join:", flush=True)
        associated_products.explain("simple")
        association_aggs = [
            F.countDistinct("cpeNameId")
            .cast("int")
            .alias("cpe_name_association_count"),
            F.first("cpeNameId", ignorenulls=True).alias("cpe_name_id"),
            F.first("cpeName", ignorenulls=True).alias("cpe_name"),
        ]
        if "deprecated" in association_columns:
            association_aggs.append(
                F.first("deprecated", ignorenulls=True).alias("product_deprecated")
            )
        if "titles" in association_columns:
            association_aggs.append(
                F.to_json(F.first("titles", ignorenulls=True)).alias("product_titles")
            )
        associated_products = associated_products.groupBy(
            *_TERM_KEY_COLUMNS, "installation_id"
        ).agg(*association_aggs)
        if "product_deprecated" not in associated_products.columns:
            associated_products = associated_products.withColumn(
                "product_deprecated", F.lit(None).cast(BooleanType())
            )
        if "product_titles" not in associated_products.columns:
            associated_products = associated_products.withColumn(
                "product_titles", F.lit(None).cast(StringType())
            )
        exposure_df = (
            exposure_df
            .drop(
                "cpe_name_association_count",
                "cpe_name_id",
                "cpe_name",
                "product_deprecated",
                "product_titles",
            )
            .join(
                associated_products,
                [*_TERM_KEY_COLUMNS, "installation_id"],
                "left",
            )
            .withColumn(
                "cpe_name_association_count",
                F.coalesce(F.col("cpe_name_association_count"), F.lit(0)),
            )
            .withColumn(
                "applicability_status",
                F.when(
                    (F.col("applicability_status") == "confirmed_match")
                    & (F.col("cpe_name_association_count") == 0),
                    F.lit("unresolved_product"),
                ).otherwise(F.col("applicability_status")),
            )
        )
        _progress("CPE association evidence joined", started)

        print("[5/7] Enriching applicability rows with CVSS and KEV evidence...", flush=True)
        core_df = _read_parquet(spark, core_path).select(
            "cve_id", "cvss_score", "cvss_version"
        ).dropDuplicates(["cve_id"])
        exposure_df = exposure_df.drop("cvss_score").join(
            core_df, "cve_id", "left"
        ).select(
            *[
                F.col(column)
                for column in EXPOSURE_SCHEMA.fieldNames()
                if column not in {"cvss_score", "known_exploited", "kev_date_added"}
            ],
            F.col("cvss_score").cast("string").alias("cvss_score"),
            F.lit(None).cast("boolean").alias("known_exploited"),
            F.lit(None).cast("string").alias("kev_date_added"),
        )
        if kev_jsonl.is_file():
            kev_df = spark.read.json(str(kev_jsonl)).select("cve_id", "date_added")
            exposure_df = (
                exposure_df.drop("known_exploited", "kev_date_added")
                .join(kev_df, "cve_id", "left")
                .withColumn("known_exploited", F.col("date_added").isNotNull())
                .withColumnRenamed("date_added", "kev_date_added")
            )
        else:
            print(
                f"WARNING: KEV snapshot not found; known_exploited is unavailable: {kev_jsonl}",
                flush=True,
            )

        exposure_df = exposure_df.persist(StorageLevel.DISK_ONLY)
        summary_row = exposure_df.agg(
            F.countDistinct("asset_id").alias("total_assets"),
            F.countDistinct("installation_id").alias("total_software_records"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status") == "confirmed_match",
                    F.col("installation_id"),
                )
            ).alias("confirmed_affected_software_records"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status") == "confirmed_match",
                    F.concat_ws("::", "installation_id", "cve_id"),
                )
            ).alias("confirmed_installation_cve_pairs"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status") == "confirmed_match",
                    F.col("asset_id"),
                )
            ).alias("distinct_affected_assets"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status") == "confirmed_match",
                    F.col("cve_id"),
                )
            ).alias("distinct_cves_affecting_inventory"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status").isin(
                        "unresolved_product",
                        "unsupported_matching",
                        "pending_manual_review",
                        "missing_configuration",
                        "no_candidate_match_not_cleared",
                    ),
                    F.col("installation_id"),
                )
            ).alias("unresolved_software_records"),
            F.countDistinct(
                F.when(
                    F.col("applicability_status") == "configuration_not_satisfied",
                    F.col("installation_id"),
                )
            ).alias("software_with_configuration_not_satisfied_candidates"),
        ).first().asDict()
        summary = {
            "project": "PRIORIS",
            "dataset": "enterprise inventory vulnerability exposure candidates",
            "inventory_directory": str(inventory_dir),
            "integration_directory": str(integration_dir),
            "nvd_tables_directory": str(nvd_tables_dir),
            "kev_snapshot": str(kev_jsonl) if kev_jsonl.is_file() else None,
            "execution": {
                "spark_master": "local[2]",
                "spark_version": spark.version,
                "python_executable": python_executable,
                "association_broadcast": False,
                "version_and_tree_semantics": "src.match_vulnerabilities helpers",
            },
            **{
                key: int(value or 0)
                for key, value in summary_row.items()
            },
            "applicability_status_counts": {
                row["applicability_status"]: int(row["count"])
                for row in exposure_df.groupBy("applicability_status").count().collect()
            },
            "elapsed_seconds_before_output": round(time.perf_counter() - started, 3),
            "limitations": [
                "The installed inventories are synthetic project fixtures, not a production CMDB.",
                "No candidate match or missing CPE association is not proof that software is safe.",
                "Confirmed means the existing local configuration evaluator passed; it is not independently verified production exposure.",
                "KEV absence is interpreted only against the dated local KEV snapshot.",
            ],
        }
        summary["total_assets"] = int(total_assets)
        summary["total_software_records"] = int(total_software)

        output_dir.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(
            prefix=".prioris-enterprise-exposure-",
            dir=output_dir.parent,
        ))
        print(
            f"[6/7] Writing exposure output to staging: {staging_dir}",
            flush=True,
        )
        output_rows = exposure_df.count()
        _write_dataframe_bounded(
            exposure_df,
            staging_dir / "enterprise_exposure",
            output_rows,
            partitions=8,
            batch_size=2_000,
        )
        _write_summary(staging_dir / "summary.json", summary)
        exposure_df.unpersist()
        spark.stop()
        print("[7/7] Publishing verified output directory...", flush=True)
        os.rename(staging_dir, output_dir)
        published = True
        summary["output_directory"] = str(output_dir)
        summary["exposure_rows"] = output_rows
        summary["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2),
            encoding="utf-8",
        )
        _progress(
            "Exposure output published",
            started,
            f"{output_rows:,} rows; {output_dir}",
        )
        return summary
    finally:
        if not published:
            spark.stop()
            if staging_dir is not None and staging_dir.exists():
                import shutil

                shutil.rmtree(staging_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Match enterprise software inventory to integrated NVD/CPE data."
    )
    parser.add_argument("--inventory-dir", type=Path, default=DEFAULT_INVENTORY_DIR)
    parser.add_argument("--integration-dir", type=Path, default=DEFAULT_INTEGRATION_DIR)
    parser.add_argument("--nvd-tables-dir", type=Path, default=DEFAULT_NVD_TABLES_DIR)
    parser.add_argument("--kev-jsonl", type=Path, default=DEFAULT_KEV_JSONL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)
    summary = run_exposure_matching(
        inventory_dir=args.inventory_dir,
        integration_dir=args.integration_dir,
        nvd_tables_dir=args.nvd_tables_dir,
        kev_jsonl=args.kev_jsonl,
        output_dir=args.output_dir,
    )
    print(json.dumps(summary, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
