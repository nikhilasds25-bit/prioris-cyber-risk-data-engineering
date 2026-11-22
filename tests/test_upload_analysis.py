import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from src.upload_analysis import (
    ASSET_TEMPLATE_COLUMNS,
    SOFTWARE_TEMPLATE_COLUMNS,
    analyze_uploaded_inventory,
    dataframe_csv_bytes,
    load_source_snapshot,
    validate_inventory_csvs,
)


ASSET_HEADERS = [
    "asset_id",
    "asset_type",
    "business_unit",
    "criticality",
    "exposure",
    "environment",
    "data_origin",
]
SOFTWARE_HEADERS = [
    "installation_id",
    "asset_id",
    "software_vendor",
    "software_product",
    "software_name",
    "software_version",
    "cpe23_uri",
    "data_origin",
]
CVE_ID = "CVE-2025-1001"
SUPPORTED_CPE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def csv_bytes(fields: list[str], rows: list[dict[str, str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def asset_row(
    asset_id: str = "ASSET-1",
    *,
    criticality: str = "high",
    exposure: str = "internet-facing",
) -> dict[str, str]:
    return {
        "asset_id": asset_id,
        "asset_type": "server",
        "business_unit": "Engineering",
        "criticality": criticality,
        "exposure": exposure,
        "environment": "production",
        "data_origin": "visitor_upload",
    }


def software_row(
    *,
    installation_id: str = "INSTALL-1",
    asset_id: str = "ASSET-1",
    version: str = "1.0",
    cpe: str = SUPPORTED_CPE,
) -> dict[str, str]:
    return {
        "installation_id": installation_id,
        "asset_id": asset_id,
        "software_vendor": "Acme",
        "software_product": "Widget",
        "software_name": "Acme Widget",
        "software_version": version,
        "cpe23_uri": cpe,
        "data_origin": "visitor_upload",
    }


def upload_csvs(
    assets: list[dict[str, str]] | None = None,
    software: list[dict[str, str]] | None = None,
) -> tuple[bytes, bytes]:
    return (
        csv_bytes(ASSET_HEADERS, assets or [asset_row()]),
        csv_bytes(SOFTWARE_HEADERS, software or [software_row()]),
    )


class UploadedInventoryValidationTests(unittest.TestCase):
    def test_template_schemas_match_existing_project_inventory_headers(self):
        root = Path(__file__).resolve().parents[1]
        for filename, expected in (
            ("enterprise_assets.csv", ASSET_TEMPLATE_COLUMNS),
            ("software_inventory.csv", SOFTWARE_TEMPLATE_COLUMNS),
        ):
            with (root / "data" / "synthetic" / filename).open(
                encoding="utf-8-sig",
                newline="",
            ) as handle:
                headers = next(csv.reader(handle))
            self.assertEqual(expected, headers)

    def test_validates_project_schema_and_accepts_cpe_23_inventory(self):
        assets, software = upload_csvs()
        result = validate_inventory_csvs(assets, software)

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.asset_row_count, 1)
        self.assertEqual(result.software_row_count, 1)

    def test_rejects_empty_files_and_missing_columns(self):
        result = validate_inventory_csvs(
            b"",
            csv_bytes(["installation_id", "asset_id"], [{"installation_id": "I1", "asset_id": "A1"}]),
        )
        self.assertFalse(result.valid)
        self.assertTrue(any("file is empty" in error for error in result.errors))

        missing = validate_inventory_csvs(
            csv_bytes(["asset_id"], [{"asset_id": "A1"}]),
            csv_bytes(["installation_id", "asset_id"], [{"installation_id": "I1", "asset_id": "A1"}]),
        )
        self.assertTrue(any("criticality" in error for error in missing.errors))
        self.assertTrue(any("cpe23_uri" in error for error in missing.errors))

    def test_rejects_duplicate_asset_ids_and_orphan_software(self):
        assets, software = upload_csvs(
            [asset_row(), asset_row()],
            [software_row(asset_id="UNKNOWN")],
        )
        result = validate_inventory_csvs(assets, software)

        self.assertFalse(result.valid)
        self.assertTrue(any("duplicate asset_id" in error for error in result.errors))
        self.assertTrue(any("does not exist" in error for error in result.errors))

    def test_rejects_invalid_context_and_product_version_cpe_fields(self):
        assets, software = upload_csvs(
            [asset_row(criticality="urgent", exposure="public")],
            [software_row(version="2.0", cpe="not-a-cpe")],
        )
        result = validate_inventory_csvs(assets, software)

        self.assertFalse(result.valid)
        self.assertTrue(any("unsupported criticality" in error for error in result.errors))
        self.assertTrue(any("unsupported exposure" in error for error in result.errors))
        self.assertTrue(any("valid CPE 2.3" in error for error in result.errors))

    def test_rejects_wildcard_version_and_version_cpe_mismatch(self):
        assets, software = upload_csvs(
            software=[software_row(version="*", cpe="cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")]
        )
        result = validate_inventory_csvs(assets, software)
        self.assertTrue(any("version must be explicit" in error for error in result.errors))

        assets, software = upload_csvs(
            software=[software_row(version="2.0", cpe=SUPPORTED_CPE)]
        )
        result = validate_inventory_csvs(assets, software)
        self.assertTrue(any("does not match the CPE version" in error for error in result.errors))

    def test_rejects_nonconcrete_cpe_product_identifiers_and_duplicate_installations(self):
        assets, software = upload_csvs(
            software=[
                software_row(
                    installation_id="I1",
                    cpe="cpe:2.3:a:*:widget:1.0:*:*:*:*:*:*:*",
                ),
                software_row(installation_id="I1", asset_id="ASSET-1"),
            ]
        )
        result = validate_inventory_csvs(assets, software)
        self.assertTrue(any("CPE vendor identifier" in error for error in result.errors))
        self.assertTrue(any("duplicate installation_id" in error for error in result.errors))


class UploadedAnalysisWorkflowTests(unittest.TestCase):
    def _staged_project(self, root: Path, *, version_semantics: str = "exact", cvss: str = "8.0") -> Path:
        raw_dir = root / "data" / "raw" / "2026-10-19"
        processed_dir = root / "data" / "processed" / "2026-10-19"
        raw_dir.mkdir(parents=True)
        processed_dir.mkdir(parents=True)

        criterion = {
            "vulnerable": True,
            "criteria": (
                SUPPORTED_CPE
                if version_semantics == "exact"
                else "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
            ),
        }
        if version_semantics == "unsupported":
            criterion["versionStartIncluding"] = "1.0"
        cve = {
            "id": CVE_ID,
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [criterion],
                }]
            }],
        }
        (raw_dir / "nvd_general.json").write_text(
            json.dumps({"vulnerabilities": [{"cve": cve}]}),
            encoding="utf-8",
        )
        (raw_dir / "nvd_known_exploited.json").write_text(
            json.dumps({"vulnerabilities": []}),
            encoding="utf-8",
        )
        (raw_dir / "manifest.json").write_text(json.dumps({
            "snapshot_folder": "2026-10-19",
            "retrieved_at_utc": "2026-10-19T00:00:00+00:00",
            "cisa_catalog_version": "fixture",
            "nvd_records": 1,
            "cisa_records": 1,
        }), encoding="utf-8")
        normalized = {
            "cve_id": CVE_ID,
            "description": "Fixture CVE",
            "cvss_score": cvss,
            "cvss_version": "3.1",
            "published": "2025-01-01T00:00:00.000",
            "has_configurations": True,
        }
        (processed_dir / "nvd_cves.jsonl").write_text(
            json.dumps(normalized) + "\n",
            encoding="utf-8",
        )
        (processed_dir / "cisa_kev.jsonl").write_text(
            json.dumps({"cve_id": CVE_ID, "date_added": "2025-01-02"}) + "\n",
            encoding="utf-8",
        )
        return root

    def test_upload_runs_real_staged_match_and_evidence_based_scoring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._staged_project(Path(temporary))
            protected = root / "results" / "older-report.csv"
            protected.parent.mkdir()
            protected.write_text("keep unchanged", encoding="utf-8")
            before = hashlib.sha256(protected.read_bytes()).hexdigest()
            assets, software = upload_csvs()

            result = analyze_uploaded_inventory(
                assets,
                software,
                project_root=root,
            )

            self.assertEqual(result.summary["snapshot_date"], "2026-10-19")
            self.assertEqual(result.summary["scored_relationship_count"], 1)
            finding = result.findings.iloc[0]
            self.assertEqual(finding["asset_id"], "ASSET-1")
            self.assertEqual(finding["cve_id"], CVE_ID)
            self.assertEqual(finding["risk_score"], 14.0)
            self.assertEqual(finding["severity_component"], 8.0)
            self.assertEqual(finding["kev_bonus_component"], 2.0)
            self.assertEqual(finding["criticality_component"], 2.0)
            self.assertEqual(finding["exposure_component"], 2.0)
            self.assertEqual(finding["source_evidence"]["phase3_audit_status"], "matched_assets_under_local_configuration_evaluation")
            self.assertEqual(result.summary["withheld_relationship_count"], 0)
            self.assertEqual(hashlib.sha256(protected.read_bytes()).hexdigest(), before)
            self.assertFalse((root / "results" / "prioris-upload").exists())

    def test_unsupported_version_comparison_is_withheld_not_scored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._staged_project(
                Path(temporary),
                version_semantics="unsupported",
            )
            assets, software = upload_csvs(
                software=[software_row(
                    version="1.0-alpha",
                    cpe="cpe:2.3:a:acme:widget:1.0-alpha:*:*:*:*:*:*:*",
                )]
            )
            result = analyze_uploaded_inventory(
                assets,
                software,
                project_root=root,
            )

        self.assertEqual(result.summary["scored_relationship_count"], 0)
        self.assertEqual(result.summary["withheld_relationship_count"], 1)
        withheld = result.audit.iloc[0]
        self.assertEqual(withheld["analysis_status"], "withheld")
        self.assertIn("Unsupported local version comparison", withheld["reason"])
        self.assertEqual(len(result.source_gaps), 1)
        self.assertEqual(
            result.source_gaps.iloc[0]["risk_scoring_disposition"],
            "withhold_pending_version_review",
        )

    def test_missing_cvss_evidence_is_retained_as_withheld(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._staged_project(Path(temporary), cvss="")
            assets, software = upload_csvs()
            result = analyze_uploaded_inventory(
                assets,
                software,
                project_root=root,
            )

        self.assertEqual(result.summary["scored_relationship_count"], 0)
        self.assertEqual(result.summary["withheld_relationship_count"], 1)
        self.assertIn("CVSS score is missing", result.audit.iloc[0]["reason"])

    def test_missing_staged_source_data_fails_explicitly_without_network_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(FileNotFoundError, "will not download"):
                load_source_snapshot(Path(temporary))

    def test_exports_are_csv_bytes_and_do_not_create_project_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self._staged_project(Path(temporary))
            assets, software = upload_csvs()
            result = analyze_uploaded_inventory(
                assets,
                software,
                project_root=root,
            )
            export = dataframe_csv_bytes(result.findings)
            parsed = list(csv.DictReader(io.StringIO(export.decode("utf-8"))))
            self.assertEqual(len(parsed), 1)
            self.assertEqual(json.loads(parsed[0]["installation_ids"]), ["INSTALL-1"])
            self.assertEqual(list((root / "results").iterdir()) if (root / "results").exists() else [], [])


if __name__ == "__main__":
    unittest.main()
