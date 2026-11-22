import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.validate_custom_version_semantics import (
    build_validation_report,
    write_report,
)


class CustomVersionSemanticsValidationTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path]:
        enrichment = root / "enrichment"
        response_dir = enrichment / "responses" / "cve"
        response_dir.mkdir(parents=True)
        manifest_records = []
        classification_rows = []
        diagnostic_records = []
        for cve_id, version, changes in (
            ("CVE-TEST-1", "0", [{"at": "2.1", "status": "unaffected"}]),
            ("CVE-TEST-2", "n/a", []),
        ):
            version_entry = {
                "version": version,
                "lessThanOrEqual": "2.0",
                "versionType": "custom",
                "status": "affected",
            }
            if changes:
                version_entry["changes"] = changes
            product = {
                "vendor": "Example",
                "product": "Widget",
                "packageName": "example-widget",
                "collectionURL": "https://wordpress.org/plugins",
                "defaultStatus": "unaffected",
                "versions": [version_entry],
            }
            cve_record = {
                "id": cve_id,
                "sourceIdentifier": "audit@patchstack.com",
                "affected": [{
                    "source": "audit@patchstack.com",
                    "affectedData": [product],
                }],
            }
            payload = json.dumps({
                "vulnerabilities": [{"cve": cve_record}],
            }).encode("utf-8")
            relative = f"responses/cve/{cve_id}.json"
            (enrichment / relative).write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            manifest_records.append({
                "cve_id": cve_id,
                "classification": "affected_products_only",
                "http_status": 200,
                "file": relative,
                "url": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                "retrieved_at_utc": "2026-10-24T08:25:30+00:00",
                "sha256": digest,
            })
            classification_rows.append({
                "cve_id": cve_id,
                "classification": "affected_products_only",
                "http_status": "200",
                "sha256": digest,
            })
            diagnostic_records.append({
                "cve_id": cve_id,
                "products": [{
                    "source": "audit@patchstack.com",
                    **product,
                }],
            })
        (enrichment / "manifest.json").write_text(json.dumps({
            "source_snapshot_date": "2026-10-19",
            "enrichment_date": "2026-10-24",
            "records": manifest_records,
        }), encoding="utf-8")
        with (enrichment / "cve_classification.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=list(classification_rows[0]))
            writer.writeheader()
            writer.writerows(classification_rows)
        diagnostic = root / "affected_products_diagnostic.json"
        diagnostic.write_text(json.dumps({
            "report": "saved_nvd_affected_products_diagnostic",
            "source_snapshot_date": "2026-10-19",
            "enrichment_date": "2026-10-24",
            "records": diagnostic_records,
        }), encoding="utf-8")
        return enrichment, diagnostic

    def test_preserves_exact_fields_and_stops_before_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            enrichment, diagnostic = self._fixture(root)

            report = build_validation_report(
                enrichment,
                diagnostic,
                expected_patchstack_count=2,
            )

            assessment = report["assessment"]
            self.assertEqual(assessment["patchstack_cve_count"], 2)
            self.assertEqual(assessment["records_with_provenance_verified_raw_fields"], 2)
            self.assertEqual(assessment["records_with_custom_version_type"], 2)
            self.assertEqual(assessment["records_testable_for_comparison_semantics"], 0)
            self.assertEqual(assessment["comparator_status"], "unverified")
            self.assertFalse(assessment["matching_performed"])
            first, second = report["records"]
            self.assertEqual(first["version"], "0")
            self.assertEqual(first["less_than"], None)
            self.assertEqual(first["less_than_or_equal"], "2.0")
            self.assertEqual(first["version_type"], "custom")
            self.assertEqual(first["status"], "affected")
            self.assertEqual(first["default_status"], "unaffected")
            self.assertEqual(first["changes"], [{"at": "2.1", "status": "unaffected"}])
            self.assertEqual(second["version"], "n/a")
            self.assertNotIn("changes", second["raw_version_entry"])
            self.assertEqual(first["affected_data_source"], "audit@patchstack.com")
            self.assertEqual(len(first["response_sha256"]), 64)

    def test_rejects_saved_response_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            enrichment, diagnostic = self._fixture(root)
            response = enrichment / "responses" / "cve" / "CVE-TEST-1.json"
            response.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                build_validation_report(
                    enrichment,
                    diagnostic,
                    expected_patchstack_count=2,
                )

    def test_refuses_to_overwrite_existing_validation_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            existing = output / "custom_version_semantics_validation.json"
            existing.write_text("preserve", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                write_report({"records": []}, output)
            self.assertEqual(existing.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
