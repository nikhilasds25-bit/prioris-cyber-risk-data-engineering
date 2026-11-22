import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.diagnose_affected_products import build_diagnostic, write_report


class AffectedProductsDiagnosticTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path]:
        enrichment = root / "enrichment"
        response_dir = enrichment / "responses" / "cve"
        response_dir.mkdir(parents=True)
        records = [
            (
                "CVE-TEST-1",
                {
                    "source": "test-source",
                    "affectedData": [{
                        "vendor": "Example",
                        "product": "Widget",
                        "packageName": "example-widget",
                        "defaultStatus": "unaffected",
                        "versions": [{
                            "version": "0",
                            "versionType": "custom",
                            "status": "affected",
                            "lessThanOrEqual": "2.0",
                            "changes": [{"at": "2.1", "status": "unaffected"}],
                        }],
                    }],
                },
            ),
            (
                "CVE-TEST-2",
                {
                    "source": "test-source",
                    "affectedData": [{
                        "vendor": "n/a",
                        "product": "n/a",
                        "versions": [{
                            "version": "n/a",
                            "status": "affected",
                        }],
                    }],
                },
            ),
        ]
        manifest_records = []
        classifications = []
        for cve_id, affected in records:
            payload = json.dumps({
                "vulnerabilities": [{
                    "cve": {"id": cve_id, "affected": [affected]},
                }],
            }).encode("utf-8")
            response_path = response_dir / f"{cve_id}.json"
            response_path.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            manifest_records.append({
                "cve_id": cve_id,
                "classification": "affected_products_only",
                "http_status": 200,
                "file": f"responses/cve/{cve_id}.json",
                "sha256": digest,
            })
            classifications.append({
                "cve_id": cve_id,
                "classification": "affected_products_only",
                "http_status": "200",
                "sha256": digest,
            })
        (enrichment / "manifest.json").write_text(json.dumps({
            "source_snapshot_date": "2026-10-19",
            "enrichment_date": "2026-10-24",
            "records": manifest_records,
        }), encoding="utf-8")
        with (enrichment / "cve_classification.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=list(classifications[0]))
            writer.writeheader()
            writer.writerows(classifications)
        inventory = root / "software_inventory.csv"
        inventory.write_text(
            "software_product,software_name\nother,Other product\n",
            encoding="utf-8",
        )
        return enrichment, inventory

    def test_profiles_custom_ranges_without_creating_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            enrichment, inventory = self._fixture(root)

            summary = build_diagnostic(enrichment, inventory)

            self.assertEqual(summary["input_affected_products_only_cve_count"], 2)
            self.assertEqual(summary["saved_response_count_hash_verified"], 2)
            self.assertEqual(
                summary["candidate_records_for_separate_product_version_study"], 1
            )
            self.assertEqual(
                summary["cves_with_exact_product_identifier_overlap_in_inventory"], 0
            )
            self.assertEqual(summary["defensible_vulnerability_matches_produced"], 0)
            self.assertEqual(summary["affected_version_entry_count"], 2)
            self.assertEqual(summary["bounded_version_entry_count"], 1)
            self.assertEqual(summary["unaffected_change_count"], 1)
            self.assertEqual(summary["version_status_counts"], {"affected": 2})
            self.assertEqual(summary["version_type_counts"], {
                "custom": 1,
                "unspecified": 1,
            })

    def test_rejects_response_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            enrichment, inventory = self._fixture(root)
            response = enrichment / "responses" / "cve" / "CVE-TEST-1.json"
            response.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                build_diagnostic(enrichment, inventory)

    def test_report_refuses_to_replace_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            existing = output / "affected_products_diagnostic.json"
            existing.write_text("preserve", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                write_report({"records": []}, output)
            self.assertEqual(existing.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
