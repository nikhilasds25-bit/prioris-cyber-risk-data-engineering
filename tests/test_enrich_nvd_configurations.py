import hashlib
import json
import tempfile
import unittest
import contextlib
import csv
import io
from pathlib import Path
from unittest.mock import Mock, patch

from src.enrich_nvd_configurations import (
    NvdClient,
    classify_record,
    criterion_ids_without_configurations,
    write_classification_report,
)
from src.match_vulnerabilities import enrichment_configuration_paths, main


class NvdConfigurationEnrichmentTests(unittest.TestCase):
    def test_classifies_recovered_configuration_separately_from_products(self):
        cve = {
            "id": "CVE-TEST-1",
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }],
                }]
            }],
            "containers": {"cna": {"affected": [{"vendor": "example"}]}},
        }
        classification, configurations, products = classify_record(cve, [])
        self.assertEqual(classification, "configuration_recovered")
        self.assertEqual(len(configurations), 1)
        self.assertEqual(products, 1)

    def test_classifies_non_configuration_evidence_without_making_a_tree(self):
        products_only = {
            "id": "CVE-TEST-2",
            "containers": {"cna": {"affected": [{"vendor": "example"}]}},
        }
        self.assertEqual(classify_record(products_only, [])[:2], ("affected_products_only", []))

        criteria_only = {"id": "CVE-TEST-3"}
        self.assertEqual(
            classify_record(criteria_only, [{"matchCriteriaId": "example"}])[:2],
            ("criteria_only", []),
        )

    def test_classifies_absent_malformed_and_failed_evidence_conservatively(self):
        self.assertEqual(
            classify_record({"id": "CVE-TEST-4"}, [])[:2],
            ("no_usable_configuration", []),
        )
        self.assertEqual(
            classify_record({"id": "CVE-TEST-5", "configurations": ["bad"]}, [])[:2],
            ("pending_review", []),
        )
        self.assertEqual(classify_record(None, [], response_error=True)[:2], ("api_error", []))

    def test_extracts_only_well_formed_match_criteria_ids(self):
        identifier = "01234567-89ab-cdef-0123-456789abcdef"
        record = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"matchCriteriaId": identifier},
                                {"matchCriteriaId": "not-a-uuid"},
                            ]
                        }
                    ]
                }
            ]
        }
        self.assertEqual(criterion_ids_without_configurations(record), [identifier])

    def test_nvd_client_retries_rate_limited_requests(self):
        limited = Mock(status_code=429, content=b'{"message":"rate limited"}')
        limited.headers = {"Retry-After": "0"}
        limited.url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        success = Mock(status_code=200, content=b'{"vulnerabilities":[]}')
        success.url = limited.url
        client = NvdClient({})
        client.session = Mock()
        client.session.get.side_effect = [limited, success]
        with patch("src.enrich_nvd_configurations.time.sleep"):
            status, body, _, requested_at = client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                {"cveId": "CVE-TEST-1"},
            )
        self.assertEqual(status, 200)
        self.assertEqual(body, success.content)
        self.assertTrue(requested_at)
        self.assertEqual(client.session.get.call_count, 2)

    def test_writes_one_auditable_classification_row_per_cve(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            manifest = {
                "records": [{
                    "cve_id": "CVE-TEST-6",
                    "classification": "no_usable_configuration",
                    "http_status": 200,
                    "match_criteria_ids": [],
                    "sha256": "ab" * 32,
                }]
            }
            report = write_classification_report(output, manifest)
            with report.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["cve_id"], "CVE-TEST-6")
            self.assertEqual(rows[0]["classification"], "no_usable_configuration")
            self.assertEqual(rows[0]["sha256"], "ab" * 32)

    def test_matcher_verifies_recovered_response_hash_and_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response_path = root / "responses" / "cve" / "CVE-TEST-1.json"
            response_path.parent.mkdir(parents=True)
            response = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-TEST-1",
                            "configurations": [{"nodes": [{"operator": "OR"}]}],
                        }
                    }
                ]
            }
            payload = json.dumps(response).encode("utf-8")
            response_path.write_bytes(payload)
            manifest = {
                "source_snapshot_date": "2026-10-19",
                "records": [
                    {
                        "cve_id": "CVE-TEST-1",
                        "classification": "configuration_recovered",
                        "http_status": 200,
                        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-TEST-1",
                        "file": "responses/cve/CVE-TEST-1.json",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ],
            }
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(
                enrichment_configuration_paths(root, "2026-10-19"),
                [response_path],
            )

            manifest["records"][0]["sha256"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                enrichment_configuration_paths(root, "2026-10-19")

    def test_matcher_rejects_wrong_source_snapshot_date(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text(
                json.dumps({"source_snapshot_date": "2026-10-18", "records": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "does not match"):
                enrichment_configuration_paths(root, "2026-10-19")

    def test_matcher_uses_only_provenance_verified_recovered_configurations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            date = "2026-10-19"
            processed = root / "data" / "processed" / date
            raw = root / "data" / "raw" / date
            inventory = root / "data" / "synthetic"
            enrichment = root / "data" / "enrichment" / "2026-10-24"
            for directory in (processed, raw, inventory):
                directory.mkdir(parents=True)
            (inventory / "enterprise_assets.csv").write_text(
                "asset_id,asset_type,data_origin\nASSET-1,server,synthetic\n",
                encoding="utf-8",
            )
            (inventory / "software_inventory.csv").write_text(
                "installation_id,asset_id,software_vendor,software_product,"
                "software_name,software_version,cpe23_uri,data_origin\n"
                "SW-1,ASSET-1,acme,widget,widget,2.0,"
                "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*,synthetic\n",
                encoding="utf-8",
            )
            (processed / "nvd_cves.jsonl").write_text(
                json.dumps({
                    "cve_id": "CVE-TEST-RECOVERED",
                    "cvss_score": 5.0,
                    "has_configurations": False,
                }) + "\n",
                encoding="utf-8",
            )
            (processed / "cisa_kev.jsonl").write_text("", encoding="utf-8")
            (raw / "nvd_general.json").write_text(
                json.dumps({"vulnerabilities": []}), encoding="utf-8"
            )
            (raw / "nvd_known_exploited.json").write_text(
                json.dumps({"vulnerabilities": []}), encoding="utf-8"
            )

            response = {
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-TEST-RECOVERED",
                        "configurations": [{
                            "nodes": [{
                                "operator": "OR",
                                "cpeMatch": [{
                                    "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                }],
                            }],
                        }],
                    },
                }],
            }
            response_path = enrichment / "responses" / "cve" / "CVE-TEST-RECOVERED.json"
            response_path.parent.mkdir(parents=True)
            payload = json.dumps(response).encode("utf-8")
            response_path.write_bytes(payload)
            (enrichment / "manifest.json").write_text(
                json.dumps({
                    "source_snapshot_date": date,
                    "records": [{
                        "cve_id": "CVE-TEST-RECOVERED",
                        "classification": "configuration_recovered",
                        "http_status": 200,
                        "url": (
                            "https://services.nvd.nist.gov/rest/json/cves/2.0?"
                            "cveId=CVE-TEST-RECOVERED"
                        ),
                        "file": "responses/cve/CVE-TEST-RECOVERED.json",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }],
                }),
                encoding="utf-8",
            )
            output = root / "results" / "enriched"
            with patch("src.match_vulnerabilities.ROOT", root), contextlib.redirect_stdout(
                io.StringIO()
            ):
                self.assertEqual(main([
                    "--date", date,
                    "--enrichment-dir", str(enrichment),
                    "--output-dir", str(output),
                ]), 0)

            with (output / "cve_configuration_audit.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                audit = next(csv.DictReader(handle))
            self.assertEqual(audit["evaluation_status"], "confirmed_candidate_match")
            self.assertEqual(audit["matched_asset_count_after_tree_evaluation"], "1")
            self.assertEqual(audit["configuration_source"], "nvd_api_enrichment")
            summary = json.loads((output / "phase3_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["input_counts"]["nvd_enrichment_configuration_records"], 1)
            self.assertEqual(summary["input_counts"]["nvd_enriched_cve_ids"], ["CVE-TEST-RECOVERED"])
            self.assertTrue(summary["input_counts"]["nvd_enrichment_manifest_sha256"])


if __name__ == "__main__":
    unittest.main()
