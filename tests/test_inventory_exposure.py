import unittest

from src.PRIORIS_inventory_exposure import _exposure_record, _term_applicability
from src.match_vulnerabilities import (
    InventoryIndex,
    configuration_manual_review_reasons,
    evaluate_configuration_indexed,
)


class InventoryExposureTests(unittest.TestCase):
    def setUp(self):
        self.installation = {
            "installation_id": "install-1",
            "asset_id": "asset-1",
            "software_name": "Apache HTTP Server",
            "software_product": "http_server",
            "software_version": "2.4.51",
            "cpe23_uri": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
        }
        self.term = {
            "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            "match_criteria_id": "match-1",
            "matchCriteriaId": "match-1",
            "vulnerable": True,
            "version_start_including": "2.4.50",
            "version_end_excluding": "2.4.52",
        }

    def test_existing_matcher_version_semantics_are_reused(self):
        self.assertEqual(
            _term_applicability(self.term, self.installation),
            "matched",
        )
        outside_range = {
            **self.installation,
            "software_version": "2.4.49",
            "cpe23_uri": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        }
        self.assertEqual(
            _term_applicability(self.term, outside_range),
            "not_matching",
        )

    def test_configuration_provenance_and_version_bounds_are_preserved(self):
        term_row = {
            "cve_id": "CVE-TEST-1",
            "source_year": 2026,
            "configuration_index": 3,
            "node_path": "0/1",
            "match_index": 2,
            "match_criteria_id": "match-1",
            "criteria": self.term["criteria"],
            "vulnerable": True,
            "version_start_including": "2.4.50",
            "version_start_excluding": None,
            "version_end_including": None,
            "version_end_excluding": "2.4.52",
            "raw_match_json": '{"vulnerable":true}',
        }
        record = _exposure_record(
            self.installation,
            cve_id="CVE-TEST-1",
            status="confirmed_match",
            term_row=term_row,
        )

        self.assertEqual(record["cve_id"], "CVE-TEST-1")
        self.assertEqual(record["asset_id"], "asset-1")
        self.assertEqual(record["configuration_index"], 3)
        self.assertEqual(record["node_path"], "0/1")
        self.assertEqual(record["match_index"], 2)
        self.assertTrue(record["vulnerable"])
        self.assertEqual(record["version_start_including"], "2.4.50")
        self.assertEqual(record["version_end_excluding"], "2.4.52")
        self.assertEqual(record["raw_match_json"], '{"vulnerable":true}')

    def test_full_configuration_evaluation_preserves_operator_and_vulnerable_flag(self):
        inventory = InventoryIndex([self.installation])
        config = {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [self.term],
                }
            ],
        }

        passed, pairs = evaluate_configuration_indexed(
            config,
            "asset-1",
            inventory,
        )

        self.assertTrue(passed)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(configuration_manual_review_reasons(config), [])

        non_vulnerable_config = {
            "operator": "OR",
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [{**self.term, "vulnerable": False}],
                }
            ],
        }
        passed, pairs = evaluate_configuration_indexed(
            non_vulnerable_config,
            "asset-1",
            InventoryIndex([self.installation]),
        )
        self.assertTrue(passed)
        self.assertEqual(pairs, [])


if __name__ == "__main__":
    unittest.main()
