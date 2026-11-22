import unittest

from src.match_vulnerabilities import (
    InventoryIndex,
    audit_status,
    classify_evaluation_status,
)


class UnsupportedVersionDiagnosticTests(unittest.TestCase):
    def test_openssl_heartbleed_known_release_order_is_scoped_and_matches(self):
        software = [{
            "installation_id": "openssl-1",
            "asset_id": "asset-1",
            "cpe23_uri": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        }]
        term = {
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "1.0.1",
            "versionEndExcluding": "1.0.1g",
            "matchCriteriaId": "9EE79AC6-5484-4A53-8333-373DAD1B5649",
        }

        inventory = InventoryIndex(software)

        self.assertEqual(
            [row["installation_id"] for rows in inventory.matches(term).values() for row in rows],
            ["openssl-1"],
        )
        self.assertEqual(inventory.unsupported_version_asset_ids(term), set())

    def test_openssl_exception_does_not_generalize_to_other_suffixes(self):
        software = [{
            "installation_id": "openssl-1",
            "asset_id": "asset-1",
            "cpe23_uri": "cpe:2.3:a:openssl:openssl:1.0.1e:*:*:*:*:*:*:*",
        }]
        term = {
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "1.0.1",
            "versionEndExcluding": "1.0.1g",
            "matchCriteriaId": "9EE79AC6-5484-4A53-8333-373DAD1B5649",
        }

        inventory = InventoryIndex(software)

        self.assertEqual(inventory.matches(term), {})
        self.assertEqual(inventory.unsupported_version_asset_ids(term), {"asset-1"})

    def test_different_numeric_component_lengths_are_not_assumed_equivalent(self):
        software = [{
            "installation_id": "widget-1",
            "asset_id": "asset-1",
            "cpe23_uri": "cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*",
        }]
        term = {
            "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionEndIncluding": "1.0",
        }

        inventory = InventoryIndex(software)

        self.assertEqual(inventory.matches(term), {})
        self.assertEqual(inventory.unsupported_version_asset_ids(term), {"asset-1"})

    def test_unsupported_boundary_is_not_a_match_and_is_reported(self):
        software = [{
            "installation_id": "openssl-1",
            "asset_id": "asset-1",
            "cpe23_uri": "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*",
        }]
        term = {
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "1.0.1",
            "versionEndExcluding": "1.0.1g",
        }

        inventory = InventoryIndex(software)

        self.assertEqual(inventory.matches(term), {})
        self.assertEqual(inventory.unsupported_version_asset_ids(term), {"asset-1"})
        self.assertEqual(
            audit_status(1, 0, 0, True, unsupported_version_candidate_count=1),
            "unsupported_version_comparison_involved",
        )

    def test_numeric_dotted_range_is_not_marked_unsupported(self):
        software = [{
            "installation_id": "openssl-1",
            "asset_id": "asset-1",
            "cpe23_uri": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
        }]
        term = {
            "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "1.0.0",
            "versionEndExcluding": "1.0.2",
        }

        inventory = InventoryIndex(software)

        self.assertIn("asset-1", inventory.matches(term))
        self.assertEqual(inventory.unsupported_version_asset_ids(term), set())

    def test_evaluation_status_separates_candidate_no_match_unknown_and_missing(self):
        cases = [
            ((0, 0, 0, False), "missing_configuration_data"),
            ((1, 1, 0, False), "confirmed_candidate_match"),
            ((1, 0, 0, False), "evaluated_no_match"),
            ((1, 0, 1, False), "unsupported_version_comparison"),
            ((1, 1, 0, True), "pending_manual_review"),
            ((1, 1, 1, False), "pending_manual_review"),
        ]
        for (configurations, matches, unsupported, pending), expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    classify_evaluation_status(
                        configurations,
                        matches,
                        unsupported,
                        pending,
                    ),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
