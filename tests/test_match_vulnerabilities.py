import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.match_vulnerabilities import (
    InventoryIndex,
    audit_status,
    component_matches,
    configuration_manual_review_reasons,
    classify_evaluation_status,
    evaluate_configuration_indexed,
    main,
    unique_match_pairs,
)


def installation(
    installation_id: str,
    asset_id: str,
    vendor: str = "acme",
    product: str = "widget",
    version: str = "2.0",
    part: str = "a",
) -> dict[str, str]:
    return {
        "installation_id": installation_id,
        "asset_id": asset_id,
        "software_vendor": vendor,
        "software_product": product,
        "software_version": version,
        "cpe23_uri": f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
    }


def criterion(
    vendor: str = "acme",
    product: str = "widget",
    version: str = "*",
    vulnerable: bool = True,
    part: str = "a",
    **bounds: str,
) -> dict[str, object]:
    return {
        "criteria": f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        "vulnerable": vulnerable,
        **bounds,
    }


def configuration(*terms: dict[str, object], operator: str = "AND", negate: bool = False):
    return {
        "nodes": [{
            "operator": operator,
            "negate": negate,
            "cpeMatch": list(terms),
        }]
    }


class CpeMatchingTests(unittest.TestCase):
    def test_vendor_and_product_components_must_match(self):
        inventory = InventoryIndex([installation("i1", "a1")])
        self.assertIn("a1", inventory.matches(criterion()))
        self.assertNotIn("a1", inventory.matches(criterion(vendor="other")))
        self.assertNotIn("a1", inventory.matches(criterion(product="other")))

    def test_component_wildcards_match(self):
        self.assertTrue(component_matches("ac*", "Acme"))
        self.assertTrue(component_matches("wid?et", "widget"))
        inventory = InventoryIndex([installation("i1", "a1", vendor="acme-corp")])
        self.assertIn("a1", inventory.matches(criterion(vendor="acme*")))

    def test_escaped_wildcards_match_as_literals(self):
        self.assertTrue(component_matches(r"foo\*", "foo*"))
        self.assertFalse(component_matches(r"foo\*", "foobar"))
        self.assertTrue(component_matches(r"foo\?", "foo?"))
        self.assertFalse(component_matches(r"foo\?", "fooa"))

    def test_exact_version_matching(self):
        inventory = InventoryIndex([installation("i1", "a1", version="2.0")])
        self.assertIn("a1", inventory.matches(criterion(version="2.0")))
        self.assertNotIn("a1", inventory.matches(criterion(version="2.1")))

    def test_inclusive_and_exclusive_version_boundaries(self):
        inventory = InventoryIndex([installation("i1", "a1", version="2.0")])
        cases = [
            ({"versionStartIncluding": "2.0"}, True),
            ({"versionStartIncluding": "2.1"}, False),
            ({"versionStartExcluding": "2.0"}, False),
            ({"versionStartExcluding": "1.9"}, True),
            ({"versionEndIncluding": "2.0"}, True),
            ({"versionEndIncluding": "1.9"}, False),
            ({"versionEndExcluding": "2.0"}, False),
            ({"versionEndExcluding": "2.1"}, True),
        ]
        for bounds, expected in cases:
            with self.subTest(bounds=bounds):
                self.assertEqual(bool(inventory.matches(criterion(**bounds))), expected)

    def test_configuration_and_and_or_logic(self):
        inventory = InventoryIndex([
            installation("widget", "both", product="widget"),
            installation("gadget", "both", product="gadget"),
            installation("widget-only", "one", product="widget"),
        ])
        widget = criterion(product="widget")
        gadget = criterion(product="gadget")
        self.assertTrue(evaluate_configuration_indexed(
            configuration(widget, gadget, operator="AND"), "both", inventory
        )[0])
        self.assertFalse(evaluate_configuration_indexed(
            configuration(widget, gadget, operator="AND"), "one", inventory
        )[0])
        self.assertTrue(evaluate_configuration_indexed(
            configuration(widget, gadget, operator="OR"), "one", inventory
        )[0])

    def test_nvd_configuration_level_and_operator_requires_all_root_nodes(self):
        inventory = InventoryIndex([
            installation("widget", "complete", product="widget"),
            installation("os", "complete", part="o", product="os"),
            installation("widget-only", "incomplete", product="widget"),
        ])
        config = {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [criterion(product="widget")]},
                {"operator": "OR", "cpeMatch": [
                    criterion(product="os", vulnerable=False, part="o")
                ]},
            ],
        }
        self.assertTrue(evaluate_configuration_indexed(config, "complete", inventory)[0])
        self.assertFalse(evaluate_configuration_indexed(config, "incomplete", inventory)[0])

    def test_negated_configuration_is_withheld_for_manual_review(self):
        negated = configuration(criterion(), negate=True)
        self.assertIn(
            "negation_semantics_require_manual_review",
            configuration_manual_review_reasons(negated),
        )
        self.assertEqual(
            classify_evaluation_status(1, 0, 0, True),
            "pending_manual_review",
        )

    def test_nested_negated_support_node_is_withheld_for_manual_review(self):
        config = {
            "nodes": [{
                "operator": "AND",
                "cpeMatch": [criterion()],
                "nodes": [{
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [criterion(product="os", vulnerable=False)],
                }],
            }]
        }
        reasons = configuration_manual_review_reasons(config)
        self.assertIn("nested_node_shape_not_defined_in_nvd_api_schema", reasons)
        self.assertIn("negation_semantics_require_manual_review", reasons)

    def test_non_vulnerable_supporting_criterion_is_required_but_not_emitted(self):
        inventory = InventoryIndex([
            installation("vulnerable", "complete", product="widget"),
            installation("support", "complete", part="o", vendor="acme", product="os"),
            installation("vulnerable-only", "incomplete", product="widget"),
        ])
        vulnerable = criterion(product="widget", vulnerable=True)
        supporting = criterion(product="os", vulnerable=False, part="o")
        passed, pairs = evaluate_configuration_indexed(
            configuration(vulnerable, supporting), "complete", inventory
        )
        self.assertTrue(passed)
        self.assertEqual([row["installation_id"] for row, _ in pairs], ["vulnerable"])
        self.assertFalse(evaluate_configuration_indexed(
            configuration(vulnerable, supporting), "incomplete", inventory
        )[0])

    def test_no_match_and_missing_configuration_statuses(self):
        inventory = InventoryIndex([installation("i1", "a1")])
        no_match = configuration(criterion(product="missing"))
        self.assertEqual(evaluate_configuration_indexed(no_match, "a1", inventory), (False, []))
        self.assertEqual(evaluate_configuration_indexed({}, "a1", inventory), (False, []))
        self.assertEqual(
            audit_status(1, 0, 0, True),
            "no_installed_product_version_matched_supported_criteria",
        )
        self.assertEqual(
            audit_status(0, 0, 0, True),
            "configuration_flag_true_but_raw_configuration_missing",
        )
        self.assertEqual(
            audit_status(0, 0, 0, False),
            "no_configuration_data_in_staged_raw_record",
        )

    def test_duplicate_relationship_pairs_are_removed(self):
        row = installation("i1", "a1")
        term = criterion()
        seen = set()
        unique = unique_match_pairs("a1", "CVE-TEST", [(row, term), (row, term)], seen)
        self.assertEqual(len(unique), 1)
        self.assertEqual(len(seen), 1)

    def test_pipeline_outputs_correct_asset_installation_kev_and_audit_relationships(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            date = "2026-10-19"
            processed = root / "data" / "processed" / date
            raw = root / "data" / "raw" / date
            synthetic = root / "data" / "synthetic"
            processed.mkdir(parents=True)
            raw.mkdir(parents=True)
            synthetic.mkdir(parents=True)

            with (synthetic / "enterprise_assets.csv").open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "asset_id", "asset_type", "business_unit", "criticality", "exposure",
                    "environment", "data_origin",
                ])
                writer.writeheader()
                writer.writerows([
                    {"asset_id": "ASSET-1", "asset_type": "server", "data_origin": "synthetic"},
                    {"asset_id": "ASSET-2", "asset_type": "server", "data_origin": "synthetic"},
                ])

            software_rows = [
                installation("SW-1", "ASSET-1"),
                installation("OS-1", "ASSET-1", vendor="acme", product="os", part="o"),
                installation("SW-2", "ASSET-2"),
            ]
            with (synthetic / "software_inventory.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=[
                    "installation_id", "asset_id", "software_vendor", "software_product",
                    "software_name", "software_version", "cpe23_uri", "data_origin",
                ])
                writer.writeheader()
                for row in software_rows:
                    writer.writerow({
                        **row,
                        "software_name": row["software_product"],
                        "data_origin": "synthetic",
                    })

            normalized = [
                {"cve_id": "CVE-TEST-1", "cvss_score": 9.0, "has_configurations": True},
                {"cve_id": "CVE-TEST-2", "cvss_score": 7.0, "has_configurations": True},
                {"cve_id": "CVE-TEST-3", "cvss_score": 5.0, "has_configurations": True},
                {"cve_id": "CVE-TEST-4", "cvss_score": 8.0, "has_configurations": True},
                {"cve_id": "CVE-TEST-5", "cvss_score": 8.0, "has_configurations": True},
            ]
            with (processed / "nvd_cves.jsonl").open("w", encoding="utf-8") as handle:
                for row in normalized:
                    handle.write(json.dumps(row) + "\n")
            (processed / "cisa_kev.jsonl").write_text(
                json.dumps({"cve_id": "CVE-TEST-1", "date_added": "2026-01-01"}) + "\n",
                encoding="utf-8",
            )

            config_one = configuration(
                criterion(product="widget", vulnerable=True),
                criterion(product="os", vulnerable=False, part="o"),
            )
            config_two = configuration(criterion(product="not-installed"))
            config_four = {
                "nodes": [{
                    "operator": "OR",
                    "negate": True,
                    "cpeMatch": [criterion(product="widget")],
                }]
            }
            config_five = {
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [criterion(product="widget")],
                    "nodes": [{
                        "operator": "OR",
                        "cpeMatch": [criterion(product="os", vulnerable=False, part="o")],
                    }],
                }]
            }
            raw_document = {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-TEST-1", "configurations": [config_one]}},
                    {"cve": {"id": "CVE-TEST-2", "configurations": [config_two]}},
                    {"cve": {"id": "CVE-TEST-3", "configurations": None}},
                    {"cve": {"id": "CVE-TEST-4", "configurations": [config_four]}},
                    {"cve": {"id": "CVE-TEST-5", "configurations": [config_five]}},
                ]
            }
            (raw / "nvd_general.json").write_text(json.dumps(raw_document), encoding="utf-8")

            with patch("src.match_vulnerabilities.ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--date", date]), 0)

            result = root / "results" / date
            with (result / "vulnerability_asset_matches.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                matches = list(csv.DictReader(handle))
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["asset_id"], "ASSET-1")
            self.assertEqual(matches[0]["installation_id"], "SW-1")
            self.assertEqual(matches[0]["cve_id"], "CVE-TEST-1")
            self.assertEqual(matches[0]["in_kev"], "True")

            with (result / "cve_configuration_audit.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                audit = {row["cve_id"]: row for row in csv.DictReader(handle)}
            self.assertEqual(
                audit["CVE-TEST-1"]["status"],
                "matched_assets_and_other_product_criteria_candidates_failed_full_configuration",
            )
            self.assertEqual(
                audit["CVE-TEST-1"]["evaluation_status"],
                "confirmed_candidate_match",
            )
            self.assertEqual(
                audit["CVE-TEST-1"]["risk_scoring_disposition"],
                "candidate_only_not_verified_exposure",
            )
            self.assertEqual(
                audit["CVE-TEST-1"]["candidate_asset_configuration_pairs_not_satisfied"],
                "1",
            )
            self.assertEqual(
                audit["CVE-TEST-2"]["status"],
                "no_installed_product_version_matched_supported_criteria",
            )
            self.assertEqual(audit["CVE-TEST-2"]["evaluation_status"], "evaluated_no_match")
            self.assertEqual(
                audit["CVE-TEST-3"]["evaluation_status"],
                "missing_configuration_data",
            )
            self.assertEqual(
                audit["CVE-TEST-3"]["status"],
                "configuration_flag_true_but_raw_configuration_missing",
            )
            self.assertEqual(audit["CVE-TEST-1"]["matched_asset_count_after_tree_evaluation"], "1")
            self.assertEqual(
                audit["CVE-TEST-4"]["evaluation_status"],
                "pending_manual_review",
            )
            self.assertEqual(
                audit["CVE-TEST-4"]["risk_scoring_disposition"],
                "withhold_manual_review",
            )
            self.assertEqual(audit["CVE-TEST-4"]["matched_asset_count_after_tree_evaluation"], "0")
            self.assertEqual(
                audit["CVE-TEST-4"]["candidate_asset_configuration_pairs_pending_manual_review"],
                "2",
            )
            self.assertIn(
                "negation_semantics_require_manual_review",
                audit["CVE-TEST-4"]["manual_review_reasons"],
            )
            self.assertEqual(
                audit["CVE-TEST-5"]["evaluation_status"],
                "pending_manual_review",
            )
            self.assertEqual(audit["CVE-TEST-5"]["matched_asset_count_after_tree_evaluation"], "0")
            self.assertIn(
                "nested_node_shape_not_defined_in_nvd_api_schema",
                audit["CVE-TEST-5"]["manual_review_reasons"],
            )
            with (result / "asset_exposure_summary.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                asset_summary = {
                    row["asset_id"]: row for row in csv.DictReader(handle)
                }
            self.assertEqual(
                asset_summary["ASSET-1"]["pending_manual_review_cve_count"],
                "2",
            )
            self.assertEqual(
                asset_summary["ASSET-1"]["global_missing_configuration_cve_count"],
                "1",
            )
            self.assertEqual(
                asset_summary["ASSET-1"]["risk_input_status"],
                "withheld_unresolved_candidate_evidence",
            )
            self.assertEqual(
                asset_summary["ASSET-1"]["risk_scoring_disposition"],
                "withhold_manual_review",
            )
            self.assertEqual(
                asset_summary["ASSET-2"]["risk_scoring_disposition"],
                "withhold_manual_review",
            )


if __name__ == "__main__":
    unittest.main()
