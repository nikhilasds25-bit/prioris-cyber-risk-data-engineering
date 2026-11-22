import csv
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.generate_coverage_inventory import (
    _outside_version_candidates,
    configuration_solution,
    generate_dataset,
)
from src.match_vulnerabilities import (
    InventoryIndex,
    _unsupported_version_comparison,
    evaluate_configuration_indexed,
    main as run_matcher,
)


def term(product, version="*", vulnerable=True, part="a", **bounds):
    return {
        "criteria": f"cpe:2.3:{part}:acme:{product}:{version}:*:*:*:*:*:*:*",
        "vulnerable": vulnerable,
        **bounds,
    }


class CoverageInventoryGeneratorTests(unittest.TestCase):
    def test_selects_and_preserves_required_supporting_criteria(self):
        config = {
            "nodes": [{
                "operator": "AND",
                "cpeMatch": [
                    term("widget", "2.0"),
                    term("os", "1.0", vulnerable=False),
                ],
            }]
        }
        solution = configuration_solution(config)
        self.assertEqual(
            [(entry["criteria"], entry["vulnerable"]) for entry in solution],
            [(term("widget", "2.0")["criteria"], True),
             (term("os", "1.0", vulnerable=False)["criteria"], False)],
        )

    def test_honors_configuration_level_and_when_selecting_synthetic_installations(self):
        vulnerable = term("widget", "2.0")
        supporting = term("os", "1.0", vulnerable=False)
        config = {
            "operator": "AND",
            "nodes": [
                {"operator": "OR", "cpeMatch": [vulnerable]},
                {"operator": "OR", "cpeMatch": [supporting]},
            ],
        }
        solution = configuration_solution(config)
        self.assertEqual(len(solution), 2)
        self.assertEqual(
            {item["criteria"] for item in solution},
            {vulnerable["criteria"], supporting["criteria"]},
        )

    def test_selects_a_vulnerable_or_branch_and_excludes_negation(self):
        config = {
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    term("widget", vulnerable=False),
                    term("gadget", "3.1", vulnerable=True),
                ],
            }]
        }
        solution = configuration_solution(config)
        self.assertEqual(len(solution), 1)
        self.assertEqual(solution[0]["criteria"], term("gadget", "3.1")["criteria"])
        config["nodes"][0]["negate"] = True
        self.assertIsNone(configuration_solution(config))

    def test_boundary_positive_and_negative_control_versions_are_distinguishable(self):
        config = {
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [term(
                    "bounded",
                    versionStartExcluding="2.0",
                    versionEndIncluding="3.0",
                )],
            }]
        }
        solution = configuration_solution(config)
        self.assertIsNotNone(solution)
        positive = solution[0]
        positive_cpe = positive["criteria"].replace(":*:", ":2.1:", 1)
        inventory = InventoryIndex([{
            "installation_id": "POS",
            "asset_id": "A1",
            "cpe23_uri": positive_cpe,
        }])
        self.assertIn("A1", inventory.matches(positive))
        outside_cpe = positive_cpe.replace(":2.1:", ":3.1:", 1)
        outside = InventoryIndex([{
            "installation_id": "NEG",
            "asset_id": "A2",
            "cpe23_uri": outside_cpe,
        }])
        self.assertNotIn("A2", outside.matches(positive))

    def test_controls_do_not_treat_unsupported_version_order_as_outside_range(self):
        bounded = term(
            "bounded",
            versionStartIncluding="1.0",
            versionEndExcluding="1.0.0",
        )
        controls = _outside_version_candidates(bounded)
        self.assertNotIn("1.0.0", controls)
        self.assertTrue(all(
            not _unsupported_version_comparison(bounded, "*", version)
            for version in controls
        ))

    def test_generated_files_are_reproducible_and_traceable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "2026-10-19" / "nvd.json"
            raw.parent.mkdir()
            raw.write_text(json.dumps({
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-TEST-1",
                        "configurations": [{
                            "nodes": [{
                                "operator": "AND",
                                "cpeMatch": [term(
                                    "widget",
                                    "2.0",
                                    versionStartIncluding="2.0",
                                    versionEndExcluding="3.0",
                                )],
                            }]
                        }],
                    }
                }]
            }), encoding="utf-8")
            output_a = root / "out-a"
            output_b = root / "out-b"
            first = generate_dataset([raw], output_a, seed=42)
            second = generate_dataset([raw], output_b, seed=42)
            self.assertEqual(first["counts"], second["counts"])
            for name in ("enterprise_assets.csv", "software_inventory.csv", "configuration_cases.csv"):
                self.assertEqual((output_a / name).read_bytes(), (output_b / name).read_bytes())
            with (output_a / "software_inventory.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertTrue(rows)
            self.assertTrue(all(row["data_origin"] == "synthetic_nvd_criterion_derived" for row in rows))
            self.assertTrue(all(row["source_cve_id"] == "CVE-TEST-1" for row in rows))
            manifest = json.loads((output_a / "generation_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["random_seed"], 42)
            self.assertGreaterEqual(manifest["counts"]["positive_configuration_cases"], 1)

    def test_generated_ground_truth_matches_full_phase3_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            date = "2026-10-19"
            raw_dir = root / "data" / "raw" / date
            processed = root / "data" / "processed" / date
            raw_dir.mkdir(parents=True)
            processed.mkdir(parents=True)
            raw = raw_dir / "nvd_general.json"
            source_config = {
                "operator": "AND",
                "nodes": [
                    {"operator": "OR", "cpeMatch": [term("widget", "2.0")]},
                    {"operator": "OR", "cpeMatch": [
                        term("os", "1.0", vulnerable=False, part="o")
                    ]},
                ],
            }
            raw.write_text(json.dumps({
                "vulnerabilities": [{
                    "cve": {
                        "id": "CVE-TEST-AND",
                        "configurations": [source_config],
                    }
                }]
            }), encoding="utf-8")
            (raw_dir / "nvd_known_exploited.json").write_text(
                json.dumps({"vulnerabilities": []}), encoding="utf-8"
            )
            (processed / "nvd_cves.jsonl").write_text(
                json.dumps({
                    "cve_id": "CVE-TEST-AND",
                    "cvss_score": 7.0,
                    "has_configurations": True,
                }) + "\n",
                encoding="utf-8",
            )
            (processed / "cisa_kev.jsonl").write_text(
                json.dumps({"cve_id": "CVE-TEST-AND", "date_added": "2026-01-01"}) + "\n",
                encoding="utf-8",
            )
            inventory_dir = root / "data" / "synthetic_nvd_aligned"
            generate_dataset([raw], inventory_dir, seed=42)
            result_dir = root / "results" / "coverage"

            with patch("src.match_vulnerabilities.ROOT", root), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run_matcher([
                    "--date", date,
                    "--inventory-dir", str(inventory_dir),
                    "--output-dir", str(result_dir),
                ]), 0)

            with (inventory_dir / "configuration_cases.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                cases = list(csv.DictReader(handle))
            self.assertEqual(len(cases), 1)
            case = cases[0]
            self.assertEqual(case["expected_positive_match"], "candidate_match")
            self.assertEqual(case["expected_control_match"], "no_match")
            self.assertEqual(case["control_type"], "version")

            with (result_dir / "vulnerability_asset_matches.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                matches = list(csv.DictReader(handle))
            matched_assets = {row["asset_id"] for row in matches if row["cve_id"] == "CVE-TEST-AND"}
            self.assertIn(case["positive_asset_id"], matched_assets)
            self.assertNotIn(case["control_asset_id"], matched_assets)
            with (inventory_dir / "software_inventory.csv").open(
                encoding="utf-8", newline=""
            ) as handle:
                installations = list(csv.DictReader(handle))
            positive_reasons = {
                row["generation_reason"] for row in installations
                if row["asset_id"] == case["positive_asset_id"]
            }
            self.assertIn("supporting_non_vulnerable_configuration_criterion", positive_reasons)


if __name__ == "__main__":
    unittest.main()
