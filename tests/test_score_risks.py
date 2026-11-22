import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.score_risks import (
    RiskScoringConfig,
    risk_tier,
    score_components,
    score_experiment,
    write_reports,
)


class RiskScoringFormulaTests(unittest.TestCase):
    def test_identical_inputs_produce_reproducible_components_and_score(self):
        first = score_components(8.1, True, "high", "internet-facing")
        second = score_components(8.1, True, "high", "internet-facing")

        self.assertEqual(first, second)
        self.assertEqual(first["score"], 14.1)
        self.assertEqual(first["tier"], "critical")

    def test_higher_severity_never_reduces_score_when_other_inputs_are_equal(self):
        lower = score_components(4.0, False, "medium", "internal")
        higher = score_components(9.0, False, "medium", "internal")

        self.assertGreater(higher["score"], lower["score"])

    def test_kev_membership_increases_score_when_other_inputs_are_equal(self):
        not_kev = score_components(7.0, False, "high", "restricted")
        kev = score_components(7.0, True, "high", "restricted")

        self.assertEqual(
            kev["score"] - not_kev["score"],
            RiskScoringConfig().kev_bonus,
        )

    def test_criticality_and_exposure_context_affect_score_as_documented(self):
        low_context = score_components(7.0, False, "low", "restricted")
        high_context = score_components(7.0, False, "critical", "internet-facing")
        same_criticality_less_exposure = score_components(
            7.0, False, "critical", "restricted"
        )

        self.assertGreater(high_context["score"], low_context["score"])
        self.assertGreater(
            high_context["score"],
            same_criticality_less_exposure["score"],
        )
        self.assertEqual(high_context["components"]["criticality"], 3.0)
        self.assertEqual(high_context["components"]["exposure"], 2.0)
        for value, expected in (
            ("low", 0.0),
            ("medium", 1.0),
            ("high", 2.0),
            ("critical", 3.0),
        ):
            self.assertEqual(
                score_components(7.0, False, value, "restricted")[
                    "components"
                ]["criticality"],
                expected,
            )
        for value, expected in (
            ("restricted", 0.0),
            ("internal", 1.0),
            ("internet-facing", 2.0),
        ):
            self.assertEqual(
                score_components(7.0, False, "low", value)["components"][
                    "exposure"
                ],
                expected,
            )

    def test_missing_or_unrecognized_evidence_withholds_score(self):
        result = score_components(None, None, "", "internet-facing")

        self.assertIsNone(result["score"])
        self.assertIsNone(result["tier"])
        self.assertEqual(
            set(result["missing_evidence"]),
            {
                "valid_cvss_score_0_to_10",
                "explicit_cisa_kev_membership",
                "recognized_asset_criticality",
            },
        )
        self.assertIsNone(
            score_components(7.0, True, "critical", "unknown")["score"]
        )

    def test_score_bounds_and_risk_tier_thresholds(self):
        config = RiskScoringConfig()
        maximum = score_components(10.0, True, "critical", "internet-facing")
        minimum = score_components(0.0, False, "low", "restricted")
        self.assertEqual(maximum["score"], config.maximum_score)
        self.assertEqual(maximum["tier"], "critical")
        self.assertEqual(minimum["score"], 0.0)
        self.assertEqual(minimum["tier"], "low")
        self.assertEqual(risk_tier(13.999, config), "high")
        self.assertEqual(risk_tier(14.0, config), "critical")
        self.assertEqual(risk_tier(10.0, config), "high")
        self.assertEqual(risk_tier(6.0, config), "medium")
        self.assertEqual(risk_tier(5.999, config), "low")
        self.assertIsNone(score_components(-0.1, False, "low", "restricted")["score"])
        self.assertIsNone(score_components(10.1, False, "low", "restricted")["score"])
        with self.assertRaisesRegex(ValueError, "between 0"):
            risk_tier(config.maximum_score + 0.1, config)
        with self.assertRaisesRegex(ValueError, "medium <= high <= critical"):
            RiskScoringConfig(
                medium_threshold=10,
                high_threshold=6,
                critical_threshold=14,
            ).validate()
        with self.assertRaisesRegex(ValueError, "must not exceed"):
            RiskScoringConfig(
                medium_threshold=10,
                high_threshold=14,
                critical_threshold=18,
            ).validate()

    def test_custom_scoring_configuration_changes_components(self):
        config = RiskScoringConfig(
            kev_bonus=3.0,
            criticality_step=0.5,
            internet_facing_bonus=1.5,
            internal_bonus=0.5,
            medium_threshold=5,
            high_threshold=9,
            critical_threshold=13,
        )

        result = score_components(8.0, True, "high", "internal", config)

        self.assertEqual(result["components"], {
            "severity": 8.0,
            "kev": 3.0,
            "criticality": 1.0,
            "exposure": 0.5,
        })
        self.assertEqual(result["score"], 12.5)
        self.assertEqual(result["tier"], "high")


class RiskScoringIsolationTests(unittest.TestCase):
    def _project(self, root: Path) -> tuple[Path, Path, list[Path]]:
        date = "2026-10-19"
        raw_dir = root / "data" / "raw" / date
        inventory_dir = root / "data" / "synthetic_nvd_aligned"
        result_dir = root / "results" / f"{date}-nvd-aligned"
        raw_dir.mkdir(parents=True)
        inventory_dir.mkdir(parents=True)
        result_dir.mkdir(parents=True)

        raw_files = []
        raw_records = []
        for name in ("nvd_general.json", "nvd_known_exploited.json"):
            path = raw_dir / name
            path.write_text("{}", encoding="utf-8")
            raw_files.append(path)
            raw_records.append({
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })

        def write_csv(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)

        asset = {
            "asset_id": "NCV-ASSET-1",
            "asset_type": "coverage_candidate",
            "business_unit": "Engineering",
            "criticality": "high",
            "exposure": "internet-facing",
            "environment": "production",
            "data_origin": "synthetic",
            "scenario_type": "positive",
            "source_cve_id": "CVE-TEST-1",
            "source_configuration_index": "1",
            "generation_reason": "generated positive fixture",
        }
        software = {
            "installation_id": "CVSI-1",
            "asset_id": asset["asset_id"],
            "software_vendor": "example",
            "software_product": "widget",
            "software_name": "Example Widget",
            "software_version": "1.0",
            "cpe23_uri": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
            "data_origin": "synthetic_nvd_criterion_derived",
            "source_cve_id": "CVE-TEST-1",
            "source_configuration_index": "1",
            "source_criteria": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
            "generation_reason": "positive exact version",
        }
        case = {
            "case_id": "CVE-TEST-1-CFG-001",
            "source_cve_id": "CVE-TEST-1",
            "configuration_index": "1",
            "positive_asset_id": asset["asset_id"],
            "control_asset_id": "NCV-ASSET-2",
            "expected_positive_match": "candidate_match",
            "expected_control_match": "no_match",
            "control_type": "version",
            "case_status": "positive_and_control",
            "exclusion_reason": "",
        }
        match = {
            "asset_id": asset["asset_id"],
            "asset_type": asset["asset_type"],
            "business_unit": asset["business_unit"],
            "criticality": asset["criticality"],
            "exposure": asset["exposure"],
            "environment": asset["environment"],
            "installation_id": software["installation_id"],
            "software_name": software["software_name"],
            "software_vendor": software["software_vendor"],
            "software_product": software["software_product"],
            "software_version": software["software_version"],
            "cpe23_uri": software["cpe23_uri"],
            "cve_id": "CVE-TEST-1",
            "cvss_score": "8.0",
            "cvss_version": "3.1",
            "in_kev": "True",
            "kev_date_added": "2022-01-01",
            "published": "2020-01-01T00:00:00.000",
            "configuration_index": "1",
            "matched_criteria": software["source_criteria"],
            "version_start_including": "",
            "version_start_excluding": "",
            "version_end_including": "",
            "version_end_excluding": "",
            "match_method": "local_cpe_criteria_and_supported_version_bounds",
            "description": "Test CVE",
        }
        audit = {
            "cve_id": "CVE-TEST-1",
            "cvss_score": "8.0",
            "in_kev": "True",
            "matched_asset_count_after_tree_evaluation": "1",
            "status": "matched_assets_under_local_configuration_evaluation",
        }
        for filename, fields, rows in (
            ("enterprise_assets.csv", list(asset), [asset]),
            ("software_inventory.csv", list(software), [software]),
            ("configuration_cases.csv", list(case), [case]),
        ):
            write_csv(inventory_dir / filename, fields, rows)
        write_csv(
            result_dir / "vulnerability_asset_matches.csv",
            list(match),
            [match],
        )
        write_csv(
            result_dir / "cve_configuration_audit.csv",
            list(audit),
            [audit],
        )
        (result_dir / "phase3_summary.json").write_text(json.dumps({
            "phase": 3,
            "snapshot_date": date,
            "output_directory": str(result_dir.resolve()),
            "inventory_directory": str(inventory_dir.resolve()),
            "results": {"vulnerability_asset_match_rows": 1},
        }), encoding="utf-8")
        (inventory_dir / "generation_manifest.json").write_text(json.dumps({
            "experiment": "NVD-aligned synthetic coverage",
            "data_origin": "synthetic",
            "snapshot_date": date,
            "random_seed": 42,
            "source_raw_files": raw_records,
            "counts": {
                "source_configurations": 1,
                "positive_configuration_cases": 1,
                "excluded_configurations": 0,
            },
        }), encoding="utf-8")
        input_files = [
            *raw_files,
            *(inventory_dir / name for name in (
                "enterprise_assets.csv",
                "software_inventory.csv",
                "configuration_cases.csv",
                "generation_manifest.json",
            )),
            *(result_dir / name for name in (
                "vulnerability_asset_matches.csv",
                "cve_configuration_audit.csv",
                "phase3_summary.json",
            )),
        ]
        return result_dir, inventory_dir, input_files

    def test_writes_only_isolated_outputs_and_preserves_all_input_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir, inventory_dir, input_files = self._project(root)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in input_files}
            output_dir = root / "results" / "risk-scoring-prototype"

            with patch("src.score_risks.ROOT", root):
                result = score_experiment(input_dir, inventory_dir)
                repeated = score_experiment(input_dir, inventory_dir)
                write_reports(result, output_dir)

            self.assertEqual(result["ranked_risks"], repeated["ranked_risks"])
            self.assertEqual(result["report"], repeated["report"])
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in input_files}
            self.assertEqual(before, after)
            self.assertEqual(result["report"]["counts"]["scored_relationships"], 1)
            self.assertEqual(result["report"]["counts"]["relationships_withheld_by_eligibility"], 0)
            self.assertEqual(
                sorted(path.name for path in output_dir.iterdir()),
                sorted([
                    "per_asset_risk_summary.csv",
                    "relationship_eligibility_audit.csv",
                    "risk_scoring_summary.json",
                    "ranked_asset_cve_risks.csv",
                    "scoring_evidence_gaps.csv",
                ]),
            )
            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                write_reports(result, output_dir)
            self.assertEqual(before, {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in input_files
            })

    def test_case_evidence_is_pair_specific_and_uses_only_supported_configuration_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_dir, inventory_dir, _ = self._project(root)

            def read_rows(path: Path) -> list[dict[str, str]]:
                with path.open(encoding="utf-8", newline="") as handle:
                    return list(csv.DictReader(handle))

            def append_rows(path: Path, rows: list[dict[str, str]]) -> None:
                with path.open("a", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=read_rows(path)[0].keys())
                    writer.writerows(rows)

            matches_path = input_dir / "vulnerability_asset_matches.csv"
            original_match = read_rows(matches_path)[0]
            alternate_configuration_match = {
                **original_match,
                "configuration_index": "2",
            }
            second_asset = {
                **read_rows(inventory_dir / "enterprise_assets.csv")[0],
                "asset_id": "NCV-ASSET-2",
                "source_cve_id": "CVE-TEST-2",
            }
            second_software = {
                **read_rows(inventory_dir / "software_inventory.csv")[0],
                "installation_id": "CVSI-2",
                "asset_id": second_asset["asset_id"],
                "source_cve_id": "CVE-TEST-2",
            }
            second_case = {
                **read_rows(inventory_dir / "configuration_cases.csv")[0],
                "case_id": "CVE-TEST-2-CFG-001",
                "source_cve_id": "CVE-TEST-2",
                "positive_asset_id": second_asset["asset_id"],
            }
            second_match = {
                **original_match,
                "asset_id": second_asset["asset_id"],
                "installation_id": second_software["installation_id"],
                "cve_id": "CVE-TEST-2",
            }
            append_rows(
                inventory_dir / "enterprise_assets.csv",
                [second_asset],
            )
            append_rows(
                inventory_dir / "software_inventory.csv",
                [second_software],
            )
            append_rows(
                inventory_dir / "configuration_cases.csv",
                [second_case],
            )
            append_rows(
                matches_path,
                [alternate_configuration_match, second_match],
            )
            audit_path = input_dir / "cve_configuration_audit.csv"
            append_rows(audit_path, [{
                **read_rows(audit_path)[0],
                "cve_id": "CVE-TEST-2",
            }])
            summary_path = input_dir / "phase3_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            summary["results"]["vulnerability_asset_match_rows"] = 3
            summary_path.write_text(json.dumps(summary), encoding="utf-8")

            with patch("src.score_risks.ROOT", root):
                result = score_experiment(input_dir, inventory_dir)

            self.assertEqual(result["report"]["counts"]["scored_relationships"], 2)
            self.assertEqual(
                len({
                    (row["asset_id"], row["cve_id"])
                    for row in result["ranked_risks"]
                }),
                2,
            )
            evidence_by_pair = {
                (row["asset_id"], row["cve_id"]): row["evidence_used"][
                    "candidate_relationship"
                ]
                for row in result["ranked_risks"]
            }
            first = evidence_by_pair[("NCV-ASSET-1", "CVE-TEST-1")]
            self.assertEqual(first["case_id"], "CVE-TEST-1-CFG-001")
            self.assertEqual(first["configuration_index"], "1")
            self.assertEqual(
                [item["installation_id"] for item in first["installations"]],
                ["CVSI-1"],
            )
            self.assertEqual(
                evidence_by_pair[("NCV-ASSET-2", "CVE-TEST-2")]["case_id"],
                "CVE-TEST-2-CFG-001",
            )


if __name__ == "__main__":
    unittest.main()
