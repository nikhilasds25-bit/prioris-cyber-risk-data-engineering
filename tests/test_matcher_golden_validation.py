import json
import unittest
from pathlib import Path

from src.validate_matcher_golden import _classify, evaluate_case
from src.match_vulnerabilities import (
    configuration_manual_review_reasons,
    risk_scoring_disposition,
)


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "matcher_validation"
    / "golden_cases.json"
)


class IndependentGoldenMatcherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    def test_all_supported_golden_expectations(self):
        supported = [
            case for case in self.fixture["cases"] if case["status"] == "supported"
        ]
        self.assertGreaterEqual(len(supported), 20)
        for case in supported:
            with self.subTest(case=case["id"]):
                result = evaluate_case(self.fixture, case)
                self.assertEqual(result["observed"], result["expected"])

    def test_unsupported_version_case_is_diagnostic_not_a_match(self):
        case = next(
            case for case in self.fixture["cases"]
            if case["id"] == "openssl_unlisted_alpha_suffix_remains_unsupported"
        )
        result = evaluate_case(self.fixture, case)
        self.assertEqual(result["observed"], [])
        self.assertEqual(
            result["unsupported_assets"],
            case["expected_unsupported_assets"],
        )
        self.assertIsNone(result["expected"])

    def test_each_pending_case_has_no_scored_expected_outcome(self):
        pending = [
            case for case in self.fixture["cases"]
            if case["status"] == "pending_review"
        ]
        self.assertEqual(
            {case["id"] for case in pending},
            {
                "numeric_version_zero_padding_equivalence",
                "negated_support_absent",
                "negated_support_present",
            },
        )
        for case in pending:
            with self.subTest(case=case["id"]):
                self.assertIsNone(case["expected"])
                self.assertIn("investigation", case)
                self.assertTrue(case["investigation"]["evidence"])
                self.assertTrue(case["investigation"]["decision"])

    def test_nested_and_negated_configurations_require_manual_review(self):
        nested = next(
            case for case in self.fixture["cases"]
            if case["id"] == "nested_and_or_positive"
        )
        negated = next(
            case for case in self.fixture["cases"]
            if case["id"] == "negated_support_absent"
        )
        nested_config = nested["template"]
        negated_config = negated["template"]
        self.assertIn(
            "nested_node_shape_not_defined_in_nvd_api_schema",
            configuration_manual_review_reasons(nested_config),
        )
        self.assertIn(
            "negation_semantics_require_manual_review",
            configuration_manual_review_reasons(negated_config),
        )
        self.assertEqual(
            risk_scoring_disposition("pending_manual_review"),
            "withhold_manual_review",
        )

    def test_false_positive_and_false_negative_boolean_results_are_distinguished(self):
        false_positive = {
            "id": "false-positive-case",
            "status": "supported",
            "expected": False,
        }
        false_negative = {
            "id": "false-negative-case",
            "status": "supported",
            "expected": True,
        }
        self.assertEqual(
            _classify(
                false_positive,
                {"expected": False, "observed": True},
            ),
            "false_positive",
        )
        self.assertEqual(
            _classify(
                false_negative,
                {"expected": True, "observed": False},
            ),
            "false_negative",
        )

    def test_pending_review_cases_are_not_given_golden_expectations(self):
        pending = [
            case for case in self.fixture["cases"]
            if case["status"] == "pending_review"
        ]
        self.assertEqual(len(pending), 3)
        for case in pending:
            with self.subTest(case=case["id"]):
                result = evaluate_case(self.fixture, case)
                self.assertIn("observed", result)
                self.assertEqual(
                    _classify(case, result),
                    "pending_review_not_scored",
                )


if __name__ == "__main__":
    unittest.main()
