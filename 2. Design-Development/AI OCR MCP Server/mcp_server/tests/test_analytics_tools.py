import unittest

from ocr_analytics.analytics import AggregateNotFoundError, InMemoryAggregateRepository, OcrAnalyticsTools
from ocr_analytics.mcp_protocol import build_tool_definitions


class OcrAnalyticsToolsTest(unittest.TestCase):
    def setUp(self):
        self.repository = InMemoryAggregateRepository(
            {
                ("CLASS#5A", "TERM#FA24"): {
                    "PartitionKey": "CLASS#5A",
                    "SortKey": "TERM#FA24",
                    "classId": "5A",
                    "grade": "5",
                    "term": "FA24",
                    "studentCount": 24,
                    "metrics": {
                        "mathRit": 218,
                        "readingRit": 211,
                    },
                    "distributions": {
                        "mathRit": [
                            {"range": "190-199", "count": 3},
                            {"range": "200-209", "count": 7},
                            {"range": "210-219", "count": 9},
                            {"range": "220-229", "count": 5},
                        ]
                    },
                },
                ("GRADE#5", "TERM#FA24"): {
                    "PartitionKey": "GRADE#5",
                    "SortKey": "TERM#FA24",
                    "grade": "5",
                    "term": "FA24",
                    "classCount": 4,
                    "studentCount": 96,
                    "metrics": {
                        "mathRit": 221,
                        "readingRit": 214,
                    },
                    "distributions": {
                        "mathRit": [
                            {"range": "190-199", "count": 8},
                            {"range": "200-209", "count": 21},
                            {"range": "210-219", "count": 35},
                            {"range": "220-229", "count": 32},
                        ]
                    },
                },
                ("SUPPORT#mathRit", "TERM#FA24"): {
                    "PartitionKey": "SUPPORT#mathRit",
                    "SortKey": "TERM#FA24",
                    "metric": "mathRit",
                    "term": "FA24",
                    "classes": [
                        {"classId": "5A", "grade": "5", "value": 218, "gradeValue": 221, "difference": -3},
                        {"classId": "5C", "grade": "5", "value": 216, "gradeValue": 221, "difference": -5},
                    ],
                },
            }
        )
        self.tools = OcrAnalyticsTools(self.repository)

    def test_get_class_summary_returns_aggregate_without_storage_keys(self):
        result = self.tools.get_class_summary("5A", "FA24")

        self.assertEqual(result["classId"], "5A")
        self.assertEqual(result["term"], "FA24")
        self.assertEqual(result["studentCount"], 24)
        self.assertNotIn("PartitionKey", result)
        self.assertNotIn("SortKey", result)

    def test_compare_class_to_grade_returns_metric_differences(self):
        result = self.tools.compare_class_to_grade("5A", "5", "FA24")

        self.assertEqual(result["classId"], "5A")
        self.assertEqual(result["grade"], "5")
        self.assertEqual(result["term"], "FA24")
        self.assertEqual(
            result["comparisons"]["mathRit"],
            {"classValue": 218, "gradeValue": 221, "difference": -3},
        )
        self.assertEqual(
            result["comparisons"]["readingRit"],
            {"classValue": 211, "gradeValue": 214, "difference": -3},
        )

    def test_get_grade_level_summary_returns_aggregate(self):
        result = self.tools.get_grade_level_summary("5", "FA24")

        self.assertEqual(result["grade"], "5")
        self.assertEqual(result["classCount"], 4)
        self.assertEqual(result["studentCount"], 96)

    def test_get_metric_distribution_accepts_class_scope(self):
        result = self.tools.get_metric_distribution("CLASS#5A", "mathRit", "FA24")

        self.assertEqual(result["scope"], "CLASS#5A")
        self.assertEqual(result["metric"], "mathRit")
        self.assertEqual(result["distribution"][0], {"range": "190-199", "count": 3})

    def test_get_metric_distribution_accepts_grade_scope(self):
        result = self.tools.get_metric_distribution("GRADE#5", "mathRit", "FA24")

        self.assertEqual(result["scope"], "GRADE#5")
        self.assertEqual(result["distribution"][-1], {"range": "220-229", "count": 32})

    def test_get_metric_distribution_rejects_raw_student_scope(self):
        with self.assertRaises(ValueError):
            self.tools.get_metric_distribution("STUDENT#123", "mathRit", "FA24")

    def test_get_classes_needing_support_returns_precomputed_list(self):
        result = self.tools.get_classes_needing_support("mathRit", "FA24")

        self.assertEqual(result["metric"], "mathRit")
        self.assertEqual(len(result["classes"]), 2)
        self.assertEqual(result["classes"][0]["classId"], "5A")

    def test_missing_aggregate_raises_clear_error(self):
        with self.assertRaises(AggregateNotFoundError) as context:
            self.tools.get_class_summary("9Z", "FA24")

        self.assertIn("CLASS#9Z", str(context.exception))

    def test_mcp_tool_definitions_expose_expected_tools(self):
        names = {tool["name"] for tool in build_tool_definitions()}

        self.assertEqual(
            names,
            {
                "get_class_summary",
                "compare_class_to_grade",
                "get_grade_level_summary",
                "get_metric_distribution",
                "get_classes_needing_support",
            },
        )


if __name__ == "__main__":
    unittest.main()
