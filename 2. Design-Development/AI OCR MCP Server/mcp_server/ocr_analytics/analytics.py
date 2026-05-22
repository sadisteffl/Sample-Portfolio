from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping, Protocol


class AggregateNotFoundError(LookupError):
    """Raised when an expected aggregate record is missing."""


class AggregateRepository(Protocol):
    def get_item(self, partition_key: str, sort_key: str) -> dict[str, Any] | None:
        """Return an aggregate item by primary key."""


class InMemoryAggregateRepository:
    def __init__(self, items: Mapping[tuple[str, str], Mapping[str, Any]]):
        self._items = {key: dict(value) for key, value in items.items()}

    def get_item(self, partition_key: str, sort_key: str) -> dict[str, Any] | None:
        item = self._items.get((partition_key, sort_key))
        return dict(item) if item else None


class DynamoDBAggregateRepository:
    def __init__(self, table: Any):
        self._table = table

    def get_item(self, partition_key: str, sort_key: str) -> dict[str, Any] | None:
        response = self._table.get_item(
            Key={
                "PartitionKey": partition_key,
                "SortKey": sort_key,
            }
        )
        item = response.get("Item")
        return to_plain_json(item) if item else None


@dataclass
class OcrAnalyticsTools:
    repository: AggregateRepository

    def get_class_summary(self, class_id: str, term: str) -> dict[str, Any]:
        return self._required_public_item(f"CLASS#{class_id}", f"TERM#{term}")

    def compare_class_to_grade(self, class_id: str, grade: str, term: str) -> dict[str, Any]:
        class_item = self._required_public_item(f"CLASS#{class_id}", f"TERM#{term}")
        grade_item = self._required_public_item(f"GRADE#{grade}", f"TERM#{term}")
        class_metrics = class_item.get("metrics", {})
        grade_metrics = grade_item.get("metrics", {})
        comparisons = {}

        for metric in sorted(set(class_metrics).intersection(grade_metrics)):
            class_value = class_metrics[metric]
            grade_value = grade_metrics[metric]
            if isinstance(class_value, (int, float)) and isinstance(grade_value, (int, float)):
                comparisons[metric] = {
                    "classValue": class_value,
                    "gradeValue": grade_value,
                    "difference": class_value - grade_value,
                }

        return {
            "classId": class_id,
            "grade": grade,
            "term": term,
            "classSummary": class_item,
            "gradeSummary": grade_item,
            "comparisons": comparisons,
        }

    def get_grade_level_summary(self, grade: str, term: str) -> dict[str, Any]:
        return self._required_public_item(f"GRADE#{grade}", f"TERM#{term}")

    def get_metric_distribution(self, scope: str, metric: str, term: str) -> dict[str, Any]:
        partition_key = normalized_scope_key(scope)
        item = self._required_public_item(partition_key, f"TERM#{term}")
        distributions = item.get("distributions", {})
        distribution = distributions.get(metric)

        if distribution is None:
            raise AggregateNotFoundError(
                f"No distribution for metric {metric!r} in {partition_key}/TERM#{term}"
            )

        return {
            "scope": partition_key,
            "metric": metric,
            "term": term,
            "distribution": distribution,
        }

    def get_classes_needing_support(self, metric: str, term: str) -> dict[str, Any]:
        item = self._required_public_item(f"SUPPORT#{metric}", f"TERM#{term}")
        return {
            "metric": metric,
            "term": term,
            "classes": item.get("classes", []),
        }

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name == "get_class_summary":
            return self.get_class_summary(
                required_string(arguments, "class_id"),
                required_string(arguments, "term"),
            )
        if name == "compare_class_to_grade":
            return self.compare_class_to_grade(
                required_string(arguments, "class_id"),
                required_string(arguments, "grade"),
                required_string(arguments, "term"),
            )
        if name == "get_grade_level_summary":
            return self.get_grade_level_summary(
                required_string(arguments, "grade"),
                required_string(arguments, "term"),
            )
        if name == "get_metric_distribution":
            return self.get_metric_distribution(
                required_string(arguments, "scope"),
                required_string(arguments, "metric"),
                required_string(arguments, "term"),
            )
        if name == "get_classes_needing_support":
            return self.get_classes_needing_support(
                required_string(arguments, "metric"),
                required_string(arguments, "term"),
            )
        raise ValueError(f"Unknown MCP tool: {name}")

    def _required_public_item(self, partition_key: str, sort_key: str) -> dict[str, Any]:
        item = self.repository.get_item(partition_key, sort_key)
        if not item:
            raise AggregateNotFoundError(f"No aggregate found for {partition_key}/{sort_key}")
        return public_item(item)


def normalized_scope_key(scope: str) -> str:
    if scope.startswith("CLASS#") or scope.startswith("GRADE#"):
        return scope
    raise ValueError("scope must be an aggregate scope such as CLASS#5A or GRADE#5")


def public_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: to_plain_json(value)
        for key, value in item.items()
        if key not in {"PartitionKey", "SortKey"}
    }


def required_string(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing required string argument: {key}")
    return value.strip()


def to_plain_json(value: Any) -> Any:
    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)
        return float(value)
    if isinstance(value, dict):
        return {key: to_plain_json(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [to_plain_json(item) for item in value]
    return value
