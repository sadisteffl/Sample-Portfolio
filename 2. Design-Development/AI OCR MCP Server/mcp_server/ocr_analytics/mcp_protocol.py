from __future__ import annotations

import json
from typing import Any, Mapping

from ocr_analytics.analytics import OcrAnalyticsTools


MCP_PROTOCOL_VERSION = "2025-11-25"


def build_tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "get_class_summary",
            "title": "Get Class Summary",
            "description": "Return aggregate reporting metrics for one class and term.",
            "inputSchema": object_schema(
                {
                    "class_id": string_schema("Class identifier, such as 5A."),
                    "term": string_schema("Academic term, such as FA24."),
                },
                ["class_id", "term"],
            ),
        },
        {
            "name": "compare_class_to_grade",
            "title": "Compare Class To Grade",
            "description": "Compare one class aggregate against its grade-level aggregate for a term.",
            "inputSchema": object_schema(
                {
                    "class_id": string_schema("Class identifier, such as 5A."),
                    "grade": string_schema("Grade level, such as 5."),
                    "term": string_schema("Academic term, such as FA24."),
                },
                ["class_id", "grade", "term"],
            ),
        },
        {
            "name": "get_grade_level_summary",
            "title": "Get Grade Level Summary",
            "description": "Return aggregate reporting metrics for one grade level and term.",
            "inputSchema": object_schema(
                {
                    "grade": string_schema("Grade level, such as 5."),
                    "term": string_schema("Academic term, such as FA24."),
                },
                ["grade", "term"],
            ),
        },
        {
            "name": "get_metric_distribution",
            "title": "Get Metric Distribution",
            "description": "Return a precomputed metric distribution for a class or grade scope.",
            "inputSchema": object_schema(
                {
                    "scope": string_schema("Aggregate scope key, such as CLASS#5A or GRADE#5."),
                    "metric": string_schema("Metric name, such as mathRit."),
                    "term": string_schema("Academic term, such as FA24."),
                },
                ["scope", "metric", "term"],
            ),
        },
        {
            "name": "get_classes_needing_support",
            "title": "Get Classes Needing Support",
            "description": "Return precomputed classes that are below grade aggregate for a metric.",
            "inputSchema": object_schema(
                {
                    "metric": string_schema("Metric name, such as mathRit."),
                    "term": string_schema("Academic term, such as FA24."),
                },
                ["metric", "term"],
            ),
        },
    ]


class McpProtocolHandler:
    def __init__(self, tools: OcrAnalyticsTools):
        self._tools = tools

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")

        if request_id is None:
            return None
        if method == "initialize":
            return success(
                request_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "ocr-analytics",
                        "title": "OCR Aggregate Analytics",
                        "version": "0.1.0",
                    },
                    "instructions": (
                        "Use these tools only for aggregate class and grade-level OCR reporting. "
                        "No individual student records are exposed."
                    ),
                },
            )
        if method == "ping":
            return success(request_id, {})
        if method == "tools/list":
            return success(request_id, {"tools": build_tool_definitions()})
        if method == "tools/call":
            return success(request_id, self._call_tool_result(request.get("params", {})))

        return error(request_id, -32601, f"Method not found: {method}")

    def _call_tool_result(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, Mapping):
            return tool_error("tools/call params must be an object")

        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str):
            return tool_error("tools/call params.name must be a string")
        if not isinstance(arguments, Mapping):
            return tool_error("tools/call params.arguments must be an object")

        try:
            result = self._tools.call_tool(name, arguments)
        except Exception as exc:
            return tool_error(str(exc))

        return {
            "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
            "structuredContent": result,
            "isError": False,
        }


def object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def string_schema(description: str) -> dict[str, str]:
    return {"type": "string", "description": description}


def success(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def tool_error(message: str) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }
