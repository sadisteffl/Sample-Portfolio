import unittest

from ocr_analytics.analytics import InMemoryAggregateRepository, OcrAnalyticsTools
from ocr_analytics.mcp_protocol import MCP_PROTOCOL_VERSION, McpProtocolHandler


class McpProtocolHandlerTest(unittest.TestCase):
    def setUp(self):
        repository = InMemoryAggregateRepository(
            {
                ("CLASS#5A", "TERM#FA24"): {
                    "classId": "5A",
                    "grade": "5",
                    "term": "FA24",
                    "studentCount": 24,
                    "metrics": {"mathRit": 218},
                },
            }
        )
        self.handler = McpProtocolHandler(OcrAnalyticsTools(repository))

    def test_initialize_advertises_tool_capability(self):
        response = self.handler.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
            }
        )

        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION)
        self.assertEqual(response["result"]["capabilities"], {"tools": {"listChanged": False}})

    def test_tools_list_returns_registered_tools(self):
        response = self.handler.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

        names = [tool["name"] for tool in response["result"]["tools"]]
        self.assertIn("get_class_summary", names)

    def test_tools_call_returns_structured_content(self):
        response = self.handler.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get_class_summary",
                    "arguments": {"class_id": "5A", "term": "FA24"},
                },
            }
        )

        self.assertEqual(response["id"], 3)
        self.assertEqual(response["result"]["structuredContent"]["classId"], "5A")
        self.assertFalse(response["result"]["isError"])

    def test_tool_execution_error_is_visible_to_model(self):
        response = self.handler.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "get_class_summary",
                    "arguments": {"class_id": "9Z", "term": "FA24"},
                },
            }
        )

        self.assertTrue(response["result"]["isError"])
        self.assertIn("No aggregate found", response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
