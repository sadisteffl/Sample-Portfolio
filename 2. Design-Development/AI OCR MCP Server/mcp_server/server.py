from __future__ import annotations

import json
import os
import sys
from typing import TextIO

from ocr_analytics.analytics import DynamoDBAggregateRepository, OcrAnalyticsTools
from ocr_analytics.mcp_protocol import McpProtocolHandler, error


def main() -> int:
    table_name = os.environ.get("OCR_REPORTING_TABLE")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")

    if not table_name:
        print("OCR_REPORTING_TABLE is required", file=sys.stderr)
        return 1

    try:
        import boto3
    except ImportError:
        print("boto3 is required. Install dependencies with: python3 -m pip install -r requirements.txt", file=sys.stderr)
        return 1

    table = boto3.resource("dynamodb", region_name=aws_region).Table(table_name)
    handler = McpProtocolHandler(OcrAnalyticsTools(DynamoDBAggregateRepository(table)))
    serve_stdio(handler, sys.stdin, sys.stdout)
    return 0


def serve_stdio(handler: McpProtocolHandler, stdin: TextIO, stdout: TextIO) -> None:
    for line in stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
            response = handler.handle(request)
        except json.JSONDecodeError as exc:
            response = error(None, -32700, f"Parse error: {exc.msg}")
        except Exception as exc:
            response = error(None, -32603, f"Internal error: {exc}")

        if response is not None:
            stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
