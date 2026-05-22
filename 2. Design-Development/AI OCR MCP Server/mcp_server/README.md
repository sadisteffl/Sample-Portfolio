# OCR Aggregate Analytics MCP Server

This is a local stdio MCP server for aggregate-only school reporting over OCR results.

It intentionally reads only the `ocr_reporting_aggregates` DynamoDB table. It does not expose raw OCR output or individual student report records.

## Tools

- `get_class_summary(class_id, term)`
- `compare_class_to_grade(class_id, grade, term)`
- `get_grade_level_summary(grade, term)`
- `get_metric_distribution(scope, metric, term)`
- `get_classes_needing_support(metric, term)`

## Aggregate Keys

The reporting table uses the same key shape for all tools:

- Class summary: `PartitionKey = CLASS#<class_id>`, `SortKey = TERM#<term>`
- Grade summary: `PartitionKey = GRADE#<grade>`, `SortKey = TERM#<term>`
- Support list: `PartitionKey = SUPPORT#<metric>`, `SortKey = TERM#<term>`

Example class aggregate:

```json
{
  "PartitionKey": "CLASS#5A",
  "SortKey": "TERM#FA24",
  "classId": "5A",
  "grade": "5",
  "term": "FA24",
  "studentCount": 24,
  "metrics": {
    "mathRit": 218,
    "readingRit": 211
  },
  "distributions": {
    "mathRit": [
      {"range": "190-199", "count": 3},
      {"range": "200-209", "count": 7}
    ]
  }
}
```

## Local Run

```bash
cd "/Users/sadisteffl/Desktop/Clarity /OCR/mcp_server"
python3 -m pip install -r requirements.txt
OCR_REPORTING_TABLE="ocr-reporting-aggregates-dev" AWS_REGION="us-east-1" python3 server.py
```

## MCP Client Config Example

```json
{
  "mcpServers": {
    "ocr-analytics": {
      "command": "python3",
      "args": ["/Users/sadisteffl/Desktop/Clarity /OCR/mcp_server/server.py"],
      "env": {
        "OCR_REPORTING_TABLE": "ocr-reporting-aggregates-dev",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```
