# AI OCR MCP Server - Maximum Security Pipeline

## Overview

This is a production-grade **Optical Character Recognition (OCR) pipeline** built with AWS serverless services and designed with a **maximum-security, air-gapped architecture**. The infrastructure demonstrates a "shift-left" security philosophy where security controls are embedded at every layer—from malware scanning before processing to encrypted data at rest and in transit.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VPC (Private, Air-Gapped)                          │
│  ┌───────────────┐    ┌──────────────┐    ┌──────────────────────────────┐ │
│  │   S3 Upload   │───▶│  GuardDuty  │───▶│   Step Functions Workflow    │ │
│  │  (Pre-Process)│    │  Malware    │    │  ┌──────────────────────────┐ │ │
│  └───────────────┘    │   Scan      │    │  │ 1. Move Clean Files      │ │ │
│                       └──────────────┘    │  │ 2. Start Textract Job    │ │ │
│                              │             │  │ 3. Extract Scores       │ │ │
│                              ▼             │  └──────────────────────────┘ │ │
│                       ┌──────────────┐    └──────────────────────────────┘ │
│         ┌─────────────│ Quarantine   │                                      │
│         │             │   Bucket     │                                      │
│         │             └──────────────┘                                      │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                       Clean Files Only                               │  │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐  │  │
│  │  │   Textract   │──▶│  DynamoDB    │──▶│  Results Archive (S3)    │  │  │
│  │  │     OCR      │   │  Orchestration│  │                          │  │  │
│  │  └──────────────┘   └──────────────┘   └──────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
│  VPC Endpoints: S3, DynamoDB, KMS, Step Functions, SNS, SQS, Textract       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Features

### Maximum Isolation
- **Air-gapped VPC architecture** with no internet gateway
- **VPC endpoints** for all AWS services (S3, DynamoDB, KMS, Textract, Step Functions, SNS, SQS)
- **Private subnets** for Lambda execution
- **Security groups** with least-privilege ingress/egress rules

### Encryption Everywhere
- **KMS Customer Managed Key** with automatic rotation
- All S3 buckets encrypted at rest with `aws:kms`
- All DynamoDB tables encrypted with CMK
- CloudWatch Logs encrypted with CMK
- SNS topics encrypted with CMK
- Step Functions state data encrypted with CMK

### Malware Protection
- **GuardDuty Malware Protection Plan** scans all uploaded files
- Automatic tagging of scan results (`NO_THREATS_FOUND` / `THREATS_FOUND`)
- Quarantine workflow for infected files
- SNS alerts for malware threats
- Malware metrics and CloudWatch alarms

### Additional Security Controls
- **Lambda code signing** configuration
- **CloudTrail** for API call auditing
- **S3 bucket policies** blocking all public access
- **Dead Letter Queues** for error handling
- **TTL-based cleanup** for orchestration data (72 hours)

## Workflow

### 1. File Upload & Scanning
```
User Upload → S3 Pre-Processing Bucket
           → GuardDuty Malware Scan
           → EventBridge Notification
```

### 2. Clean File Processing
```
Scan: NO_THREATS_FOUND
  → Step Functions: Move to Processed Bucket
  → EventBridge: Trigger OCR Workflow
  → Textract: Start Document Analysis
```

### 3. Infected File Handling
```
Scan: THREATS_FOUND
  → Step Functions: Move to Quarantine Bucket
  → SNS Alert: Email Notification
  → CloudWatch: Log Threat Details
```

### 4. OCR Processing
```
Clean File in Processed Bucket
  → Lambda: Start Textract Job (async)
  → DynamoDB: Store Job Metadata + taskToken
  → Textract: Process Document (TABLES, FORMS, QUERIES)
  → SNS: Job Completion Notification
  → Lambda: Process Results (Extract Math RIT Scores)
  → DynamoDB: Update Job Status
  → S3: Archive Results
  → Step Functions: Complete Workflow
```

## AWS Services Used

| Service | Purpose |
|---------|---------|
| **S3** | File storage (pre-processing, processed, quarantine, results) |
| **GuardDuty** | Malware scanning for uploaded files |
| **Textract** | OCR and document text/data extraction |
| **Lambda** | Serverless compute for workflow steps |
| **Step Functions** | Orchestrated workflow management |
| **DynamoDB** | Job orchestration and student records |
| **EventBridge** | Event-driven workflow triggers |
| **SNS** | Notifications (alerts, job completion) |
| **SQS** | Dead Letter Queues for error handling |
| **KMS** | Encryption key management |
| **CloudWatch** | Logging, metrics, and alarms |
| **CloudTrail** | API audit logging |
| **Kinesis Firehose** | Long-term log archival to S3 |
| **Signer** | Lambda code signing |

## Data Flow

### Student Score Extraction
The pipeline extracts Math RIT scores from student assessment reports using a multi-pass algorithm:

1. **Query Results** - Textract QUERIES feature (highest priority)
2. **Term-Based Scoring** - Scores near current term indicators (FA24, SP24, etc.)
3. **Keyword Matching** - Lines containing "Math" and "RIT"
4. **RIT Header Search** - "Student RIT" or "RIT Score" patterns
5. **Fallback** - Any valid 3-digit RIT score (180-280 range)

### DynamoDB Schema
**Orchestration Table** (`ocr-orchestration-and-records-dev`):
- PartitionKey: `TEXTRACT_JOB#{job_id}`
- SortKey: `METADATA`
- TTL: 72 hours

**Reporting Aggregates Table** (`ocr-reporting-aggregates-{env}`):
- Pre-computed class and grade-level aggregates
- Read-only access for MCP analytics server

## Outputs

| Output | Description |
|--------|-------------|
| `ocr_reporting_aggregates_table_name` | DynamoDB table for MCP analytics |
| `ocr_mcp_reporting_read_only_policy_arn` | IAM policy for read-only MCP access |

## Deployment

### Prerequisites
```bash
# Configure AWS CLI
aws configure

# Verify region
aws configure get region
```

### Deploy with Terraform
```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan \
  -var="aws_region=us-east-1" \
  -var="environment=dev" \
  -var="alert_email=your-email@example.com"

# Apply the configuration
terraform apply \
  -var="aws_region=us-east-1" \
  -var="environment=dev" \
  -var="alert_email=your-email@example.com"
```

### Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `us-east-1` |
| `environment` | Environment name | `dev` |
| `alert_email` | Email for malware threat alerts | `sadisteffl@gmail.com` |

## Cost Considerations

### VPC Interface Endpoints
- ~$0.01/hour per endpoint (~$18/month per endpoint)
- Currently enabled: KMS, Step Functions, SNS, SQS, Textract, Logs, Lambda
- To reduce costs during testing, disable interface endpoints

### Lambda Execution
- Pay-per-request with on-demand pricing
- Reserved concurrency limits cost control

### Textract
- Asynchronous document analysis pricing
- Charges per page processed

### DynamoDB
- On-demand capacity mode (pay-per-request)
- TTL auto-expires orchestration records (72 hours)

### S3 Storage
- Lifecycle policies transition to Glacier
- Non-current versions expire after 7 days

## Monitoring & Alerts

### CloudWatch Alarms
- **S3 Malware Detected** - Triggers on any threat found
- **Textract Completion Rate** - Alerts if completion drops below threshold
- **Textract Failure Rate** - Alerts on job failures
- **DynamoDB Throttles** - Alerts on throttled requests
- **DynamoDB System Errors** - Alerts on 5xx errors
- **DynamoDB All Errors** - Alerts on any non-200 responses

### Log Groups
- All Lambda functions encrypted with CMK
- Step Functions execution logs
- GuardDuty malware scan results
- Textract completion notifications
- 7-day retention with Firehose archival to S3

## Compliance Features

This infrastructure aligns with:
- **ISO 27001** - Comprehensive security controls and logging
- **SOC 2** - Encryption, audit trails, and access controls
- **FERPA-ready** - Student data protection with encryption and isolation

## Troubleshooting

### File Stuck in Pre-Processing
1. Check GuardDuty scan status in S3 object tags
2. Review CloudWatch Logs for `/aws/events/guardduty-s3-*`
3. Verify Step Functions execution in console

### Textract Job Timeout
1. Default timeout: 300 seconds (5 minutes)
2. Check Textract service quotas
3. Review document complexity and size

### Malware Alert Not Received
1. Confirm SNS subscription (check email for confirmation link)
2. Verify `alert_email` variable
3. Check SNS topic CloudWatch Logs

### VPC Endpoint Connection Issues
1. Verify security group allows HTTPS to VPC CIDR
2. Check route table associations
3. Confirm VPC endpoint DNS is enabled

## MCP Server Integration

The infrastructure outputs are designed for integration with an **MCP (Model Context Protocol) server** for AI-powered analytics:

```typescript
// Example MCP server configuration
const mcpServer = {
  dynamodbTable: terraform.output.ocr_reporting_aggregates_table_name,
  iamPolicyArn: terraform.output.ocr_mcp_reporting_read_only_policy_arn
};
```

The read-only IAM policy (`ocr_mcp_reporting_read_only`) provides secure access to aggregated analytics data without exposing individual student records.

## Architecture Decisions

### Why Air-Gapped?
- Prevents data exfiltration via internet
- Reduces attack surface to VPC-level only
- Enforces strict egress controls

### Why GuardDuty Malware Protection?
- Native AWS integration with S3 EventBridge
- Automatic tagging for downstream routing
- No additional infrastructure required

### Why Step Functions?
- Visual workflow debugging
- Built-in error handling and retry
- taskToken pattern for async operations

### Why DynamoDB On-Demand?
- No capacity planning required
- Auto-scales with workload
- Cost-effective for sporadic OCR workloads

### Why Kinesis Firehose?
- Automatic batching and compression
- No Lambda function needed for log export
- Cost-effective long-term archival

## License

This infrastructure is provided as an example of security-focused AWS architecture design.

## Author

**Sadi**
- Security Engineering Portfolio
- Shift-Left Security Philosophy
- https://github.com/sadisteffl

---

*Last Updated: 2025*
