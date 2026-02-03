# S3 Malware Scanning and Quarantine Module

This Terraform module implements an automated incident response workflow for detecting and quarantining malware in S3 buckets using AWS GuardDuty Malware Protection.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Upload Files to S3                          │
│              (pre-processing-storage bucket)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │  GuardDuty Malware  │
                  │   Protection Plan   │
                  │   (Scans Files)     │
                  └──────────┬──────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
      ┌───────────────────┐     ┌──────────────────┐
      │  NO_THREATS_FOUND │     │  THREATS_FOUND   │
      │   (Files stay)    │     │  (EventBridge    │
      └───────────────────┘     │   Trigger)       │
                                └────────┬─────────┘
                                         │
                                         ▼
                              ┌────────────────────┐
                              │  Step Functions    │
                              │  Quarantine        │
                              │  State Machine     │
                              └────────┬───────────┘
                                       │
                                       ▼
                              ┌────────────────────┐
                              │  Lambda Function   │
                              │  (Move to          │
                              │   Quarantine)      │
                              └────────┬───────────┘
                                       │
                                       ▼
                              ┌────────────────────┐
                              │  Quarantine Bucket  │
                              │  (Restricted       │
                              │   Access)          │
                              └────────┬───────────┘
                                       │
                                       ▼
                              ┌────────────────────┐
                              │  SNS Alert to      │
                              │  Security Team     │
                              └────────────────────┘
```

## Features

- **Automated Malware Scanning**: GuardDuty scans all files uploaded to the pre-processing S3 bucket
- **Automated Quarantine**: Infected files are automatically moved to a secure quarantine bucket
- **Event-Driven**: Uses EventBridge for real-time response to scan results
- **Security Isolation**: Quarantine bucket has restricted access (security admins only)
- **Alerting**: SNS notifications to security team when malware is detected
- **Comprehensive Logging**: CloudWatch Logs and X-Ray tracing for audit trails
- **Encryption**: KMS encryption for all data at rest and in transit
- **VPC Isolation**: Lambda functions run in a private VPC

## Prerequisites

1. **AWS GuardDuty Enabled**: GuardDuty must be enabled in your AWS account
2. **GuardDuty Malware Protection**: The Malware Protection feature must be enabled in GuardDuty
3. **Email Confirmation**: You must confirm the SNS subscription via email link

## Usage

### 1. Configure Variables

Copy `terraform.tfvars.example` to `terraform.tfvars` and update with your values:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Required variables:
- `alert_email`: Email address for security alerts
- `security_admin_iam_arns`: List of IAM ARNs for security admins

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review the Plan

```bash
terraform plan
```

### 4. Deploy the Infrastructure

```bash
terraform apply
```

### 5. Confirm SNS Subscription

Check your email and click the confirmation link to start receiving alerts.

## How It Works

1. **Upload**: Files are uploaded to the `pre-processing-storage-{environment}-{account-id}` bucket
2. **Scan**: GuardDuty automatically scans the file for malware
3. **Detect**: If malware is found, GuardDuty tags the object and sends an EventBridge event
4. **Quarantine**: Step Functions triggers a Lambda function to move the file to the quarantine bucket
5. **Alert**: SNS sends an email notification to the security team
6. **Access**: Only security admins can access files in the quarantine bucket

## Security Considerations

- **Quarantine Bucket Access**: Restricted to security admins only via bucket policy
- **KMS Encryption**: All sensitive data encrypted with customer-managed KMS keys
- **Lambda VPC Isolation**: Functions run in private subnets with no direct internet access
- **Code Signing**: Lambda functions require code signing validation
- **Least Privilege IAM**: All roles follow the principle of least privilege
- **Versioning**: Both buckets have versioning enabled for recovery
- **Block Public Access**: Both buckets block all public access

## Outputs

After deployment, Terraform will output:

- Pre-processing bucket name and ARN
- Quarantine bucket name and ARN
- SNS topic ARN
- Lambda function ARN
- Step Functions state machine ARN
- GuardDuty malware protection plan ARN
- KMS key ARN
- VPC and security group IDs

## Maintenance

### Viewing Quarantined Files

```bash
aws s3 ls s3://quarantine-storage-prod-123456789012/ --recursive
```

### Downloading Quarantined Files (Security Admins Only)

```bash
aws s3 cp s3://quarantine-storage-prod-123456789012/malicious-file.exe . --profile security-admin
```

### Viewing Logs

```bash
# Lambda logs
aws logs tail /aws/lambda/QuarantineProcessor-prod --follow

# Step Functions logs
aws logs tail /aws/vendedlogs/states/Quarantine-Workflow-prod --follow
```

## Troubleshooting

### Files Not Being Scanned
- Verify GuardDuty is enabled
- Verify Malware Protection plan is active
- Check S3 EventBridge is enabled

### Files Not Being Quarantined
- Check Step Functions executions in AWS Console
- Review Lambda logs for errors
- Verify IAM role permissions

### Not Receiving Alerts
- Confirm SNS subscription (check email)
- Verify SNS topic policy allows publishing
- Check CloudWatch Logs for errors

## Variables Reference

| Variable | Description | Type | Default | Required |
|----------|-------------|------|---------|----------|
| `environment` | Environment name | `string` | `prod` | No |
| `aws_region` | AWS region | `string` | `us-east-1` | No |
| `alert_email` | Security team email | `string` | - | **Yes** |
| `vpc_cidr` | VPC CIDR block | `string` | `10.0.0.0/16` | No |
| `availability_zone_count` | Number of AZs | `number` | `2` | No |
| `security_admin_iam_arns` | Admin IAM ARNs | `list(string)` | `[]` | **Yes** |
| `iam_user_name` | IAM user for docs | `string` | `""` | No |

## Cost Considerations

- **GuardDuty Malware Protection**: Charged per GB scanned
- **S3 Storage**: Standard storage rates apply
- **Lambda**: Pay per invocation + execution time
- **Step Functions**: Pay per state transition
- **SNS**: First 64K/month free, then per message
- **KMS**: $1/month per key + per 10K operations
- **Data Transfer**: Standard AWS rates apply

## License

This infrastructure code is provided as-is for educational and operational purposes.
