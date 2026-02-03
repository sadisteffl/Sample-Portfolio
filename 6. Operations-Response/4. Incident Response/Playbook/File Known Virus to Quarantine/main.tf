provider "aws" {
  region = "us-east-1"
}

provider "null" {}

# Data sources
data "aws_caller_identity" "current" {}

#=============================================================================
# KMS ENCRYPTION
#=============================================================================

resource "aws_kms_key" "encryption_key" {
  description             = "KMS key for S3 malware scanning infrastructure"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags                    = merge(local.common_tags, { Name = "Malware-Scanning-KMS-Key" })
}

resource "aws_kms_alias" "encryption_key" {
  name          = "alias/malware-scanning-key-${var.environment}"
  target_key_id = aws_kms_key.encryption_key.key_id
}

# KMS Key Policy - Allow SNS, Lambda, and GuardDuty to use the key
resource "aws_kms_key_policy" "encryption_key" {
  key_id = aws_kms_key.encryption_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow SNS to Use the Key"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Lambda to Use the Key"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty to Use the Key"
        Effect = "Allow"
        Principal = {
          Service = "malware-protection-plan.guardduty.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

#=============================================================================
# VPC & NETWORKING
#=============================================================================

resource "aws_vpc" "lambda_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "Lambda-VPC-${var.environment}"
  })
}

resource "aws_subnet" "lambda_private_subnet" {
  count             = var.availability_zone_count
  vpc_id            = aws_vpc.lambda_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "Lambda-Private-Subnet-${count.index + 1}-${var.environment}"
  })
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_security_group" "lambda_sg" {
  name        = "lambda-security-group-${var.environment}"
  description = "Security group for Lambda functions"
  vpc_id      = aws_vpc.lambda_vpc.id

  tags = merge(local.common_tags, { Name = "Lambda-SG" })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.lambda_vpc.id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  tags = merge(local.common_tags, { Name = "S3-VPC-Endpoint" })
}

#=============================================================================
# SQS DEAD LETTER QUEUE
#=============================================================================

resource "aws_sqs_queue" "quarantine_processor_dlq" {
  name                      = "quarantine-processor-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.encryption_key.arn

  tags = merge(local.common_tags, { Name = "Quarantine-Processor-DLQ" })
}

#=============================================================================
# LAMBDA CODE SIGNING CONFIG
#=============================================================================

resource "aws_lambda_code_signing_config" "lambda_code_signing" {
  allowed_publishers {
    signing_profile_version_arns = [
      aws_signer_signing_profile.lambda_signing_profile.version_arn
    ]
  }

  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }

  tags = merge(local.common_tags, { Name = "Lambda-Code-Signing-Config" })
}

resource "aws_signer_signing_profile" "lambda_signing_profile" {
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    value = 365
    type  = "DAYS"
  }

  tags = merge(local.common_tags, { Name = "Lambda-Signing-Profile" })
}

#=============================================================================
# LOCALS & TAGS
#=============================================================================

locals {
  common_tags = {
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "MalwareScanning"
  }
}

# Only query IAM access keys if a user name is provided (for testing/documentation)
data "aws_iam_access_keys" "user_keys" {
  count = var.iam_user_name != "" ? 1 : 0
  user  = var.iam_user_name
}

# SNS Topic for Malware Threat Alerts
resource "aws_sns_topic" "malware_threat_alerts" {
  name              = "malware-threat-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.encryption_key.arn
  tags              = merge(local.common_tags, { Name = "Malware-Threat-Alerts" })
}

# SNS Topic Subscription - Email
resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.malware_threat_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email

  # Auto-confirm subscription (you'll still need to click the link in the email)
  # This is for documentation purposes - AWS still requires email confirmation
}

resource "aws_s3_bucket" "pre_processing_storage" {
  bucket        = "pre-processing-storage-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(local.common_tags, { Name = "Pre-Processing-Storage" })
}

resource "aws_s3_bucket_notification" "enable_eventbridge" {
  bucket = aws_s3_bucket.pre_processing_storage.id

  # Enable EventBridge for all S3 events
  eventbridge = true

  # Ignore changes managed by GuardDuty to prevent configuration drift
  lifecycle {
    ignore_changes = [eventbridge]
  }
}

# Ensure EventBridge is enabled using the newer configuration method
resource "aws_s3_bucket_ownership_controls" "pre_processing_storage" {
  bucket = aws_s3_bucket.pre_processing_storage.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "pre_processing_storage" {
  bucket                  = aws_s3_bucket.pre_processing_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "pre_processing_storage" {
  bucket = aws_s3_bucket.pre_processing_storage.id
  versioning_configuration { status = "Enabled" }
}


# NOTE: This would be in an entirely different AWS account to prevent sprawling. 

resource "aws_s3_bucket" "quarantine_storage" {
  bucket        = "quarantine-storage-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(local.common_tags, { Name = "Quarantine-Storage" })
}

resource "aws_s3_bucket_public_access_block" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Bucket policy to restrict quarantine bucket access to security admins only
# Denies all access except from the quarantine Lambda and security admins
resource "aws_s3_bucket_policy" "restrict_quarantine_access" {
  bucket = aws_s3_bucket.quarantine_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowQuarantineLambdaToWriteFiles"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_file_processor.arn
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.quarantine_storage.arn}/*"
      },
      {
        Sid    = "AllowSecurityAdminsFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = var.security_admin_iam_arns
        }
        Action = "s3:*"
        Resource = [
          "${aws_s3_bucket.quarantine_storage.arn}",
          "${aws_s3_bucket.quarantine_storage.arn}/*"
        ]
      },
      {
        Sid    = "DenyAllOtherAccess"
        Effect = "Deny"
        NotPrincipal = {
          AWS = flatten([
            aws_iam_role.lambda_file_processor.arn,
            var.security_admin_iam_arns
          ])
        }
        Action = "s3:*"
        Resource = [
          "${aws_s3_bucket.quarantine_storage.arn}",
          "${aws_s3_bucket.quarantine_storage.arn}/*"
        ]
      }
    ]
  })
}

# GuardDuty Malware Protection for S3: 

resource "aws_guardduty_malware_protection_plan" "s3" {
  role = aws_iam_role.guardduty_malware_protection.arn

  protected_resource {
    s3_bucket {
      bucket_name = aws_s3_bucket.pre_processing_storage.bucket
    }
  }

  actions {
    tagging {
      status = "ENABLED"
    }
  }
}

resource "aws_iam_role" "guardduty_malware_protection" {
  name = "GuardDutyMalwareProtection-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "malware-protection-plan.guardduty.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "guardduty_malware_protection_policy" {
  name = "GuardDutyMalwareProtectionPolicy"
  role = aws_iam_role.guardduty_malware_protection.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [{
      "Sid" : "AllowManagedRuleToSendS3EventsToGuardDuty",
      "Effect" : "Allow",
      "Action" : [
        "events:PutRule",
        "events:DeleteRule",
        "events:PutTargets",
        "events:RemoveTargets"
      ],
      # Robust: Use wildcard + Condition to avoid dependency on AWS naming convention
      "Resource" : [
        "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/*"
      ],
      "Condition" : {
        "StringLike" : {
          "events:ManagedBy" : "malware-protection-plan.guardduty.amazonaws.com"
        }
      }
      },
      {
        "Sid" : "AllowGuardDutyToMonitorEventBridgeManagedRule",
        "Effect" : "Allow",
        "Action" : [
          "events:DescribeRule",
          "events:ListTargetsByRule"
        ],
        # Robust: Use wildcard + Condition to avoid dependency on AWS naming convention
        "Resource" : [
          "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/*"
        ],
        "Condition" : {
          "StringLike" : {
            "events:ManagedBy" : "malware-protection-plan.guardduty.amazonaws.com"
          }
        }
      },
      {
        "Sid" : "AllowPostScanTag",
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObjectTagging",
          "s3:GetObjectTagging",
          "s3:PutObjectVersionTagging",
          "s3:GetObjectVersionTagging"
        ],
        "Resource" : [
          "${aws_s3_bucket.pre_processing_storage.arn}/*"
        ]
      },
      {
        "Sid" : "AllowEnableS3EventBridgeEvents",
        "Effect" : "Allow",
        "Action" : [
          "s3:PutBucketNotification",
          "s3:GetBucketNotification"
        ],
        "Resource" : [
          aws_s3_bucket.pre_processing_storage.arn
        ]
      },
      {
        "Sid" : "AllowPutValidationObject",
        "Effect" : "Allow",
        "Action" : [
          "s3:PutObject"
        ],
        "Resource" : [
          "${aws_s3_bucket.pre_processing_storage.arn}/malware-protection-resource-validation-object"
        ]
      },
      {
        "Sid" : "AllowCheckBucketOwnership",
        "Effect" : "Allow",
        "Action" : [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ],
        "Resource" : [
          aws_s3_bucket.pre_processing_storage.arn
        ]
      },
      {
        "Sid" : "AllowMalwareScan",
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject",
          "s3:GetObjectVersion"
        ],
        "Resource" : [
          "${aws_s3_bucket.pre_processing_storage.arn}/*"
        ]
      }
    ]
    }
  )
}

#=============================================================================
# IAM ROLES FOR LAMBDA & STEP FUNCTIONS
#=============================================================================

# IAM Role for Lambda Functions (Quarantine Processor)
resource "aws_iam_role" "lambda_file_processor" {
  name = "LambdaFileProcessor-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy for Lambda to access S3 and SQS
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "LambdaS3AccessPolicy"
  role = aws_iam_role.lambda_file_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3Operations"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:CopyObject",
          "s3:DeleteObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:HeadObject"
        ]
        Resource = [
          "${aws_s3_bucket.pre_processing_storage.arn}",
          "${aws_s3_bucket.pre_processing_storage.arn}/*",
          "${aws_s3_bucket.quarantine_storage.arn}",
          "${aws_s3_bucket.quarantine_storage.arn}/*"
        ]
      },
      {
        Sid    = "AllowSQSOperations"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.quarantine_processor_dlq.arn
      }
    ]
  })
}

# Attach AWS managed policy for Lambda basic execution
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_file_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Attach AWS managed policy for Lambda VPC execution
resource "aws_iam_role_policy_attachment" "lambda_vpc_execution" {
  role       = aws_iam_role.lambda_file_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Attach AWS managed policy for X-Ray
resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda_file_processor.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# IAM Role for Step Functions
resource "aws_iam_role" "step_functions_processor" {
  name = "StepFunctionsProcessor-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy for Step Functions to invoke Lambda and publish to SNS
resource "aws_iam_role_policy" "step_functions_policy" {
  name = "StepFunctionsPolicy"
  role = aws_iam_role.step_functions_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowInvokeLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.quarantine_processor.arn
      },
      {
        Sid    = "AllowPublishSNS"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.malware_threat_alerts.arn
      },
      {
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowXRay"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Role for EventBridge to invoke Step Functions
resource "aws_iam_role" "eventbridge_invoke_sfn" {
  name = "EventBridgeInvokeStepFunctions-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy for EventBridge to start Step Functions executions
resource "aws_iam_role_policy" "eventbridge_invoke_sfn_policy" {
  name = "EventBridgeInvokeStepFunctionsPolicy"
  role = aws_iam_role.eventbridge_invoke_sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowStartExecution"
        Effect = "Allow"
        Action = [
          "states:StartExecution"
        ]
        Resource = [
          aws_sfn_state_machine.quarantine_processor.arn
        ]
      }
    ]
  })
}

#=============================================================================
# LAMBDA & STEP FUNCTIONS - FILE PROCESSING WORKFLOW
#=============================================================================


# --- 3.5. Lambda Function for Quarantine ---

# Lambda Function Package for quarantine
data "archive_file" "lambda_quarantine_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_quarantine_payload.zip"
  source {
    content  = <<EOF
import boto3
import json
import os
from botocore.exceptions import ClientError

s3 = boto3.client('s3')
SOURCE_BUCKET = os.environ['SOURCE_BUCKET']
QUARANTINE_BUCKET = os.environ['QUARANTINE_BUCKET']

def lambda_handler(event, context):
    """
    Move an infected file from source bucket to quarantine bucket
    """
    try:
        # Extract file information from Step Functions input
        bucket = event.get('bucket', SOURCE_BUCKET)
        key = event.get('objectKey')

        if not bucket or not key:
            raise ValueError("Missing bucket or key in event")

        print(f"Quarantining file: s3://{bucket}/{key}")
        print(f"Full event: {json.dumps(event)}")

        # Check if object exists before copying
        try:
            head_obj = s3.head_object(Bucket=bucket, Key=key)
            print(f"Object found. Size: {head_obj.get('ContentLength')}, Tags: {head_obj.get('TagCount')}")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code')
            if error_code == '404' or 'NoSuchKey' in str(e):
                print(f"ERROR: Object s3://{bucket}/{key} does not exist!")
                print(f"File may have already been moved or deleted")
                raise FileNotFoundError(f"Object {key} not found in bucket {bucket}")
            else:
                raise

        # Copy object to quarantine bucket
        copy_source = {'Bucket': bucket, 'Key': key}
        s3.copy_object(CopySource=copy_source, Bucket=QUARANTINE_BUCKET, Key=key)

        print(f"Successfully copied to quarantine: s3://{QUARANTINE_BUCKET}/{key}")

        # Delete from source
        s3.delete_object(Bucket=bucket, Key=key)

        print(f"Deleted from source: s3://{bucket}/{key}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'File quarantined successfully',
                'source': f's3://{bucket}/{key}',
                'quarantine': f's3://{QUARANTINE_BUCKET}/{key}'
            })
        }

    except FileNotFoundError as e:
        print(f"File not found error: {e}")
        raise e
    except ClientError as e:
        print(f"Error quarantining file: {e}")
        raise e
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise e
EOF
    filename = "lambda_quarantine_function.py"
  }
}

resource "aws_lambda_function" "quarantine_processor" {
  filename         = data.archive_file.lambda_quarantine_zip.output_path
  function_name    = "QuarantineProcessor-${var.environment}"
  role             = aws_iam_role.lambda_file_processor.arn
  handler          = "lambda_quarantine_function.lambda_handler"
  runtime          = "python3.11"
  source_code_hash = data.archive_file.lambda_quarantine_zip.output_base64sha256

  reserved_concurrent_executions = 100
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda_code_signing.arn
  kms_key_arn                    = aws_kms_key.encryption_key.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.quarantine_processor_dlq.arn
  }

  vpc_config {
    subnet_ids         = aws_subnet.lambda_private_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      SOURCE_BUCKET     = aws_s3_bucket.pre_processing_storage.id
      QUARANTINE_BUCKET = aws_s3_bucket.quarantine_storage.id
    }
  }
  tracing_config {
    mode = "Active"
  }


  tags = merge(local.common_tags, { Name = "Quarantine-Processor-Lambda" })

  depends_on = [aws_iam_role_policy_attachment.lambda_basic_execution]
}

# --- 3.6. Step Functions State Machine for Quarantine ---

# CloudWatch Log Group for Quarantine Step Functions
# Note: KMS encryption will be enabled after key policy is applied
resource "aws_cloudwatch_log_group" "quarantine_step_functions_logs" {
  name              = "/aws/vendedlogs/states/Quarantine-Workflow-${var.environment}"
  retention_in_days = 7
  tags              = merge(local.common_tags, { Name = "Quarantine-Step-Functions-Logs" })
}

resource "aws_sfn_state_machine" "quarantine_processor" {
  name     = "Quarantine-Workflow-${var.environment}"
  role_arn = aws_iam_role.step_functions_processor.arn

  definition = <<EOF
{
  "Comment": "Move infected files from pre-processing to quarantine bucket",
  "StartAt": "QuarantineFile",
  "States": {
    "QuarantineFile": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.quarantine_processor.arn}",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "NotifyQuarantineFailure"
        }
      ],
      "Next": "QuarantineSuccess"
    },
    "NotifyQuarantineFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.malware_threat_alerts.arn}",
        "Message.$": "States.Format('Failed to quarantine infected file from pre-processing bucket.\\n\\nError: {}', $.error)",
        "MessageAttributes": {
          "MessageType": {
            "DataType": "String",
            "StringValue": "QuarantineError"
          }
        }
      },
      "Next": "Failure"
    },
    "QuarantineSuccess": {
      "Type": "Succeed"
    },
    "Failure": {
      "Type": "Fail"
    }
  }
}
EOF

  # Enable CloudWatch Logging
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.quarantine_step_functions_logs.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  # Enable X-Ray tracing
  tracing_configuration {
    enabled = true
  }

  tags = merge(local.common_tags, { Name = "Quarantine-StateMachine" })
}

# --- 4. EventBridge Rules to Trigger Quarantine Workflow ---

# Trigger Step Functions when threats are detected
resource "aws_cloudwatch_event_rule" "trigger_quarantine_processing" {
  name        = "TriggerQuarantineOnThreatFound"
  description = "Trigger Step Functions to move infected files to quarantine bucket"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Malware Protection Object Scan Result"]
    detail = {
      scanResultDetails = {
        scanResultStatus = ["THREATS_FOUND"]
      }
    }
  })
}

# EventBridge Target - Quarantine Step Functions
resource "aws_cloudwatch_event_target" "quarantine_step_functions_trigger" {
  rule      = aws_cloudwatch_event_rule.trigger_quarantine_processing.name
  target_id = "StepFunctions-QuarantineProcessor"
  arn       = aws_sfn_state_machine.quarantine_processor.arn
  role_arn  = aws_iam_role.eventbridge_invoke_sfn.arn

  # Transform event to pass bucket and object key
  input_transformer {
    input_paths = {
      bucket    = "$.detail.s3ObjectDetails.bucketName"
      objectKey = "$.detail.s3ObjectDetails.objectKey"
    }

    input_template = "{\"bucket\": \"<bucket>\", \"objectKey\": \"<objectKey>\"}"
  }
}

# Permission for EventBridge to invoke quarantine Lambda
resource "aws_lambda_permission" "allow_quarantine_eventbridge" {
  statement_id  = "AllowQuarantineExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.quarantine_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger_quarantine_processing.arn
}