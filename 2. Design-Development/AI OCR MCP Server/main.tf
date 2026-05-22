#=============================================================================
# OCR Pipeline - Maximum Security (Air-Gapped / No Internet)
#=============================================================================


terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Local variables for tagging
locals {
  common_tags = {
    Project     = "OCR-Pipeline"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Security    = "Max-Isolation"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" { state = "available" }

#=============================================================================
# VARIABLES
#=============================================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "alert_email" {
  description = "Email address for malware threat alerts"
  type        = string
  default     = "sadisteffl@gmail.com"
}

#=============================================================================
# KMS ENCRYPTION
#=============================================================================

# KMS Customer Managed Key for encryption at rest
resource "aws_kms_key" "second_encryption_key" {
  description             = "KMS CMK for OCR Pipeline encryption - ${var.environment} - v2"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "OCR-Pipeline-CMK-${var.environment}-v2"
  })
}

# KMS Key Policy - Allow AWS services to use the key
resource "aws_kms_key_policy" "second_encryption_key_policy" {
  key_id = aws_kms_key.second_encryption_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSNSUsage"
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
        Sid    = "AllowLambdaUsage"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsUsage"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
        Action = [
          "kms:DescribeKey",
          "kms:GenerateDataKey*",
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailUsage"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowDynamoDBUsage"
        Effect = "Allow"
        Principal = {
          Service = "dynamodb.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3Usage"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowStepFunctionsUsage"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.step_functions_processor.arn,
            aws_iam_role.ocr_step_functions_role.arn
          ]
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowTextractServiceUsage"
        Effect = "Allow"
        Principal = {
          Service = "textract.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDutyMalwareProtection"
        Effect = "Allow"
        Principal = {
          Service = "malware-protection-plan.guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowIAMPublishersToSNS"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.textract_sns_role.arn,
            aws_iam_role.ocr_lambda_execution_role1.arn
          ]
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = "*"
      }
    ]
  })
}

# KMS Alias for easier reference
resource "aws_kms_alias" "second_encryption_key_alias" {
  name          = "alias/ocr-pipeline-key-${var.environment}-v2"
  target_key_id = aws_kms_key.second_encryption_key.id
}

#=============================================================================
# SNS NOTIFICATIONS
#=============================================================================

# SNS Topic for Malware Threat Alerts
resource "aws_sns_topic" "malware_threat_alerts" {
  name              = "malware-threat-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.second_encryption_key.arn
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

#=============================================================================
# VPC INFRASTRUCTURE
#=============================================================================

# VPC for Lambda functions (air-gapped, private)
resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "Lambda-VPC-${var.environment}"
  })
}

# Private subnets for Lambda functions (one per AZ for high availability)
resource "aws_subnet" "lambda_private_subnet" {
  count             = 1
  vpc_id            = aws_vpc.lambda_vpc.id
  cidr_block        = cidrsubnet(aws_vpc.lambda_vpc.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "Lambda-Private-Subnet-${count.index + 1}-${var.environment}"
    Type = "Private"
  })
}

# Security Group for Lambda functions
resource "aws_security_group" "lambda_sg" {
  name        = "Lambda-SG-${var.environment}"
  description = "Security group for Lambda functions"
  vpc_id      = aws_vpc.lambda_vpc.id

  # Allow outbound HTTPS traffic to VPC Interface Endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.lambda_vpc.cidr_block]
    description = "Allow HTTPS to VPC Interface Endpoints (Textract, KMS, SNS, SQS, etc.)"
  }

  # Allow outbound traffic to S3 via Gateway VPC Endpoint prefix list
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    prefix_list_ids = ["pl-63a5400a"]
    description     = "Allow S3 access via Gateway VPC Endpoint"
  }

  # Allow ingress from within the security group for VPC endpoint communication
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    self        = true
    description = "Allow HTTPS within security group for VPC endpoint callbacks"
  }

  tags = merge(local.common_tags, {
    Name = "Lambda-Security-Group"
  })
}

# VPC Endpoints for AWS Services
# S3 Gateway Endpoint (required for S3 access)
# Open policy to allow Lambda to access S3 buckets through the VPC endpoint
# S3 actions are controlled by IAM policies, not VPC endpoint policies
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.lambda_vpc.id
  service_name = "com.amazonaws.${var.aws_region}.s3"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "FullS3AccessThroughEndpoint"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:*"
        Resource  = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "S3-VPC-Endpoint"
  })
}

# DynamoDB Gateway Endpoint (required for DynamoDB access)
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.lambda_vpc.id
  service_name = "com.amazonaws.${var.aws_region}.dynamodb"

  tags = merge(local.common_tags, {
    Name = "DynamoDB-VPC-Endpoint"
  })
}

# Interface VPC Endpoints (DISABLED for cost savings during testing)
# These cost ~$0.01/hour per endpoint (~$18/month per endpoint)
# To re-enable, uncomment the following block:

# KMS VPC Endpoint - REQUIRED for KMS encryption
resource "aws_vpc_endpoint" "kms" {
  vpc_id              = aws_vpc.lambda_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.lambda_private_subnet[*].id

  security_group_ids = [
    aws_security_group.lambda_sg.id
  ]

  tags = merge(local.common_tags, {
    Name = "KMS-VPC-Endpoint"
  })
}

# Step Functions VPC Endpoint - REQUIRED for Step Functions callbacks
resource "aws_vpc_endpoint" "states" {
  vpc_id              = aws_vpc.lambda_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.states"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.lambda_private_subnet[*].id

  security_group_ids = [
    aws_security_group.lambda_sg.id
  ]

  tags = merge(local.common_tags, {
    Name = "StepFunctions-VPC-Endpoint"
  })
}

# SNS VPC Endpoint - May be required for Step Functions error notifications
resource "aws_vpc_endpoint" "sns" {
  vpc_id              = aws_vpc.lambda_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.sns"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.lambda_private_subnet[*].id

  security_group_ids = [
    aws_security_group.lambda_sg.id
  ]

  tags = merge(local.common_tags, {
    Name = "SNS-VPC-Endpoint"
  })
}

# SQS VPC Endpoint - May be required for DLQ access
resource "aws_vpc_endpoint" "sqs" {
  vpc_id              = aws_vpc.lambda_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.sqs"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.lambda_private_subnet[*].id

  security_group_ids = [
    aws_security_group.lambda_sg.id
  ]

  tags = merge(local.common_tags, {
    Name = "SQS-VPC-Endpoint"
  })
}

locals {
  vpc_endpoint_services = [
    "textract",
    "logs",
    "lambda"
  ]
}

resource "aws_vpc_endpoint" "interface_endpoints" {
  count = length(local.vpc_endpoint_services)

  vpc_id              = aws_vpc.lambda_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.${local.vpc_endpoint_services[count.index]}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true

  subnet_ids = aws_subnet.lambda_private_subnet[*].id

  security_group_ids = [
    aws_security_group.lambda_sg.id
  ]

  # Policy to restrict access to resources in this account only
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountAccess"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${upper(local.vpc_endpoint_services[count.index])}-VPC-Endpoint"
  })
}

# Route table for private subnets
resource "aws_route_table" "lambda_private_rt" {
  vpc_id = aws_vpc.lambda_vpc.id

  # Add routes to VPC endpoints
  route {
    cidr_block = aws_vpc.lambda_vpc.cidr_block
    gateway_id = "local"
  }

  tags = merge(local.common_tags, {
    Name = "Lambda-Private-Route-Table"
  })
}

# Route table association for private subnets
resource "aws_route_table_association" "lambda_private_rta" {
  count          = 1
  subnet_id      = aws_subnet.lambda_private_subnet[count.index].id
  route_table_id = aws_route_table.lambda_private_rt.id
}

# Update S3 and DynamoDB VPC endpoints with route table
resource "aws_vpc_endpoint_route_table_association" "s3_vpc_endpoint_rt_association" {
  route_table_id  = aws_route_table.lambda_private_rt.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint_route_table_association" "dynamodb_vpc_endpoint_rt_association" {
  route_table_id  = aws_route_table.lambda_private_rt.id
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
}

#=============================================================================
# S3 PRE-PROCESING
#=============================================================================

# 1. Pre-Processing (Incoming)
resource "aws_s3_bucket" "pre_processing_storage" {
  bucket        = "pre-processing-storage-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(local.common_tags, { Name = "Pre-Processing-Storage" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pre_processed_storage" {
  bucket = aws_s3_bucket.pre_processing_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# 2. Processed (Clean Files)
resource "aws_s3_bucket" "processed_storage" {
  bucket        = "processed-storage-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(local.common_tags, { Name = "Processed-Storage" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "processed_storage" {
  bucket = aws_s3_bucket.processed_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "processed_storage" {
  bucket = aws_s3_bucket.processed_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "processed_storage" {
  bucket = aws_s3_bucket.processed_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle configuration - expire non-current versions after 7 days
resource "aws_s3_bucket_lifecycle_configuration" "processed_storage" {
  bucket = aws_s3_bucket.processed_storage.id

  rule {
    id     = "processed-lifecycle"
    status = "Enabled"

    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Expire non-current versions after 7 days
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "processed_storage" {
  bucket = aws_s3_bucket.processed_storage.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Enable EventBridge notifications for processed_storage bucket
resource "aws_s3_bucket_notification" "processed_storage_eventbridge" {
  bucket      = aws_s3_bucket.processed_storage.id
  eventbridge = true
}

# 3. Quarantine (Infected Files)
resource "aws_s3_bucket" "quarantine_storage" {
  bucket        = "quarantine-storage-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags          = merge(local.common_tags, { Name = "Quarantine-Storage" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
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


# Lifecycle configuration - expire non-current versions after 7 days
resource "aws_s3_bucket_lifecycle_configuration" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id

  rule {
    id     = "quarantine-lifecycle"
    status = "Enabled"

    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Expire non-current versions after 7 days
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "quarantine_storage" {
  bucket = aws_s3_bucket.quarantine_storage.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Enable S3 EventBridge notifications for GuardDuty Malware Protection
# Note: GuardDuty Malware Protection manages this configuration via IAM permissions
resource "aws_s3_bucket_notification" "enable_eventbridge" {
  bucket = aws_s3_bucket.pre_processing_storage.id

  # Enable EventBridge for all S3 events
  eventbridge = true

  # Ignore changes managed by GuardDuty to prevent configuration drift
  lifecycle {
    ignore_changes = [eventbridge]
  }
}

resource "null_resource" "enable_eventbridge_s3" {
  depends_on = [aws_s3_bucket.pre_processing_storage]

  provisioner "local-exec" {
    command = "aws s3api put-bucket-notification-configuration --bucket ${aws_s3_bucket.pre_processing_storage.id} --notification-configuration 'EventBridgeConfiguration={}' --region ${var.aws_region}"
  }

  # Only run when the bucket is created or recreated
  triggers = {
    bucket_arn = aws_s3_bucket.pre_processing_storage.arn
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

# Lifecycle configuration - expire non-current versions after 7 days
resource "aws_s3_bucket_lifecycle_configuration" "pre_processing_storage" {
  bucket = aws_s3_bucket.pre_processing_storage.id

  rule {
    id     = "pre-processing-lifecycle"
    status = "Enabled"

    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Expire non-current versions after 7 days
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# Bucket policy to allow ONLY the quarantine Lambda to access infected files
# All other users are blocked by IAM policies (default deny)
resource "aws_s3_bucket_policy" "block_malware_downloads" {
  bucket = aws_s3_bucket.pre_processing_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowQuarantineLambdaToAccessInfectedFiles"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_file_processor.arn
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.pre_processing_storage.arn}/*"
        Condition = {
          StringEquals = {
            "s3:ExistingObjectTag/GuardDutyMalwareScanStatus" : "THREATS_FOUND"
          }
        }
      }
    ]
  })
}


#=============================================================================
# GUARDDUTY MALWARE PROTECTION
#=============================================================================


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
      # FIXED: Replaced hardcoded Account ID/Region with variables
      "Resource" : [
        "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"
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
        "Resource" : [
          "arn:aws:events:${var.aws_region}:${data.aws_caller_identity.current.account_id}:rule/DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*"
        ]
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
        "Sid" : "AllowKMSForMalwareScan",
        "Effect" : "Allow",
        "Action" : [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        "Resource" : [
          aws_kms_key.second_encryption_key.arn
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
# LAMBDA & STEP FUNCTIONS - FILE PROCESSING WORKFLOW
#=============================================================================

# --- 1. IAM Roles ---

# Lambda Execution Role
resource "aws_iam_role" "lambda_file_processor" {
  name = "Lambda-File-Processor-${var.environment}"

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

# Lambda IAM Policy
resource "aws_iam_role_policy" "lambda_file_processor_policy" {
  name = "LambdaFileProcessorPolicy"
  role = aws_iam_role.lambda_file_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:GetObjectTagging"
        ]
        Resource = [
          "${aws_s3_bucket.pre_processing_storage.arn}/*",
          aws_s3_bucket.pre_processing_storage.arn
        ]
      },
      {
        Sid    = "S3WriteAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.processed_storage.arn}/*",
          "${aws_s3_bucket.quarantine_storage.arn}/*",
          "${aws_s3_bucket.pre_processing_storage.arn}/*"
        ]
      },
      {
        Sid    = "S3CopyAccess"
        Effect = "Allow"
        Action = [
          "s3:CopyObject",
          "s3:GetObject",
          "s3:GetObjectVersion"
        ]
        Resource = [
          "${aws_s3_bucket.pre_processing_storage.arn}/*",
          "${aws_s3_bucket.processed_storage.arn}/*",
          "${aws_s3_bucket.quarantine_storage.arn}/*"
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/*"
      },
      {
        Sid    = "StepFunctionsExecution"
        Effect = "Allow"
        Action = [
          "states:SendTaskSuccess",
          "states:SendTaskFailure"
        ]
        Resource = "*"
      },
      {
        Sid    = "SQSDLQPermissions"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sqs_queue.file_processor_dlq.arn,
          aws_sqs_queue.quarantine_processor_dlq.arn
        ]
      },
      {
        Sid    = "ENIPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

# Step Functions Execution Role
resource "aws_iam_role" "step_functions_processor" {
  name = "Step-Functions-Processor-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
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

# EventBridge Role to Invoke Step Functions
resource "aws_iam_role" "eventbridge_invoke_sfn" {
  name = "EventBridge-Invoke-SFN-${var.environment}"

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

# EventBridge Policy to Start Step Function Executions
resource "aws_iam_role_policy" "eventbridge_invoke_sfn_policy" {
  name = "EventBridgeInvokeSFNPolicy"
  role = aws_iam_role.eventbridge_invoke_sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "states:StartExecution"
        Resource = [
          aws_sfn_state_machine.file_processor.arn,
          aws_sfn_state_machine.quarantine_processor.arn,
          aws_sfn_state_machine.ocr_workflow2.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

# Step Functions IAM Policy
resource "aws_iam_role_policy" "step_functions_processor_policy" {
  name = "StepFunctionsProcessorPolicy"
  role = aws_iam_role.step_functions_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.file_processor.arn,
          aws_lambda_function.quarantine_processor.arn,
          aws_lambda_function.start_textract_job.arn,
          aws_lambda_function.process_textract_results.arn
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.malware_threat_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

# --- 2. Lambda Function ---

# Lambda Function Package (inline code for simplicity)
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_payload.zip"
  source {
    content  = <<EOF
import boto3
import json
import os
from botocore.exceptions import ClientError

s3 = boto3.client('s3')
SOURCE_BUCKET = os.environ['SOURCE_BUCKET']
DEST_BUCKET = os.environ['DEST_BUCKET']

def lambda_handler(event, context):
    """
    Move a file from source bucket to destination bucket
    """
    try:
        # Extract file information from Step Functions input
        bucket = event.get('bucket', SOURCE_BUCKET)
        key = event.get('objectKey')

        if not bucket or not key:
            raise ValueError("Missing bucket or key in event")

        print(f"Processing file: s3://{bucket}/{key}")

        # Copy object to destination
        copy_source = {'Bucket': bucket, 'Key': key}
        s3.copy_object(CopySource=copy_source, Bucket=DEST_BUCKET, Key=key)

        print(f"Successfully copied to: s3://{DEST_BUCKET}/{key}")

        # Delete from source
        s3.delete_object(Bucket=bucket, Key=key)

        print(f"Deleted from source: s3://{bucket}/{key}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'File moved successfully',
                'source': f's3://{bucket}/{key}',
                'destination': f's3://{DEST_BUCKET}/{key}'
            })
        }

    except ClientError as e:
        print(f"Error processing file: {e}")
        raise e
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise e
EOF
    filename = "lambda_function.py"
  }
}


# Dead Letter Queues for Lambda Functions
resource "aws_sqs_queue" "file_processor_dlq" {
  name                      = "file-processor-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.second_encryption_key.arn

  tags = merge(local.common_tags, { Name = "File-Processor-DLQ" })
}

resource "aws_sqs_queue" "quarantine_processor_dlq" {
  name                      = "quarantine-processor-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.second_encryption_key.arn

  tags = merge(local.common_tags, { Name = "Quarantine-Processor-DLQ" })
}

# DLQ for Start Textract Job Lambda
resource "aws_sqs_queue" "start_textract_dlq" {
  name                      = "start-textract-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.second_encryption_key.arn

  tags = merge(local.common_tags, { Name = "Start-Textract-DLQ" })
}

# DLQ for Process Textract Results Lambda
resource "aws_sqs_queue" "process_textract_dlq" {
  name                      = "process-textract-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.second_encryption_key.arn

  tags = merge(local.common_tags, { Name = "Process-Textract-DLQ" })
}

# Lambda Code Signing Configuration
resource "aws_lambda_code_signing_config" "lambda_code_signing" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda_signing_profile.version_arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }

  tags = merge(local.common_tags, { Name = "Lambda-Code-Signing-Config" })
}

# Signer Signing Profile
resource "aws_signer_signing_profile" "lambda_signing_profile" {
  platform_id = "AWSLambda-SHA384-ECDSA"

  signature_validity_period {
    type  = "DAYS"
    value = 180
  }

  tags = merge(local.common_tags, { Name = "Lambda-Signing-Profile" })
}

resource "aws_lambda_function" "file_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "FileProcessor-${var.environment}"
  role             = aws_iam_role.lambda_file_processor.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.11"
  timeout          = 300
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  reserved_concurrent_executions = 100
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda_code_signing.arn
  kms_key_arn                    = aws_kms_key.second_encryption_key.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.file_processor_dlq.arn
  }

  vpc_config {
    subnet_ids         = aws_subnet.lambda_private_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      SOURCE_BUCKET = aws_s3_bucket.pre_processing_storage.id
      DEST_BUCKET   = aws_s3_bucket.processed_storage.id
    }
  }


  tags = merge(local.common_tags, { Name = "File-Processor-Lambda" })

  depends_on = [aws_iam_role_policy_attachment.lambda_basic_execution]
}

# Lambda Basic Execution Attachment
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_file_processor.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- 3. Step Functions State Machine ---

# CloudWatch Log Group for Step Functions
resource "aws_cloudwatch_log_group" "step_functions_logs" {
  name              = "/aws/vendedlogs/states/File-Processor-Workflow-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "Step-Functions-Logs" })

  depends_on = [aws_kms_key.second_encryption_key]
}

resource "aws_sfn_state_machine" "file_processor" {
  name     = "File-Processor-Workflow-${var.environment}"
  role_arn = aws_iam_role.step_functions_processor.arn

  definition = <<EOF
{
  "Comment": "Move clean files from pre-processing to processed bucket",
  "StartAt": "MoveFile",
  "States": {
    "MoveFile": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.file_processor.arn}",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "NotifyFailure"
        }
      ],
      "Next": "Success"
    },
    "NotifyFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.malware_threat_alerts.arn}",
        "Message": "Failed to move clean file from pre-processing to processed bucket.\n\nError: $.error",
        "MessageAttributes": {
          "MessageType": {
            "DataType": "String",
            "StringValue": "FileProcessingError"
          }
        }
      },
      "Next": "Failure"
    },
    "Success": {
      "Type": "Succeed"
    },
    "Failure": {
      "Type": "Fail"
    }
  }
}
EOF

  encryption_configuration {
    kms_key_id                        = aws_kms_key.second_encryption_key.arn
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
    kms_data_key_reuse_period_seconds = 900
  }

  # Enable CloudWatch Logging
  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions_logs.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }


  tags = merge(local.common_tags, { Name = "File-Processor-StateMachine" })
}

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
  timeout          = 300
  source_code_hash = data.archive_file.lambda_quarantine_zip.output_base64sha256

  reserved_concurrent_executions = 100
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda_code_signing.arn
  kms_key_arn                    = aws_kms_key.second_encryption_key.arn

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


  tags = merge(local.common_tags, { Name = "Quarantine-Processor-Lambda" })

  depends_on = [aws_iam_role_policy_attachment.lambda_basic_execution]
}

# --- 3.6. Step Functions State Machine for Quarantine ---

# CloudWatch Log Group for Quarantine Step Functions
# Note: KMS encryption will be enabled after key policy is applied
resource "aws_cloudwatch_log_group" "quarantine_step_functions_logs" {
  name              = "/aws/vendedlogs/states/Quarantine-Workflow-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
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
        "Message": "Failed to quarantine infected file from pre-processing bucket.\n\nError: $.error",
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
    include_execution_data = false
    level                  = "ERROR"
  }

  encryption_configuration {
    kms_key_id                        = aws_kms_key.second_encryption_key.arn
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
    kms_data_key_reuse_period_seconds = 900
  }

  tags = merge(local.common_tags, { Name = "Quarantine-StateMachine" })
}

# --- 4. EventBridge Rules to Trigger Workflows ---

# Trigger Step Functions when clean scan is detected
resource "aws_cloudwatch_event_rule" "trigger_file_processing" {
  name        = "TriggerFileProcessingOnCleanScan"
  description = "Trigger Step Functions to move clean files to processed bucket"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Malware Protection Object Scan Result"]
    detail = {
      scanResultDetails = {
        scanResultStatus = ["NO_THREATS_FOUND"]
      }
    }
  })
}

# EventBridge Target - Step Functions
resource "aws_cloudwatch_event_target" "step_functions_trigger" {
  rule      = aws_cloudwatch_event_rule.trigger_file_processing.name
  target_id = "StepFunctions-FileProcessor"
  arn       = aws_sfn_state_machine.file_processor.arn
  role_arn  = aws_iam_role.eventbridge_invoke_sfn.arn

  # Transform GuardDuty event to extract bucket and objectKey for Lambda
  input_transformer {
    input_paths = {
      bucket    = "$.detail.s3ObjectDetails.bucketName"
      objectKey = "$.detail.s3ObjectDetails.objectKey"
    }

    input_template = "{\"bucket\": \"<bucket>\", \"objectKey\": \"<objectKey>\"}"
  }
}


# Permission for EventBridge to start Step Functions execution
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.file_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger_file_processing.arn
}

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

#=============================================================================
# LOGGING ARCHITECTURE (EventBridge + CloudWatch)
#=============================================================================

# --- 1. Log Groups ---

# FIXED: Added missing log group for Threats with KMS encryption
resource "aws_cloudwatch_log_group" "s3_malware_scan_logs" {
  name              = "/aws/events/guardduty-s3-malware-threats"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
}

# CloudWatch Log Group for clean scans with KMS encryption
resource "aws_cloudwatch_log_group" "clean_scans" {
  name              = "/aws/events/guardduty-s3-clean-scans"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
}

# --- 2. EventBridge Rules ---

resource "aws_cloudwatch_event_rule" "capture_malware_threats_only" {
  name        = "CaptureS3MalwareThreats"
  description = "Log ONLY infected files found by GuardDuty"

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


resource "aws_cloudwatch_event_rule" "capture_clean_scans" {
  name        = "CaptureS3CleanScans"
  description = "Log only CLEAN files scanned by GuardDuty"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Malware Protection Object Scan Result"]
    detail = {
      scanResultDetails = {
        scanResultStatus = ["NO_THREATS_FOUND"]
      }
    }
  })
}

# --- 3. Targets ---

# FIXED: Added missing Target for Threats
resource "aws_cloudwatch_event_target" "log_threat_results" {
  rule = aws_cloudwatch_event_rule.capture_malware_threats_only.name
  arn  = aws_cloudwatch_log_group.s3_malware_scan_logs.arn
}

# Send SNS notification for malware threats
resource "aws_cloudwatch_event_target" "sns_threat_alerts" {
  rule      = aws_cloudwatch_event_rule.capture_malware_threats_only.name
  arn       = aws_sns_topic.malware_threat_alerts.arn
  target_id = "SNS-Threat-Alerts"

  # Transform the event into a readable message format
  input_transformer {
    input_paths = {
      bucket     = "$.detail.s3ObjectDetails.bucketName"
      objectKey  = "$.detail.s3ObjectDetails.objectKey"
      threatName = "$.detail.scanResultDetails.threats[0].name"
      scanTime   = "$.time"
      region     = "$.region"
    }

    input_template = "\"MALWARE THREAT DETECTED - Bucket: <bucket> - File: <objectKey> - Threat: <threatName> - Time: <scanTime> - Region: <region> - Immediate action required!\""
  }
}

resource "aws_cloudwatch_event_target" "log_clean_results" {
  rule = aws_cloudwatch_event_rule.capture_clean_scans.name
  arn  = aws_cloudwatch_log_group.clean_scans.arn
}


# --- 4. Permissions (Resource Policy) ---l

# Unified Policy Document
# REPLACE THE "data" BLOCK AT LINE 179-198 WITH THIS:
data "aws_iam_policy_document" "allow_events_logging_combined" {
  statement {
    sid = "AllowEventBridgeToLogGroups"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = [
      # 1. Access to the Log Group itself (Required to create the stream)
      aws_cloudwatch_log_group.s3_malware_scan_logs.arn,
      aws_cloudwatch_log_group.clean_scans.arn,

      # 2. Access to the Streams inside (Required to put the log events)
      "${aws_cloudwatch_log_group.s3_malware_scan_logs.arn}:*",
      "${aws_cloudwatch_log_group.clean_scans.arn}:*"
    ]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
}

# Apply combined policy
resource "aws_cloudwatch_log_resource_policy" "allow_events_logging_policy" {
  policy_name     = "AllowEventBridgeToLogGroups"
  policy_document = data.aws_iam_policy_document.allow_events_logging_combined.json
}

# SNS Topic Policy to allow EventBridge to publish alerts
resource "aws_sns_topic_policy" "allow_eventbridge_publish" {
  arn = aws_sns_topic.malware_threat_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgeToPublishSNSTopic"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.malware_threat_alerts.arn
      }
    ]
  })
}

# --- 5. Metrics & Alarms ---

resource "aws_cloudwatch_log_metric_filter" "malware_threat_metric" {
  name           = "GuardDutyMalwareThreatCount"
  pattern        = "{ $.detail.scanResultStatus = \"THREATS_FOUND\" }"
  log_group_name = aws_cloudwatch_log_group.s3_malware_scan_logs.name

  metric_transformation {
    name          = "InfectedFilesDetected"
    namespace     = "GuardDuty/S3Malware"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "malware_threat_alarm" {
  alarm_name          = "S3-Malware-Detected-Alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = aws_cloudwatch_log_metric_filter.malware_threat_metric.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.malware_threat_metric.metric_transformation[0].namespace
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors for any S3 objects flagged as malware by GuardDuty."
  treat_missing_data  = "notBreaching"
}

#=============================================================================
# SECURITY PROTECTION (CloudTrail)
#=============================================================================

resource "aws_cloudtrail" "cloudtrail_main" {
  name                          = "cloudtrail-${var.environment}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  sns_topic_name                = aws_sns_topic.cloudtrail_notifications.arn
  kms_key_id                    = aws_kms_key.second_encryption_key.arn
}

resource "aws_sns_topic" "cloudtrail_notifications" {
  name              = "cloudtrail-notifications-${var.environment}"
  kms_master_key_id = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "CloudTrail-Notifications" })
}

resource "aws_sns_topic_policy" "cloudtrail_notifications" {
  arn = aws_sns_topic.cloudtrail_notifications.arn
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "CloudTrailSNSPublish",
        "Effect" : "Allow",
        "Principal" : { "Service" : "cloudtrail.amazonaws.com" },
        "Action" : "SNS:Publish",
        "Resource" : aws_sns_topic.cloudtrail_notifications.arn
      }
    ]
  })
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudtrail-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  # FIXED: Updated Tag name
  tags = merge(local.common_tags, { Name = "CloudTrail-Logs" })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

# KMS Server-Side Encryption Configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle configuration - expire non-current versions after 7 days
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "cloudtrail-lifecycle"
    status = "Enabled"

    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Expire non-current versions after 7 days
    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    # Transition to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Delete after 5 years
    expiration {
      days = 1825 # 5 years (must be greater than transition days)
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "AWSCloudTrailAclCheck20150319",
        "Effect" : "Allow",
        "Principal" : { "Service" : "cloudtrail.amazonaws.com" },
        "Action" : "s3:GetBucketAcl",
        "Resource" : aws_s3_bucket.cloudtrail.arn,
        "Condition" : {
          "StringEquals" : {
            "aws:SourceArn" : "${aws_cloudtrail.cloudtrail_main.arn}"
          }
        }
      },
      {
        "Sid" : "AWSCloudTrailWrite20150319",
        "Effect" : "Allow",
        "Principal" : { "Service" : "cloudtrail.amazonaws.com" },
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        "Condition" : {
          "StringEquals" : {
            "s3:x-amz-acl" : "bucket-owner-full-control",
            "aws:SourceArn" : "${aws_cloudtrail.cloudtrail_main.arn}"
          }
        }
      }
    ]
    }
  )
}

## PART 2 -- DO NOT EVER REMOVE! 


#=============================================================================
# OCR PROCESSING - EVENTBRIDGE TRIGGER
#=============================================================================

# EventBridge Rule to trigger OCR processing when clean files land in processed_storage
resource "aws_cloudwatch_event_rule" "trigger_ocr_processing" {
  name        = "TriggerOCRProcessing"
  description = "Trigger OCR workflow when clean files are moved to processed storage"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["Object Created"]
    detail = {
      bucket = {
        name = [aws_s3_bucket.processed_storage.bucket]
      }
      object = {
        key = [{
          prefix = "" # Match all objects
        }]
      }
    }
  })

  tags = merge(local.common_tags, { Name = "OCR-Processing-Trigger" })
}


#-------------------------------------------------------------------------------
# TEXTRACT RESULTS ARCHIVE BUCKET
#-------------------------------------------------------------------------------

resource "aws_s3_bucket" "textract_results_archive" {
  bucket = "textract-results-archive-${var.environment}-${data.aws_caller_identity.current.account_id}"
  tags = merge(local.common_tags, {
    Name               = "Textract-Results-Archive"
    CostCenter         = "OCR-Processing"
    DataClassification = "Confidential"
    Purpose            = "Archive-Processed-Results"
  })
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "textract_results_archive" {
  bucket                  = aws_s3_bucket.textract_results_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning
resource "aws_s3_bucket_versioning" "textract_results_archive" {
  bucket = aws_s3_bucket.textract_results_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

# KMS Server-Side Encryption Configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "textract_results_archive" {
  bucket = aws_s3_bucket.textract_results_archive.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle configuration - expire non-current versions after 7 days
resource "aws_s3_bucket_lifecycle_configuration" "textract_results_archive" {
  bucket = aws_s3_bucket.textract_results_archive.id

  rule {
    id     = "textract-results-lifecycle"
    status = "Enabled"

    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Expire non-current versions after 7 days
    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    # Transition to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Expire after 365 days (must be greater than transition days)
    expiration {
      days = 365
    }
  }
}

#=============================================================================
# CLOUDWATCH LOGS ARCHIVE TO S3
#=============================================================================

#-------------------------------------------------------------------------------
# S3 BUCKET FOR CLOUDWATCH LOGS ARCHIVE
#-------------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudwatch_logs_archive" {
  bucket = "cloudwatch-logs-archive-${var.environment}-${data.aws_caller_identity.current.account_id}"
  tags = merge(local.common_tags, {
    Name               = "CloudWatch-Logs-Archive"
    CostCenter         = "Logging"
    DataClassification = "Confidential"
    Purpose            = "CloudWatch-Logs-Long-Term-Archive"
  })
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "cloudwatch_logs_archive" {
  bucket                  = aws_s3_bucket.cloudwatch_logs_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning
resource "aws_s3_bucket_versioning" "cloudwatch_logs_archive" {
  bucket = aws_s3_bucket.cloudwatch_logs_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

# KMS Server-Side Encryption Configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudwatch_logs_archive" {
  bucket = aws_s3_bucket.cloudwatch_logs_archive.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.second_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Lifecycle policy: Transition to Glacier after 30 days, delete after 5 years
resource "aws_s3_bucket_lifecycle_configuration" "cloudwatch_logs_archive" {
  bucket = aws_s3_bucket.cloudwatch_logs_archive.id

  rule {
    id     = "cloudwatch-logs-lifecycle"
    status = "Enabled"

    # Apply to all objects in bucket
    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    # Transition to Glacier after 30 days
    transition {
      days          = 30
      storage_class = "GLACIER"
    }

    # Delete after 5 years
    expiration {
      days = 1825 # 5 years
    }

    # Non-current version transition
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }

    # Non-current version expiration
    noncurrent_version_expiration {
      noncurrent_days = 1825 # 5 years (must be greater than transition days)
    }
  }
}

# S3 Bucket Policy for CloudWatch Logs via Kinesis Firehose
resource "aws_s3_bucket_policy" "cloudwatch_logs_archive" {
  bucket = aws_s3_bucket.cloudwatch_logs_archive.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "FirehoseAclCheck",
        "Effect" : "Allow",
        "Principal" : { "Service" : "firehose.amazonaws.com" },
        "Action" : "s3:GetBucketAcl",
        "Resource" : aws_s3_bucket.cloudwatch_logs_archive.arn
      },
      {
        "Sid" : "FirehosePutObject",
        "Effect" : "Allow",
        "Principal" : { "Service" : "firehose.amazonaws.com" },
        "Action" : "s3:PutObject",
        "Resource" : "${aws_s3_bucket.cloudwatch_logs_archive.arn}/cloudwatch-logs/*",
        "Condition" : {
          "StringEquals" : {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

#-------------------------------------------------------------------------------
# KINESIS FIREHOSE FOR CLOUDWATCH LOGS TO S3 EXPORT
#-------------------------------------------------------------------------------

# IAM Role for Kinesis Firehose
resource "aws_iam_role" "firehose_role" {
  name = "FirehoseDeliveryRole-${var.environment}"

  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "firehose.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "Firehose-Delivery-Role"
  })
}

# IAM Policy for Firehose to write to S3 and CloudWatch Logs
resource "aws_iam_role_policy" "firehose_policy" {
  name = "firehose-s3-policy"
  role = aws_iam_role.firehose_role.id

  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ],
        "Resource" : [
          aws_s3_bucket.cloudwatch_logs_archive.arn,
          "${aws_s3_bucket.cloudwatch_logs_archive.arn}/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws-kinesisfirehose-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ],
        "Resource" : [
          aws_kms_key.second_encryption_key.arn
        ]
      }
    ]
  })
}

# Kinesis Firehose Delivery Stream for CloudWatch Logs
resource "aws_kinesis_firehose_delivery_stream" "cloudwatch_logs_stream" {
  name        = "CloudWatchLogsDeliveryStream-${var.environment}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_role.arn
    bucket_arn          = aws_s3_bucket.cloudwatch_logs_archive.arn
    prefix              = "cloudwatch-logs/"
    error_output_prefix = "errors/"

    # Enable compression
    compression_format = "GZIP"

    # CloudWatch Logging for Firehose
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws-kinesisfirehose/cloudwatch-logs-export"
      log_stream_name = "S3Delivery"
    }
  }

  # Server-side encryption
  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.second_encryption_key.arn
  }

  tags = merge(local.common_tags, {
    Name = "CloudWatch-Logs-Firehose"
  })
}

# CloudWatch Log Group for Firehose itself
resource "aws_cloudwatch_log_group" "firehose_logs" {
  name              = "/aws-kinesisfirehose/cloudwatch-logs-export"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn

  tags = merge(local.common_tags, {
    Name = "Firehose-Logs"
  })
}

resource "aws_cloudwatch_log_stream" "firehose_logs_stream" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose_logs.name
}

#-------------------------------------------------------------------------------
# IAM ROLE FOR CLOUDWATCH LOGS SUBSCRIPTION FILTERS TO FIREHOSE
#-------------------------------------------------------------------------------

# IAM Role for CloudWatch Logs to put records to Firehose
resource "aws_iam_role" "cwl_to_firehose" {
  name = "CWLToFirehoseRole-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "logs.amazonaws.com" }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "CWL-To-Firehose-Role"
  })
}

# IAM Policy for CloudWatch Logs to put records to Firehose
resource "aws_iam_role_policy" "cwl_to_firehose_policy" {
  name = "CWLToFirehosePolicy"
  role = aws_iam_role.cwl_to_firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "firehose:PutRecord"
        Resource = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

#-------------------------------------------------------------------------------
# CLOUDWATCH LOG SUBSCRIPTION FILTERS (EXPORT VIA FIREHOSE TO S3)
#-------------------------------------------------------------------------------

# Step Functions Logs Export
resource "aws_cloudwatch_log_subscription_filter" "step_functions_logs_export" {
  name            = "step-functions-logs-export"
  log_group_name  = aws_cloudwatch_log_group.step_functions_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# Quarantine Step Functions Logs Export
resource "aws_cloudwatch_log_subscription_filter" "quarantine_step_functions_logs_export" {
  name            = "quarantine-step-functions-logs-export"
  log_group_name  = aws_cloudwatch_log_group.quarantine_step_functions_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# Clean Scans Logs Export
resource "aws_cloudwatch_log_subscription_filter" "clean_scans_logs_export" {
  name            = "clean-scans-logs-export"
  log_group_name  = aws_cloudwatch_log_group.clean_scans.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# Textract Completion SNS Logs Export
resource "aws_cloudwatch_log_subscription_filter" "textract_completion_sns_logs_export" {
  name            = "textract-completion-sns-logs-export"
  log_group_name  = aws_cloudwatch_log_group.textract_completion_sns_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# Start Textract Lambda Logs Export
resource "aws_cloudwatch_log_subscription_filter" "start_textract_lambda_logs_export" {
  name            = "start-textract-lambda-logs-export"
  log_group_name  = aws_cloudwatch_log_group.start_textract_lambda_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# Process Textract Results Logs Export
resource "aws_cloudwatch_log_subscription_filter" "process_textract_results_logs_export" {
  name            = "process-textract-results-logs-export"
  log_group_name  = aws_cloudwatch_log_group.process_textract_results_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# OCR Step Functions Logs Export
resource "aws_cloudwatch_log_subscription_filter" "ocr_step_functions_logs_export" {
  name            = "ocr-step-functions-logs-export"
  log_group_name  = aws_cloudwatch_log_group.ocr_step_functions_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

# S3 Malware Scan Logs Export (already has 365 retention)
resource "aws_cloudwatch_log_subscription_filter" "s3_malware_scan_logs_export" {
  name            = "s3-malware-scan-logs-export"
  log_group_name  = aws_cloudwatch_log_group.s3_malware_scan_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn

  depends_on = [aws_kinesis_firehose_delivery_stream.cloudwatch_logs_stream]
}

#-------------------------------------------------------------------------------
# DYNAMODB ORCHESTRATION AND RECORDS TABLE
#-------------------------------------------------------------------------------

# DynamoDB Table: OCR Orchestration and Student Records
# Single-table design storing orchestration state (temp) and student records (permanent)
# Documentation: docs/dynamodb-schema.md
resource "aws_dynamodb_table" "ocr_orchestration_and_records" {
  name         = "ocr-orchestration-and-records-dev"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PartitionKey"
  range_key    = "SortKey"

  attribute {
    name = "PartitionKey"
    type = "S"
  }

  attribute {
    name = "SortKey"
    type = "S"
  }

  ttl {
    attribute_name = "ExpiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.second_encryption_key.arn
  }

  # Optional: Prevent accidental deletion in production
  lifecycle {
    prevent_destroy = false # Set to true for production
  }

  tags = merge(local.common_tags, {
    Name               = "OCR-Orchestration-And-Records"
    Environment        = var.environment
    CostCenter         = "OCR-Processing"
    DataClassification = "Confidential"
    Purpose            = "Student-Assessment-Data"
    Documentation      = "docs/dynamodb-schema.md"
  })
}

# DynamoDB Table: Precomputed reporting aggregates for MCP analytics
# Stores only class-level, grade-level, and support-list aggregates.
resource "aws_dynamodb_table" "ocr_reporting_aggregates" {
  name         = "ocr-reporting-aggregates-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PartitionKey"
  range_key    = "SortKey"

  attribute {
    name = "PartitionKey"
    type = "S"
  }

  attribute {
    name = "SortKey"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.second_encryption_key.arn
  }

  tags = merge(local.common_tags, {
    Name               = "OCR-Reporting-Aggregates"
    Environment        = var.environment
    CostCenter         = "OCR-Processing"
    DataClassification = "Confidential-Aggregated"
    Purpose            = "Class-And-Grade-Level-MCP-Analytics"
  })
}

# Attach this policy to the internal identity that runs the local MCP server.
resource "aws_iam_policy" "ocr_mcp_reporting_read_only" {
  name        = "OCR-MCP-Reporting-ReadOnly-${var.environment}"
  description = "Read-only access for the aggregate-only OCR analytics MCP server"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyReportingAggregates"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.ocr_reporting_aggregates.arn,
          "${aws_dynamodb_table.ocr_reporting_aggregates.arn}/index/*"
        ]
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name    = "OCR-MCP-Reporting-ReadOnly"
    Purpose = "Aggregate-Only-MCP-Access"
  })
}

# SNS Topic for DynamoDB Alerts
resource "aws_sns_topic" "dynamodb_alerts" {
  name              = "dynamodb-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "DynamoDB-Alerts" })
}

# SNS Topic Subscription - Email
resource "aws_sns_topic_subscription" "dynamodb_email_alerts" {
  topic_arn = aws_sns_topic.dynamodb_alerts.arn
  protocol  = "email"
  endpoint  = "sadisteffl@gmail.com"
}

# SNS Topic for Textract Completion Notifications
resource "aws_sns_topic" "textract_completion_notification" {
  name              = "textract-completion-notification-${var.environment}"
  kms_master_key_id = aws_kms_key.second_encryption_key.arn
  tags = merge(local.common_tags, {
    Name = "Textract-Completion-Notification"
  })
}

# CloudWatch Log Group for SNS Topic with KMS encryption
resource "aws_cloudwatch_log_group" "textract_completion_sns_logs" {
  name              = "/aws/sns/textract-completion-notification"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "Textract-Completion-SNS-Logs" })
}

# SNS Topic Subscription - Email
resource "aws_sns_topic_subscription" "textract_email_notification" {
  topic_arn = aws_sns_topic.textract_completion_notification.arn
  protocol  = "email"
  endpoint  = "sadisteffl@gmail.com"
}

# CloudWatch Metric Filter: Track Textract Job Completions
resource "aws_cloudwatch_log_metric_filter" "textract_completion_count" {
  name           = "TextractJobCompletionCount"
  pattern        = "{ $.message = *JobStatus* }"
  log_group_name = aws_cloudwatch_log_group.textract_completion_sns_logs.name

  metric_transformation {
    name          = "TextractJobCompletions"
    namespace     = "OCR/Textract"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Metric Filter: Track Failed Textract Jobs
resource "aws_cloudwatch_log_metric_filter" "textract_failure_count" {
  name           = "TextractJobFailureCount"
  pattern        = "{ $.message = *FAILED* }"
  log_group_name = aws_cloudwatch_log_group.textract_completion_sns_logs.name

  metric_transformation {
    name          = "TextractJobFailures"
    namespace     = "OCR/Textract"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Alarm: Monitor Textract Completion Rate
resource "aws_cloudwatch_metric_alarm" "textract_completion_alarm" {
  alarm_name          = "ocr-textract-completion-rate-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.textract_completion_count.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.textract_completion_count.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert when Textract completion rate drops below expected levels"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.dynamodb_alerts.arn]

  tags = local.common_tags
}

# CloudWatch Alarm: Monitor Textract Failure Rate
resource "aws_cloudwatch_metric_alarm" "textract_failure_alarm" {
  alarm_name          = "ocr-textract-failure-rate-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.textract_failure_count.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.textract_failure_count.metric_transformation[0].namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when Textract jobs fail"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.dynamodb_alerts.arn]

  tags = local.common_tags
}

# CloudWatch Alarm: Throttled Requests (should never happen with on-demand)
resource "aws_cloudwatch_metric_alarm" "dynamodb_throttles" {
  alarm_name          = "ocr-dynamodb-throttles-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert when DynamoDB requests are throttled"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.ocr_orchestration_and_records.name
  }

  alarm_actions = [aws_sns_topic.dynamodb_alerts.arn]

  tags = local.common_tags
}

# CloudWatch Alarm: System Errors
resource "aws_cloudwatch_metric_alarm" "dynamodb_system_errors" {
  alarm_name          = "ocr-dynamodb-system-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SystemErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Alert when DynamoDB experiences system errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.ocr_orchestration_and_records.name
  }

  alarm_actions = [aws_sns_topic.dynamodb_alerts.arn]

  tags = local.common_tags
}

# CloudWatch Alarm: All Errors (4xx and 5xx)
resource "aws_cloudwatch_metric_alarm" "dynamodb_all_errors" {
  alarm_name          = "ocr-dynamodb-all-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert on any DynamoDB errors (non-200 status codes)"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TableName = aws_dynamodb_table.ocr_orchestration_and_records.name
  }

  alarm_actions = [aws_sns_topic.dynamodb_alerts.arn]

  tags = local.common_tags
}


#=============================================================================
# OCR LAMBDA EXECUTION ROLE
#=============================================================================

# IAM Role for OCR Lambda Execution
resource "aws_iam_role" "ocr_lambda_execution_role1" {
  name = "OcrLambdaExecutionRole1"

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

  tags = merge(local.common_tags, {
    Name = "OCR-Lambda-Execution-Role"
  })
}

# Attach AWSLambdaBasicExecutionRole managed policy
resource "aws_iam_role_policy_attachment" "ocr_lambda_basic_execution" {
  role       = aws_iam_role.ocr_lambda_execution_role1.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Inline policy for OCR-specific permissions
resource "aws_iam_role_policy" "ocr_lambda_execution_policy" {
  name = "OcrLambdaExecutionPolicy"
  role = aws_iam_role.ocr_lambda_execution_role1.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "TextractStartDocumentAnalysis"
        Effect   = "Allow"
        Action   = "textract:StartDocumentAnalysis"
        Resource = "*"
      },
      {
        Sid    = "TextractGetDocumentAnalysis"
        Effect = "Allow"
        Action = [
          "textract:GetDocumentAnalysis",
          "textract:GetDocumentTextDetection"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3AccessToProcessedBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          "${aws_s3_bucket.processed_storage.arn}/*"
        ]
      },
      {
        Sid    = "S3AccessToResultsBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.textract_results_archive.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBPutItem"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = [
          aws_dynamodb_table.ocr_orchestration_and_records.arn,
          "${aws_dynamodb_table.ocr_orchestration_and_records.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBQueryAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:Query",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          aws_dynamodb_table.ocr_orchestration_and_records.arn,
          "${aws_dynamodb_table.ocr_orchestration_and_records.arn}/*"
        ]
      },
      {
        Sid    = "SNSPublishTextractCompletion"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.textract_completion_notification.arn
      },
      {
        Sid    = "StepFunctionsTaskCallback"
        Effect = "Allow"
        Action = [
          "states:SendTaskSuccess",
          "states:SendTaskFailure"
        ]
        Resource = "*"
      },
      {
        Sid    = "SQSDLQPermissions"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sqs_queue.start_textract_dlq.arn,
          aws_sqs_queue.process_textract_dlq.arn
        ]
      },
      {
        Sid    = "ENIPermissions"
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSUsage"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

#=============================================================================
# TEXTRACT SNS NOTIFICATION ROLE
#=============================================================================

# IAM Role for Textract to publish SNS notifications
resource "aws_iam_role" "textract_sns_role" {
  name = "TextractSNSRole-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "textract.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "Textract-SNS-Role"
  })
}

# Policy for Textract to publish to SNS
resource "aws_iam_role_policy" "textract_sns_policy" {
  name = "TextractSNSPolicy"
  role = aws_iam_role.textract_sns_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowTextractToPublishSNS"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.textract_completion_notification.arn
      },
      {
        Sid    = "AllowKMSForSNS"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

#=============================================================================
# LAMBDA #1: START TEXTRACT JOB
#=============================================================================

# Lambda Function Package - Start Textract Job
data "archive_file" "lambda_start_textract_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_start_textract_payload.zip"
  source {
    content  = <<EOF
import boto3
import os
import json
import time
from datetime import datetime

# Initialize AWS clients
textract = boto3.client('textract')
dynamodb = boto3.resource('dynamodb')

# Environment variables
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
TEXTRACT_SNS_ROLE_ARN = os.environ['TEXTRACT_SNS_ROLE_ARN']

table = dynamodb.Table(DYNAMODB_TABLE)

def lambda_handler(event, context):
    """
    Lambda #1: Start Textract Job
    - Triggers asynchronous Textract document analysis
    - Stores job metadata in DynamoDB WITH taskToken (atomic operation)
    - Returns job ID for tracking

    Expected Event Format:
    {
        "bucket": "processed-storage-dev-123456789",
        "objectKey": "*",
        "taskToken": "..."  # Provided by Step Functions
    }

    Note: Task token is now passed directly from Step Functions and stored
    atomically with the job metadata, eliminating race conditions.
    """
    try:
        # Extract event parameters
        bucket = event.get('bucket')
        key = event.get('objectKey')
        task_token = event.get('taskToken')  # Get taskToken from Step Functions

        # Validate required parameters
        if not bucket or not key:
            raise ValueError("Missing required parameters: bucket and objectKey")

        print(f"[START] Processing S3 object: s3://{bucket}/{key}")
        if task_token:
            print(f"[TASK] Received taskToken from Step Functions")
        else:
            print(f"[WARN] No taskToken provided - callback will fail!")

        # Start Textract asynchronous document analysis
        # Using FORMS, TABLES, and QUERIES features for comprehensive data extraction
        response = textract.start_document_analysis(
            DocumentLocation={
                'S3Object': {
                    'Bucket': bucket,
                    'Name': key
                }
            },
            FeatureTypes=['TABLES', 'FORMS', 'QUERIES'],
            QueriesConfig={
                'Queries': [
                    {
                        'Text': 'What is the student Math RIT score?',
                        'Alias': 'MATH_RIT_SCORE'
                    }
                ]
            },
            NotificationChannel={
                'SNSTopicArn': SNS_TOPIC_ARN,
                'RoleArn': TEXTRACT_SNS_ROLE_ARN
            }
        )

        job_id = response['JobId']
        print(f"[TEXTRACT] Started Textract job: {job_id}")

        # Store job metadata in DynamoDB WITH taskToken (atomic operation)
        # This eliminates the race condition where taskToken arrives before job metadata
        timestamp = int(time.time())
        expires_at = timestamp + 259200  # 72 hours

        dynamodb_item = {
            'PartitionKey': f'TEXTRACT_JOB#{job_id}',
            'SortKey': 'METADATA',
            'ExpiresAt': expires_at,
            's3Bucket': bucket,
            's3Key': key,
            'jobStatus': 'IN_PROGRESS',
            'startedAt': timestamp,
            'createdAt': datetime.utcnow().isoformat()
        }

        # Add taskToken if provided (REQUIRED for workflow completion)
        if task_token:
            dynamodb_item['taskToken'] = task_token
            print(f"[DYNAMODB] Storing taskToken with job metadata (atomic)")
        else:
            print(f"[ERROR] No taskToken - workflow will not complete properly!")

        table.put_item(Item=dynamodb_item)
        print(f"[DYNAMODB] Stored job metadata for: {job_id}")
        print(f"[DYNAMODB] Expires at: {expires_at} (72 hours)")

        return {
            'jobId': job_id,
            's3Bucket': bucket,
            's3Key': key,
            'featureTypes': ['TABLES', 'FORMS', 'QUERIES'],
            'queries': ['MATH_RIT_SCORE']
        }

    except ValueError as e:
        # Validation errors
        print(f"[ERROR] Validation error: {str(e)}")
        raise e

    except Exception as e:
        # Unexpected errors
        print(f"[ERROR] Failed to start Textract job: {str(e)}")
        print(f"[ERROR] Event: {json.dumps(event)}")
        raise e
EOF
    filename = "lambda_start_textract.py"
  }
}

# Lambda Function: Start Textract Job
resource "aws_lambda_function" "start_textract_job" {
  filename                       = data.archive_file.lambda_start_textract_zip.output_path
  function_name                  = "StartTextractJob-${var.environment}"
  role                           = aws_iam_role.ocr_lambda_execution_role1.arn
  handler                        = "lambda_start_textract.lambda_handler"
  runtime                        = "python3.11"
  timeout                        = 30
  memory_size                    = 256
  source_code_hash               = data.archive_file.lambda_start_textract_zip.output_base64sha256
  reserved_concurrent_executions = 100
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda_code_signing.arn
  kms_key_arn                    = aws_kms_key.second_encryption_key.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.start_textract_dlq.arn
  }

  vpc_config {
    subnet_ids         = aws_subnet.lambda_private_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DYNAMODB_TABLE        = aws_dynamodb_table.ocr_orchestration_and_records.name
      SNS_TOPIC_ARN         = aws_sns_topic.textract_completion_notification.arn
      TEXTRACT_SNS_ROLE_ARN = aws_iam_role.textract_sns_role.arn
    }
  }


  tags = merge(local.common_tags, {
    Name = "Start-Textract-Job-Lambda"
  })

  depends_on = [aws_iam_role_policy_attachment.ocr_lambda_basic_execution]
}

# CloudWatch Log Group for Start Textract Lambda with KMS encryption
resource "aws_cloudwatch_log_group" "start_textract_lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.start_textract_job.function_name}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "Start-Textract-Lambda-Logs" })
}

#=============================================================================
# LAMBDA #2: PROCESS TEXTRACT RESULTS
#=============================================================================

# Lambda Function Package - Process Textract Results
data "archive_file" "lambda_process_textract_results_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_process_textract_results_payload.zip"
  source {
    content  = <<EOF
import json
import boto3
import os

# Clients
textract = boto3.client('textract')
dynamodb = boto3.resource('dynamodb')
s3 = boto3.client('s3')
sfn = boto3.client('stepfunctions')

def lambda_handler(event, context):
    """
    Lambda #2: Process Textract Results
    - Receives SNS notifications from TWO sources:
      1. Textract service (job completion)
      2. Step Functions (taskToken callback - now redundant since Lambda #1 stores it)

    IMPORTANT: taskToken is now stored atomically by Lambda #1, eliminating
    race conditions. The Step Functions callback message is handled for
    compatibility but is no longer the primary taskToken source.
    """
    # Parse SNS notification
    sns_msg = json.loads(event['Records'][0]['Sns']['Message'])

    # Check message type
    if sns_msg.get('type') == 'STEP_FUNCTION_CALLBACK':
        # Message from Step Functions - taskToken handling
        # Note: This is now REDUNDANT since Lambda #1 stores the taskToken
        # We handle this message gracefully but it's no longer critical
        job_id = sns_msg.get('jobId')
        task_token = sns_msg.get('taskToken')

        print(f"[CALLBACK] Received taskToken message for job: {job_id}")
        print(f"[CALLBACK] TaskToken was already stored by Lambda #1 (atomic operation)")

        # Store taskToken if not already present (defensive programming)
        table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])
        try:
            table.update_item(
                Key={'PartitionKey': f'TEXTRACT_JOB#{job_id}', 'SortKey': 'METADATA'},
                UpdateExpression="SET taskToken = :token",
                ExpressionAttributeValues={':token': task_token},
                ConditionExpression="attribute_not_exists(taskToken)"  # Only if not present
            )
            print(f"[CALLBACK] Stored taskToken (was missing)")
        except Exception as e:
            if 'ConditionalCheckFailedException' in str(e):
                print(f"[CALLBACK] TaskToken already present (expected)")
            else:
                print(f"[CALLBACK] Error: {e}")

        return {"status": "task_token_acknowledged"}

    # Message from Textract - process results
    job_id = sns_msg['JobId']

    # 1. GET TEXTRACT RESULTS
    results = textract.get_document_analysis(JobId=job_id)

    # 2. EXTRACT STUDENT MATH SCORE (RIT)
    import re

    math_score = "Not Found"

    # Pass 1: Look for Query Results (highest priority - explicit Textract queries)
    for block in results['Blocks']:
        if block.get('BlockType') == 'QUERY_RESULT':
            if block.get('Alias') == 'MATH_RIT_SCORE':
                math_score = block.get('Text', 'Not Found')
                break
            if 'Math' in block.get('Text', ''):
                math_score = block['Text']
                break

    # Pass 2: Smart extraction - look for score near current term indicators (FA24, SP24, etc.)
    # This runs BEFORE generic keyword matching to prioritize current term scores
    if math_score == "Not Found":
        # Collect all LINE blocks with their positions
        line_blocks = []
        for block in results['Blocks']:
            if block['BlockType'] == 'LINE':
                line_blocks.append({
                    'text': block.get('Text', ''),
                    'id': block.get('Id', ''),
                    'page': block.get('Page', 1)
                })

        # Term priorities (most recent terms first)
        # FA24 = Fall 2024 (most recent), SP24 = Spring 2024, WI24 = Winter 2024
        term_priority = [
            (r'\bFA24\b', 100), (r'\bSP24\b', 90), (r'\bWI24\b', 80),  # 2024 terms
            (r'Fall 2024-2025', 95), (r'Fall 2024', 90),
            (r'\bFA23\b', 70), (r'\bSP23\b', 60), (r'\bWI23\b', 50),  # 2023 terms
            (r'\bFA\d{2}\b', 40), (r'\bSP\d{2}\b', 30), (r'\bWI\d{2}\b', 20),  # Other terms
            (r'Fall \d{4}', 35), (r'Spring \d{4}', 25), (r'Winter \d{4}', 15)
        ]

        best_score = None
        best_priority = -1

        # Look for scores near term indicators, track by priority
        for i, block in enumerate(line_blocks):
            block_text = block['text']

            # Check if this block contains a term indicator
            for pattern, priority in term_priority:
                if re.search(pattern, block_text, re.IGNORECASE):
                    # Look for a 3-digit score in nearby blocks (within 5 blocks before or after)
                    for j in range(max(0, i-5), min(len(line_blocks), i+5)):
                        numbers = re.findall(r'\b(\d{3})\b', line_blocks[j]['text'])
                        for num in numbers:
                            if 180 <= int(num) <= 280:
                                # Found a valid RIT score near a term indicator
                                # Only update if this term has higher priority
                                if priority > best_priority:
                                    best_score = num
                                    best_priority = priority
                                    print(f"[EXTRACTION] Found score {best_score} near term (priority {priority}): {block_text[:50]}")
                                break
                    break

        if best_score:
            math_score = best_score

    # Pass 3: Look for LINE blocks with both "Math" and "RIT" in same block
    if math_score == "Not Found":
        for block in results['Blocks']:
            if block['BlockType'] == 'LINE' and 'Math' in block.get('Text', '') and 'RIT' in block.get('Text', ''):
                numbers = re.findall(r'\b\d{3}\b', block['Text'])
                if numbers:
                    # Filter for valid RIT score range (180-280)
                    for num in numbers:
                        if 180 <= int(num) <= 280:
                            math_score = num
                            break
                if math_score != "Not Found":
                    break

    # Pass 4: Look for "Student RIT" or "RIT Score" followed by a 3-digit number (lowest priority)
    if math_score == "Not Found":
        # Collect all LINE blocks with their positions
        line_blocks = []
        for block in results['Blocks']:
            if block['BlockType'] == 'LINE':
                line_blocks.append({
                    'text': block.get('Text', ''),
                    'id': block.get('Id', ''),
                    'page': block.get('Page', 1)
                })

        # Look for "Student RIT" or "RIT Score" indicators
        rit_keywords = ['Student RIT', 'RIT Score', 'RIT']
        for i, block in enumerate(line_blocks):
            if any(keyword in block['text'] for keyword in rit_keywords):
                # Check nearby blocks for a 3-digit RIT score
                for j in range(max(0, i-2), min(len(line_blocks), i+10)):
                    numbers = re.findall(r'\b(\d{3})\b', line_blocks[j]['text'])
                    for num in numbers:
                        # Validate RIT score range (typically 180-280)
                        if 180 <= int(num) <= 280:
                            # Prefer scores that appear immediately after "Student RIT"
                            if 'Student RIT' in block['text'] or 'RIT Score' in block['text']:
                                math_score = num
                                break
                            if math_score == "Not Found":
                                math_score = num
                if math_score != "Not Found":
                    break

    # Pass 5: Fallback - Look for any standalone 3-digit number in valid RIT range
    if math_score == "Not Found":
        for block in results['Blocks']:
            if block['BlockType'] == 'LINE':
                numbers = re.findall(r'\b(\d{3})\b', block.get('Text', ''))
                for num in numbers:
                    if 180 <= int(num) <= 280:
                        math_score = num
                        break
            if math_score != "Not Found":
                break

    # 3. SEND DATA TO DYNAMODB
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    # Retrieve taskToken stored by Lambda #1 (atomic operation)
    print(f"[DYNAMODB] Retrieving taskToken for job: {job_id}")
    record = table.get_item(Key={'PartitionKey': f'TEXTRACT_JOB#{job_id}', 'SortKey': 'METADATA'})
    task_token = record.get('Item', {}).get('taskToken')

    if not task_token:
        # CRITICAL: taskToken is missing - workflow cannot complete
        error_msg = f"[ERROR] taskToken not found for job {job_id}! Lambda #1 may have failed to store it."
        print(error_msg)
        print(f"[ERROR] Job record: {record.get('Item', {})}")
        raise Exception(f"TaskToken missing - cannot complete Step Functions workflow: {job_id}")

    print(f"[DYNAMODB] Retrieved taskToken successfully")

    table.update_item(
        Key={'PartitionKey': f'TEXTRACT_JOB#{job_id}', 'SortKey': 'METADATA'},
        UpdateExpression="SET mathScore = :s, jobStatus = :st",
        ExpressionAttributeValues={':s': math_score, ':st': 'SUCCEEDED'}
    )

    # 4. SEND RESULTS TO RESULTS BUCKET
    s3.put_object(
        Bucket=os.environ['RESULTS_BUCKET'],
        Key=f"ocr-results/{job_id}.json",
        Body=json.dumps(results, default=str)
    )

    # RESUME STEP FUNCTION
    if task_token:
        sfn.send_task_success(taskToken=task_token, output=json.dumps({"mathScore": math_score}))

    return {"status": "success", "score": math_score}
EOF
    filename = "lambda_process_textract_results.py"
  }
}

# Lambda Function: Process Textract Results
resource "aws_lambda_function" "process_textract_results" {
  filename                       = data.archive_file.lambda_process_textract_results_zip.output_path
  function_name                  = "ProcessTextractResults-${var.environment}"
  role                           = aws_iam_role.ocr_lambda_execution_role1.arn
  handler                        = "lambda_process_textract_results.lambda_handler"
  runtime                        = "python3.11"
  timeout                        = 60
  memory_size                    = 512
  source_code_hash               = data.archive_file.lambda_process_textract_results_zip.output_base64sha256
  reserved_concurrent_executions = 100
  code_signing_config_arn        = aws_lambda_code_signing_config.lambda_code_signing.arn
  kms_key_arn                    = aws_kms_key.second_encryption_key.arn

  dead_letter_config {
    target_arn = aws_sqs_queue.process_textract_dlq.arn
  }

  vpc_config {
    subnet_ids         = aws_subnet.lambda_private_subnet[*].id
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.ocr_orchestration_and_records.name
      RESULTS_BUCKET = aws_s3_bucket.textract_results_archive.id
    }
  }


  tags = merge(local.common_tags, {
    Name = "Process-Textract-Results-Lambda"
  })

  depends_on = [aws_iam_role_policy_attachment.ocr_lambda_basic_execution]
}

# CloudWatch Log Group for Process Textract Results Lambda with KMS encryption
resource "aws_cloudwatch_log_group" "process_textract_results_logs" {
  name              = "/aws/lambda/${aws_lambda_function.process_textract_results.function_name}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "Process-Textract-Results-Lambda-Logs" })
}

# Lambda Permission for SNS to invoke Process Textract Results Lambda
resource "aws_lambda_permission" "allow_sns_process_textract" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.process_textract_results.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.textract_completion_notification.arn
}

# SNS Subscription to trigger Lambda when Textract completes
resource "aws_sns_topic_subscription" "textract_completion_lambda_trigger" {
  topic_arn            = aws_sns_topic.textract_completion_notification.arn
  protocol             = "lambda"
  endpoint             = aws_lambda_function.process_textract_results.arn
  raw_message_delivery = false # False = SNS will wrap the message in JSON
}

#=============================================================================
# STEP FUNCTION: OCR WORKFLOW (FIRST VERSION - START TEXTRACT ONLY)
#=============================================================================

# CloudWatch Log Group for OCR Step Functions with KMS encryption
resource "aws_cloudwatch_log_group" "ocr_step_functions_logs" {
  name              = "/aws/vendedlogs/states/OCR-Workflow-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.second_encryption_key.arn
  tags              = merge(local.common_tags, { Name = "OCR-Step-Functions-Logs" })
}

# IAM Role for OCR Step Functions
resource "aws_iam_role" "ocr_step_functions_role" {
  name = "OCR-StepFunctions-Role-${var.environment}"

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

  tags = merge(local.common_tags, {
    Name = "OCR-StepFunctions-Role"
  })
}

# Attach managed policy for Step Functions
resource "aws_iam_role_policy_attachment" "ocr_step_functions_basic" {
  role       = aws_iam_role.ocr_step_functions_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"
}

# Inline policy for OCR Step Functions
resource "aws_iam_role_policy" "ocr_step_functions_policy" {
  name = "OCRStepFunctionsPolicy"
  role = aws_iam_role.ocr_step_functions_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeStartTextractLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.start_textract_job.arn
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSAccessForSNS"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:Encrypt"
        ]
        Resource = aws_kms_key.second_encryption_key.arn
      }
    ]
  })
}

# Step Function State Machine: OCR Workflow (Phase 2 - Complete)


# OCR Workflow State Machine (v2 - to replace stuck deletion)
resource "aws_sfn_state_machine" "ocr_workflow2" {
  name     = "ocr_workflow2"
  role_arn = aws_iam_role.ocr_step_functions_role.arn

  definition = <<EOF
{
  "Comment": "OCR Workflow - taskToken passed to Lambda #1 to eliminate race condition",
  "StartAt": "StartTextractJob",
  "States": {
    "StartTextractJob": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.start_textract_job.arn}",
      "Parameters": {
        "bucket.$": "$.bucket",
        "objectKey.$": "$.objectKey",
        "taskToken.$": "$$.Task.Token"
      },
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "NotifyFailure"
        }
      ],
      "Next": "WaitForTextractCompletion"
    },
    "WaitForTextractCompletion": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish.waitForTaskToken",
      "TimeoutSeconds": 300,
      "HeartbeatSeconds": 60,
      "Parameters": {
        "TopicArn": "${aws_sns_topic.textract_completion_notification.arn}",
        "Message": {
          "type": "STEP_FUNCTION_CALLBACK",
          "jobId.$": "$.jobId",
          "taskToken.$": "$$.Task.Token"
        }
      },
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "ResultPath": "$.error",
          "Next": "NotifyFailure"
        }
      ],
      "Next": "Success"
    },
    "NotifyFailure": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.dynamodb_alerts.arn}",
        "Message": {
          "Input": "OCR Workflow Failed"
        }
      },
      "Next": "Failure"
    },
    "Success": {
      "Type": "Succeed"
    },
    "Failure": {
      "Type": "Fail"
    }
  }
}
EOF

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.ocr_step_functions_logs.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  encryption_configuration {
    kms_key_id                        = aws_kms_key.second_encryption_key.arn
    kms_data_key_reuse_period_seconds = 100
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
  }

  tags = merge(local.common_tags, {
    Name = "OCR-Workflow-StateMachine-v2"
  })
}

#=============================================================================
# EVENTBRIDGE TARGET: CONNECT S3 EVENT TO OCR WORKFLOW
#=============================================================================

# EventBridge Target - OCR Step Functions
# This connects the existing S3 event to the new OCR workflow
resource "aws_cloudwatch_event_target" "ocr_workflow_trigger" {
  rule       = aws_cloudwatch_event_rule.trigger_ocr_processing.name
  target_id  = "StepFunctions-OCRWorkflow"
  arn        = aws_sfn_state_machine.ocr_workflow2.arn
  role_arn   = aws_iam_role.eventbridge_invoke_sfn.arn
  depends_on = [aws_sfn_state_machine.ocr_workflow2]

  input_transformer {
    input_paths = {
      bucket     = "$.detail.s3ObjectDetails.bucketName"
      objectKey  = "$.detail.s3ObjectDetails.objectKey"
      threatName = "$.detail.scanResultDetails.threats[0].name"
      scanTime   = "$.time"
      region     = "$.region"
    }

    input_template = "\"MALWARE THREAT DETECTED - Bucket: <bucket> - File: <objectKey> - Threat: <threatName> - Time: <scanTime> - Region: <region> - Immediate action required!\""
  }
}

# EventBridge Target - Direct Lambda Trigger
resource "aws_cloudwatch_event_target" "start_textract_lambda_trigger" {
  rule      = aws_cloudwatch_event_rule.trigger_ocr_processing.name
  target_id = "Lambda-StartTextractJob"
  arn       = aws_lambda_function.start_textract_job.arn

  input_transformer {
    input_paths = {
      bucket    = "$.detail.bucket.name"
      objectKey = "$.detail.object.key"
    }

    input_template = <<EOF
{
  "bucket": <bucket>,
  "objectKey": <objectKey>
}
EOF
  }
}

# Lambda Permission - Allow EventBridge to invoke Lambda
resource "aws_lambda_permission" "allow_eventbridge_textract" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.start_textract_job.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger_ocr_processing.arn
}

output "ocr_reporting_aggregates_table_name" {
  description = "DynamoDB table read by the aggregate-only OCR analytics MCP server"
  value       = aws_dynamodb_table.ocr_reporting_aggregates.name
}

output "ocr_mcp_reporting_read_only_policy_arn" {
  description = "IAM policy ARN for read-only MCP access to OCR reporting aggregates"
  value       = aws_iam_policy.ocr_mcp_reporting_read_only.arn
}
