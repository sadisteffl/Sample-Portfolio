#=============================================================================
# VARIABLES FOR S3 MALWARE SCANNING & QUARANTINE MODULE
#=============================================================================

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address to receive malware threat alerts"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "Alert email must be a valid email address."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for Lambda VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zone_count" {
  description = "Number of availability zones for private subnets"
  type        = number
  default     = 2

  validation {
    condition     = var.availability_zone_count >= 1 && var.availability_zone_count <= 4
    error_message = "Availability zone count must be between 1 and 4."
  }
}

variable "security_admin_iam_arns" {
  description = "List of IAM ARNs for security admins who can access the quarantine bucket"
  type        = list(string)
  default     = []

  validation {
    condition = length([
      for arn in var.security_admin_iam_arns :
      can(regex("^arn:aws:iam::\\d{12}:.*", arn))
    ]) == length(var.security_admin_iam_arns)
    error_message = "All security admin ARNs must be valid IAM ARNs."
  }
}

variable "iam_user_name" {
  description = "IAM user name to query for access keys (for testing/documentation)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
