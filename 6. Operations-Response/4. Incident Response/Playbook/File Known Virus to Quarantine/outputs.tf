#=============================================================================
# OUTPUTS FOR S3 MALWARE SCANNING & QUARANTINE MODULE
#=============================================================================

output "pre_processing_bucket_name" {
  description = "Name of the S3 bucket for pre-processing storage (files are scanned here)"
  value       = aws_s3_bucket.pre_processing_storage.id
}

output "pre_processing_bucket_arn" {
  description = "ARN of the pre-processing S3 bucket"
  value       = aws_s3_bucket.pre_processing_storage.arn
}

output "quarantine_bucket_name" {
  description = "Name of the S3 bucket for quarantined malware files"
  value       = aws_s3_bucket.quarantine_storage.id
}

output "quarantine_bucket_arn" {
  description = "ARN of the quarantine S3 bucket"
  value       = aws_s3_bucket.quarantine_storage.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for malware threat alerts"
  value       = aws_sns_topic.malware_threat_alerts.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function that quarantines infected files"
  value       = aws_lambda_function.quarantine_processor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the quarantine Lambda function"
  value       = aws_lambda_function.quarantine_processor.arn
}

output "step_function_state_machine_arn" {
  description = "ARN of the Step Functions state machine for quarantine workflow"
  value       = aws_sfn_state_machine.quarantine_processor.arn
}

output "guardduty_malware_protection_plan_arn" {
  description = "ARN of the GuardDuty malware protection plan"
  value       = aws_guardduty_malware_protection_plan.s3.arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.encryption_key.arn
}

output "vpc_id" {
  description = "ID of the VPC used by Lambda functions"
  value       = aws_vpc.lambda_vpc.id
}

output "security_group_id" {
  description = "ID of the security group used by Lambda functions"
  value       = aws_security_group.lambda_sg.id
}

output "dead_letter_queue_url" {
  description = "URL of the SQS dead letter queue for failed Lambda invocations"
  value       = aws_sqs_queue.quarantine_processor_dlq.id
}

output "eventbridge_rule_threat_found" {
  description = "Name of the EventBridge rule that triggers on malware detection"
  value       = aws_cloudwatch_event_rule.trigger_quarantine_processing.name
}

output "setup_instructions" {
  description = "Instructions for completing the setup"
  value       = <<-EOT
    ✓ Infrastructure deployed successfully!

    Next Steps:
    1. Upload files to: ${aws_s3_bucket.pre_processing_storage.id}
    2. GuardDuty will automatically scan files
    3. Infected files will be moved to: ${aws_s3_bucket.quarantine_storage.id}
    4. Security team will receive alerts at: ${var.alert_email}

    Important Notes:
    - Confirm the SNS subscription by clicking the link sent to ${var.alert_email}
    - Only security admins with IAM ARNs in var.security_admin_iam_arns can access the quarantine bucket
    - Ensure GuardDuty is enabled in your AWS account
    - GuardDuty Malware Protection feature must be enabled in the GuardDuty console
  EOT
}
