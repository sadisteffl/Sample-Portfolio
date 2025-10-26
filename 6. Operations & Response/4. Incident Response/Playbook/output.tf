output "locked_down_user" {
  description = "The IAM user that has been locked down."
  value       = var.iam_user_name
}

output "deactivated_access_key_ids" {
  description = "A list of access key IDs that were set to Inactive."
  value       = [for k in data.aws_iam_access_keys.user_keys.access_keys : k.id if k.status == "Active"]
}

output "deny_all_policy_arn" {
  description = "The ARN of the DenyAll policy that was attached to the user."
  value       = aws_iam_policy.deny_all.arn
}