output "password_policy_id" {
  description = "The ID of the IAM account password policy."
  value       = aws_iam_account_password_policy.default.id
}
