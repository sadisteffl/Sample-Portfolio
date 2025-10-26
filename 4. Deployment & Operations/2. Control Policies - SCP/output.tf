output "scp_policy_id" {
  description = "The ID of the created SCP."
  value       = aws_organizations_policy.SCP1.id
}

output "permissions_boundary_arn_enforced" {
  description = "The full ARN of the permissions boundary being enforced."
  value       = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/YourDeveloperBoundaryPolicy"
}
