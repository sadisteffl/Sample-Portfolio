provider "aws" {
  region = "us-east-1"
}

provider "null" {}


data "aws_iam_access_keys" "user_keys" {
  user = var.iam_user_name
}

# Data source to get managed policy ARNs as a comma-separated string.
data "external" "managed_policy_arns" {
  program = ["bash", "-c", "policies=$(aws iam list-attached-user-policies --user-name '${var.iam_user_name}' --query 'AttachedPolicies[].PolicyArn' --output text | tr '\\t' ','); printf '{\"policies_csv\": \"%s\"}' \"$policies\""]
}

# Data source to get inline policy names as a comma-separated string.
data "external" "inline_policy_names" {
  program = ["bash", "-c", "policies=$(aws iam list-user-policies --user-name '${var.iam_user_name}' --query 'PolicyNames' --output text | tr '\\t' ','); printf '{\"policies_csv\": \"%s\"}' \"$policies\""]
}

resource "null_resource" "deactivate_access_keys" {
  # This triggers the provisioner for each active access key.
  for_each = { for k in data.aws_iam_access_keys.user_keys.access_keys : k.id => k if k.status == "Active" }

  provisioner "local-exec" {
    command = "aws iam update-access-key --user-name '${var.iam_user_name}' --access-key-id '${each.key}' --status Inactive"
  }
}

resource "null_resource" "detach_managed_policies" {
  # This triggers the provisioner for each attached managed policy.
  for_each = toset(compact(split(",", try(data.external.managed_policy_arns.result.policies_csv, ""))))

  provisioner "local-exec" {
    command = "aws iam detach-user-policy --user-name '${var.iam_user_name}' --policy-arn '${each.key}'"
  }
}

resource "null_resource" "delete_inline_policies" {
  # This triggers the provisioner for each attached inline policy.
  for_each = toset(compact(split(",", try(data.external.inline_policy_names.result.policies_csv, ""))))

  provisioner "local-exec" {
    command = "aws iam delete-user-policy --user-name '${var.iam_user_name}' --policy-name '${each.key}'"
  }
}

resource "aws_iam_policy" "deny_all" {
  name        = "incident-${var.incident_id}-DenyAll"
  description = "Explicitly denies all actions for incident response."
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Deny",
        Action   = "*",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "apply_deny_all" {
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.deny_all.arn
  # Ensure policies are detached before this runs
  depends_on = [
    null_resource.detach_managed_policies,
    null_resource.delete_inline_policies
  ]
}

resource "null_resource" "disable_login" {
  # This provisioner only runs when the playbook is applied.
  # The "|| true" ensures the command succeeds even if the user has no profile.
  provisioner "local-exec" {
    command = "aws iam delete-login-profile --user-name '${var.iam_user_name}' || true"
  }

  # Add a dependency to ensure this runs after other actions.
  depends_on = [aws_iam_user_policy_attachment.apply_deny_all]
}