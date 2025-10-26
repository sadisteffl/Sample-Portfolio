# main.tf - Defines the IAM password policy resource

resource "aws_iam_account_password_policy" "default" {
  minimum_password_length = var.minimum_password_length
  require_lowercase_characters = var.require_lowercase_characters
  require_uppercase_characters = var.require_uppercase_characters
  require_numbers = var.require_numbers
  require_symbols = var.require_symbols
  password_reuse_prevention = var.password_reuse_prevention
  max_password_age = var.max_password_age
  hard_expiry = var.hard_expiry
  allow_users_to_change_password = var.allow_users_to_change_password
}