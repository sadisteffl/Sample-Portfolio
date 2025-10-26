variable "minimum_password_length" {
  description = "The minimum length to require for user passwords."
  type        = number
  default     = 14
}

variable "require_lowercase_characters" {
  description = "Whether to require lowercase characters for user passwords."
  type        = bool
  default     = true
}

variable "require_uppercase_characters" {
  description = "Whether to require uppercase characters for user passwords."
  type        = bool
  default     = true
}

variable "require_numbers" {
  description = "Whether to require numbers for user passwords."
  type        = bool
  default     = true
}

variable "require_symbols" {
  description = "Whether to require symbols for user passwords."
  type        = bool
  default     = true
}

variable "password_reuse_prevention" {
  description = "The number of previous passwords that users are prevented from reusing."
  type        = number
  default     = 24
}

variable "max_password_age" {
  description = "The number of days that a user password is valid."
  type        = number
  default     = 90
}

variable "hard_expiry" {
  description = "Whether users are prevented from setting a new password after their password has expired (i.e. require administrator reset)."
  type        = bool
  default     = false
}

variable "allow_users_to_change_password" {
  description = "Whether to allow users to change their own password."
  type        = bool
  default     = true
}