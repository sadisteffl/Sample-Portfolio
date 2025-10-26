# main.tf
provider "aws" {
  region = "us-east-1"
}

# Insecure Security Group (allows all inbound traffic)
resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Security group with overly permissive rules"

  ingress {
    description = "Allow all inbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # 🔴 Checkov should flag this
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Publicly Accessible S3 Bucket
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket-example"
  acl    = "public-read"  # 🔴 Checkov should flag this
}

# Missing Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "unencrypted" {
  bucket = aws_s3_bucket.public_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # ✅ Add this to fix encryption
    }
  }
}

# Hardcoded Secret (Semgrep should catch this)
variable "api_key" {
  default = "12345-SECRET-KEY-EXAMPLE"  # 🔴 Semgrep will flag this
}
