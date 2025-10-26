trivy fs --scanners vuln,secret,config .

2025-10-23T18:20:27-05:00       WARN    '--scanners config' is deprecated. Use '--scanners misconfig' instead. See https://github.com/aquasecurity/trivy/discussions/5586 for the detail.
2025-10-23T18:20:27-05:00       INFO    [vuln] Vulnerability scanning is enabled
2025-10-23T18:20:27-05:00       INFO    [misconfig] Misconfiguration scanning is enabled
2025-10-23T18:20:27-05:00       INFO    [misconfig] Need to update the checks bundle
2025-10-23T18:20:27-05:00       INFO    [misconfig] Downloading the checks bundle...
165.46 KiB / 165.46 KiB [------------------------------------------------------------------------] 100.00% ? p/s 200ms
2025-10-23T18:20:29-05:00       INFO    [secret] Secret scanning is enabled
2025-10-23T18:20:29-05:00       INFO    [secret] If your scanning is slow, please try '--scanners vuln,misconfig' to disable secret scanning
2025-10-23T18:20:29-05:00       INFO    [secret] Please see https://trivy.dev/v0.67/docs/scanner/secret#recommendation for faster secret detection
2025-10-23T18:20:29-05:00       INFO    [terraform scanner] Scanning root module        file_path="."
2025-10-23T18:20:29-05:00       INFO    Number of language-specific files       num=0
2025-10-23T18:20:29-05:00       INFO    Detected config files   num=2

Report Summary

┌───────────────┬───────────┬─────────────────┬─────────┬───────────────────┐
│    Target     │   Type    │ Vulnerabilities │ Secrets │ Misconfigurations │
├───────────────┼───────────┼─────────────────┼─────────┼───────────────────┤
│ .             │ terraform │        -        │    -    │         0         │
├───────────────┼───────────┼─────────────────┼─────────┼───────────────────┤
│ infra-test.tf │ terraform │        -        │    -    │        12         │
└───────────────┴───────────┴─────────────────┴─────────┴───────────────────┘
Legend:
- '-': Not scanned
- '0': Clean (no security findings detected)


infra-test.tf (terraform)

Tests: 12 (SUCCESSES: 0, FAILURES: 12)
Failures: 12 (UNKNOWN: 0, LOW: 3, MEDIUM: 1, HIGH: 7, CRITICAL: 1)

AVD-AWS-0086 (HIGH): No public access block so not blocking public acls
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.


See https://avd.aquasec.com/misconfig/avd-aws-0086
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0087 (HIGH): No public access block so not blocking public policies
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.


See https://avd.aquasec.com/misconfig/avd-aws-0087
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0089 (LOW): Bucket has logging disabled
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Ensures S3 bucket logging is enabled for S3 buckets

See https://avd.aquasec.com/misconfig/s3-bucket-logging
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0090 (MEDIUM): Bucket does not have versioning enabled
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket.

You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets.

With versioning you can recover more easily from both unintended user actions and application failures.

When you enable versioning, also keep in mind the potential costs of storing noncurrent versions of objects. To help manage those costs, consider setting up an S3 Lifecycle configuration.


See https://avd.aquasec.com/misconfig/avd-aws-0090
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0091 (HIGH): No public access block so not blocking public acls
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.


See https://avd.aquasec.com/misconfig/avd-aws-0091
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0092 (HIGH): Bucket has a public ACL: "public-read"
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Buckets should not have ACLs that allow public access


See https://avd.aquasec.com/misconfig/avd-aws-0092
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:30
   via infra-test.tf:28-31 (aws_s3_bucket.public_bucket)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28   resource "aws_s3_bucket" "public_bucket" {
  29     bucket = "my-public-bucket-example"
  30 [   acl    = "public-read"  # 🔴 Checkov should flag this
  31   }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0093 (HIGH): No public access block so not restricting public buckets
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
S3 buckets should restrict public policies for the bucket. By enabling, the restrict_public_buckets, only the bucket owner and AWS Services can access if it has a public policy.


See https://avd.aquasec.com/misconfig/avd-aws-0093
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0094 (LOW): Bucket does not have a corresponding public access block.
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.


See https://avd.aquasec.com/misconfig/avd-aws-0094
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:28-31
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  28 ┌ resource "aws_s3_bucket" "public_bucket" {
  29 │   bucket = "my-public-bucket-example"
  30 │   acl    = "public-read"  # 🔴 Checkov should flag this
  31 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0104 (CRITICAL): Security group rule allows unrestricted egress to any IP address.
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.


See https://avd.aquasec.com/misconfig/aws-vpc-no-public-egress-sgr
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:23
   via infra-test.tf:19-24 (egress)
    via infra-test.tf:7-25 (aws_security_group.insecure_sg)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   7   resource "aws_security_group" "insecure_sg" {
   .   
  23 [     cidr_blocks = ["0.0.0.0/0"]
  ..   
  25   }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0107 (HIGH): Security group rule allows unrestricted ingress from any IP address.
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Security groups provide stateful filtering of ingress and egress network traffic to AWS
resources. It is recommended that no security group allows unrestricted ingress access to
remote server administration ports, such as SSH to port 22 and RDP to port 3389.


See https://avd.aquasec.com/misconfig/avd-aws-0107
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:16
   via infra-test.tf:11-17 (ingress)
    via infra-test.tf:7-25 (aws_security_group.insecure_sg)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   7   resource "aws_security_group" "insecure_sg" {
   .   
  16 [     cidr_blocks = ["0.0.0.0/0"]  # 🔴 Checkov should flag this
  ..   
  25   }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0124 (LOW): Security group rule does not have a description.
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.


See https://avd.aquasec.com/misconfig/aws-vpc-add-description-to-security-group-rule
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:19-24
   via infra-test.tf:7-25 (aws_security_group.insecure_sg)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   7   resource "aws_security_group" "insecure_sg" {
   .   
  19 ┌   egress {
  20 │     from_port   = 0
  21 │     to_port     = 0
  22 │     protocol    = "-1"
  23 │     cidr_blocks = ["0.0.0.0/0"]
  24 └   }
  25   }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


AVD-AWS-0132 (HIGH): Bucket does not encrypt data with a customer managed key.
══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.


See https://avd.aquasec.com/misconfig/avd-aws-0132
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 infra-test.tf:34-42
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  34 ┌ resource "aws_s3_bucket_server_side_encryption_configuration" "unencrypted" {
  35 │   bucket = aws_s3_bucket.public_bucket.id
  36 │ 
  37 │   rule {
  38 │     apply_server_side_encryption_by_default {
  39 │       sse_algorithm = "AES256" # ✅ Add this to fix encryption
  40 │     }
  41 │   }
  42 └ }
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
