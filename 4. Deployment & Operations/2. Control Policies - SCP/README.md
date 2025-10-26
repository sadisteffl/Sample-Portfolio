# Proactive AWS Governance with Terraform SCPs
Hello! This repository contains a sample Terraform configuration designed to demonstrate a practical and scalable approach to AWS governance using Service Control Policies (SCPs). The goal is to showcase how to implement critical preventative guardrails directly within AWS Organizations.

## The Challenge: SCPs as a Scarce Resource
Service Control Policies are one of the most powerful tools for enforcing security and compliance across an AWS Organization. However, they have historically been a scarce resource. While AWS has expanded policy capabilities in some areas, the limit of 5 SCPs attached to any single Organizational Unit (OU) or account has been a long-standing challenge.

This limitation forces a strategic approach. Instead of creating many small, single-purpose policies, the best practice is to consolidate multiple logical controls into a single, comprehensive SCP. This repository is a practical example of that philosophy.

## What This Terraform Configuration Does
This code creates a single, consolidated SCP that enforces two distinct, high-impact security controls:

### Enforces IAM Permissions Boundaries 
It denies the iam:CreateRole action unless a specific, pre-approved permissions boundary is attached. This is a critical preventative control to stop privilege escalation and the creation of overly-permissive IAM roles by developers.

### Enforces RDS SSL/TLS Connections 
It denies the rds:CreateDBInstance/rds:ModifyDBInstance and rds:CreateDBCluster/rds:ModifyDBCluster actions if the request does not use an approved DB Parameter Group. This ensures that all data in transit to and from your RDS databases is encrypted by default.

### How to Use This Repository
Prerequisites
Before applying this Terraform configuration, you must have the following resources already created in your AWS environment:

An IAM Permissions Boundary Policy: The policy that defines the maximum permissions your developers' roles can have. You will need its ARN.

SSL-Enforcing RDS Parameter Groups: You must create custom DB Parameter Groups and DB Cluster Parameter Groups for each database engine you use (e.g., PostgreSQL, MySQL) and configure them to enforce SSL.

PostgreSQL/SQL Server: Set rds.force_ssl to 1 or true.

MySQL/MariaDB: Set require_secure_transport to ON.

### Configuration & Deployment
Update the SCP Content: Modify the content section of the aws_organizations_policy resource to include the ARN of your permissions boundary and the names of your SSL-enforcing parameter groups.

Set the Target ID (Known Error Source):
Please note: The deployment will fail with an InvalidInputException by design until you complete this step. In the aws_organizations_policy_attachment resource (around line 58), you must replace the placeholder target_id (ou-a1b2-abcdef12) with the actual ID of the OU or account where you want to attach this policy.
