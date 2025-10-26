# AWS Security Controls Map for ISO 27001, SOC 2 and AWS Best Practices Frameworks

## Executive Summary

This standard provides comprehensive security controls for AWS infrastructure, mapped to ISO 27001:2022 and SOC 2 compliance frameworks. It defines specific, actionable security requirements for all major AWS services, enabling teams to build secure, compliant cloud infrastructure while maintaining operational efficiency.

**Key Services Covered:**
- Identity & Access Management (IAM)
- Storage services (S3, EBS)
- Compute services (EC2, Lambda)
- Database services (RDS, DynamoDB)
- Network services (VPC, CloudFront)
- Security services (CloudTrail, KMS)

**Implementation Approach:**
- **Critical controls** (0-30 days) - Prevent severe security breaches
- **High priority controls** (30-90 days) - Address significant security risks
- **Medium priority controls** (90-180 days) - Enhance security posture

**Target Audience:** Cloud architects, DevOps engineers, security professionals, and compliance teams.

---

This list is limited just to AWS IAM and not IAM audit controls across the company.

## Introduction
This document provides a detailed mapping of AWS security best practices to the control requirements of the ISO/IEC 27001:2022 standard and the AICPA's SOC 2 Trust Services Criteria. The controls are organized by AWS service and include a severity rating to provide a clear, actionable guide for architects, engineers, and compliance professionals. This would be posted on an internal site with a list of every AWS resource possible so developers have a guide for what is expected of every resource. Of course, this is a sample but I would provide the extensive list once hired. 

Frameworks Referenced:
ISO/IEC 27001:2022: The international standard for information security management systems (ISMS). We will reference the Annex A controls.
SOC 2 (System and Organization Controls 2): A framework for managing customer data based on five "Trust Services Criteria" (TSC). We will focus primarily on the Security (Common Criteria), Confidentiality, and Availability TSCs.


## Amazon S3 (Simple Storage Service)

Controls for S3 focus on protecting data at rest and in transit, and preventing unauthorized access.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| S3-01 | Critical | Block Public Access | Enable "Block all public access" at the account and bucket level to prevent accidental public exposure of data. | A.8.2, A.8.9, A.8.24 | CC6.1, CC6.7 |
| S3-02 | High | Bucket Policies & ACLs | Implement restrictive bucket policies and Access Control Lists (ACLs) that enforce least-privilege access to objects. | A.5.15, A.8.3 | CC6.1, CC6.5 |
| S3-03 | High | Server-Side Encryption | Enforce server-side encryption for all objects stored in S3. Use AWS Key Management Service (SSE-KMS) for manageable, audited encryption keys. | A.8.24 | CC6.7, Confidentiality |
| S3-04 | High | Encryption in Transit | Enforce encryption of data in transit by requiring HTTPS (TLS) connections to S3 endpoints using a bucket policy condition (aws:SecureTransport). | A.8.24 | CC6.7, Confidentiality |
| S3-05 | High | Versioning & MFA Delete | Enable versioning on S3 buckets to protect against accidental deletion or overwrites. Enable MFA Delete for an additional layer of protection against object deletion. | A.8.13, A.8.14 | CC3.2, Availability |
| S3-06 | Medium | S3 Access Logs | Enable server access logging for all S3 buckets. Store logs in a separate, secure S3 bucket for audit and security analysis. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| S3-07 | Medium | S3 Object Lock | Use S3 Object Lock for WORM (Write-Once-Read-Many) storage requirements, ensuring objects cannot be deleted or overwritten for a fixed amount of time. | A.8.9, A.8.13 | CC6.7, Confidentiality |
| S3-08 | Medium | Amazon Macie | Use Amazon Macie to discover and protect sensitive data (like PII and financial information) stored in S3 using machine learning and pattern matching. | A.8.9, A.8.20 | CC6.7, Confidentiality |

## Amazon EC2 (Elastic Compute Cloud) & VPC (Virtual Private Cloud)
These controls cover network security, host-level security, and data protection for virtual servers and networks.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| EC2-01 | Critical | Security Groups | Use security groups as a stateful firewall to control inbound and outbound traffic to EC2 instances. Follow the principle of least privilege. | A.8.23 | CC6.1, CC6.6 |
| EC2-02 | Medium | Network ACLs (NACLs) | Use NACLs as a stateless firewall at the subnet level for an additional layer of defense. | A.8.23 | CC6.1, CC6.6 |
| EC2-03 | Medium | VPC Endpoints | Use VPC endpoints to privately connect your VPC to supported AWS services without requiring an internet gateway, NAT device, or VPN connection. | A.8.23 | CC6.1, CC6.6 |
| EC2-04 | High | EBS Encryption | Encrypt all EBS volumes attached to EC2 instances using AWS KMS to protect data at rest. Enable "Encrypt by Default" for the region. | A.8.24 | CC6.7, Confidentiality |
| EC2-05 | High | AMI Management | Use hardened, patched, and approved Amazon Machine Images (AMIs). Implement a process for regularly updating and patching your custom AMIs. | A.8.7, A.8.8 | CC7.1 |
| EC2-06 | Critical | Patch Management | Implement a robust patch management process for the operating systems and applications on your EC2 instances using AWS Systems Manager Patch Manager. | A.8.8 | CC7.1 |
| EC2-07 | High | SSH Key Management | Prohibit the use of password-based logins for EC2 instances. Use securely managed SSH key pairs. Do not use the same key pair for all instances or regions. | A.5.17, A.8.5 | CC6.1, CC6.3 |
| EC2-08 | High | VPC Flow Logs | Enable VPC Flow Logs to capture information about the IP traffic going to and from network interfaces in your VPC. Analyze these logs for anomalous traffic. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| EC2-09 | High | AWS Systems Manager | Utilize AWS Systems Manager Session Manager for secure, auditable remote access to EC2 instances, eliminating the need for open inbound SSH or RDP ports. | A.8.5, A.8.16 | CC6.1, CC6.6 |


## Amazon RDS (Relational Database Service)
Controls for RDS focus on securing the database engine, the data it contains, and the network connections to it.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| RDS-01 | High | Encryption at Rest | Enable encryption at rest for all RDS instances and snapshots using AWS KMS. | A.8.24 | CC6.7, Confidentiality |
| RDS-02 | High | Encryption in Transit | Enforce SSL/TLS for all connections to your RDS instances to protect data in transit. | A.8.24 | CC6.7, Confidentiality |
| RDS-03 | Critical | Public Accessibility | Configure RDS instances to not be publicly accessible. Access should be restricted to within the VPC. | A.8.2, A.8.23 | CC6.1, CC6.6 |
| RDS-04 | Critical | Security Group Access | Restrict network access to RDS instances using security groups. Only allow connections from specific application servers or bastion hosts. | A.8.23 | CC6.1, CC6.6 |
| RDS-05 | High | Automated Backups & Retention | Enable automated backups for RDS instances and configure an appropriate backup retention period to support point-in-time recovery. | A.8.13 | CC3.2, Availability |
| RDS-06 | High | Database Logging | Enable and configure database engine logging (e.g., audit, error, general, slow query logs) and forward them to CloudWatch Logs for monitoring and analysis. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| RDS-07 | Medium | IAM Database Authentication | Where supported, use IAM database authentication to manage database access using IAM users and roles instead of native database credentials. | A.5.15, A.8.2 | CC6.1, CC6.2 |

## AWS Identity and Access Management (IAM)
IAM is the foundation of AWS security, controlling who can do what within your AWS environment.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| IAM-01 | Critical | Root Account Security | Secure the root account with multi-factor authentication (MFA), store credentials in a secure location, and avoid using it for daily operations. | A.5.15, A.9.4 | CC6.1, CC6.3 |
| IAM-02 | Critical | MFA Enforcement | Enforce MFA for all IAM users, especially those with privileged access. Use hardware MFA tokens for highly privileged accounts. | A.5.17, A.9.4 | CC6.1, CC6.3 |
| IAM-03 | Critical | Least Privilege Access | Implement least privilege access by granting only the minimum permissions necessary for users and services to perform their functions. | A.5.15, A.9.2 | CC6.1, CC6.5 |
| IAM-04 | High | IAM Role Usage | Use IAM roles instead of long-term access keys whenever possible, especially for applications and AWS services. | A.5.15, A.9.2 | CC6.1, CC6.2 |
| IAM-05 | High | Password Policy | Enforce strong password policies including minimum length, complexity requirements, and regular rotation. | A.5.17 | CC6.1, CC6.3 |
| IAM-06 | High | Access Key Rotation | Rotate IAM user access keys regularly (recommended every 90 days) and deactivate old keys promptly. | A.5.17, A.9.4 | CC6.1, CC6.3 |
| IAM-07 | Medium | IAM Access Analyzer | Use IAM Access Analyzer to identify resources shared with external entities and ensure appropriate access patterns. | A.5.15, A.8.2 | CC6.1, CC6.6 |

## AWS CloudTrail
CloudTrail provides governance, compliance, and operational auditing for your AWS account.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| CT-01 | Critical | Enable CloudTrail | Enable CloudTrail in all regions to log all API calls made in your AWS account. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| CT-02 | Critical | Log File Validation | Enable log file validation to verify the integrity of CloudTrail log files. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| CT-03 | High | S3 Storage for Logs | Store CloudTrail logs in a separate, secure S3 bucket with appropriate access controls and encryption. | A.8.24, A.8.16 | CC6.7, CC7.2 |
| CT-04 | High | CloudWatch Integration | Send CloudTrail logs to CloudWatch Logs for real-time monitoring, alerting, and automated analysis. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| CT-05 | Medium | Multi-Region Trail | Create a multi-region trail to capture API activity across all AWS regions used by your organization. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| CT-06 | Medium | Data Events | Enable data events for high-risk S3 buckets and Lambda functions to capture object-level and function execution activity. | A.8.15, A.8.16 | CC7.1, CC7.2 |

## AWS Lambda
Serverless computing security requires attention to function configuration, permissions, and runtime security.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| LAMBDA-01 | High | Function Permissions | Apply least privilege permissions to Lambda execution roles. Avoid granting wildcards (*) in policies. | A.5.15, A.9.2 | CC6.1, CC6.5 |
| LAMBDA-02 | High | VPC Configuration | Deploy Lambda functions in VPCs when accessing AWS resources, using appropriate security groups and subnets. | A.8.23 | CC6.1, CC6.6 |
| LAMBDA-03 | Medium | Environment Variables Encryption | Encrypt sensitive environment variables using AWS KMS and avoid storing secrets in plain text. | A.8.24 | CC6.7, Confidentiality |
| LAMBDA-04 | High | Code Signing | Use AWS Lambda code signing to ensure only trusted code is deployed to your functions. | A.8.11, A.14.2 | CC6.8, CC7.1 |
| LAMBDA-05 | Medium | Dead Letter Queues | Configure dead letter queues (DLQs) to capture and analyze failed function invocations. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| LAMBDA-06 | Medium | Runtime Security | Use supported runtimes and keep them updated. Regularly scan function packages for vulnerabilities. | A.8.8 | CC7.1 |

## Amazon CloudFront
Content delivery network security focuses on protecting data in transit and preventing DDoS attacks.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| CF-01 | High | HTTPS Enforcement | Enforce HTTPS between viewers and CloudFront and between CloudFront and your origin server. | A.8.24 | CC6.7, Confidentiality |
| CF-02 | High | TLS Version | Use modern TLS versions (1.2+) and strong cipher suites for all connections. | A.8.24 | CC6.7, Confidentiality |
| CF-03 | Medium | WAF Integration | Integrate AWS WAF with CloudFront distributions to protect against common web vulnerabilities. | A.8.23, A.14.2 | CC6.6, CC7.1 |
| CF-04 | Medium | Origin Access | Use Origin Access Identity (OAI) or Origin Access Control (OAC) to restrict direct access to your origin resources. | A.8.2, A.8.23 | CC6.1, CC6.6 |
| CF-05 | Medium | Geo Restrictions | Implement geo restrictions if your service should not be accessible from certain geographic locations. | A.8.2 | CC6.1, CC6.6 |

## AWS Key Management Service (KMS)
KMS provides centralized control over your encryption keys and their usage.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| KMS-01 | Critical | Key Rotation | Enable automatic key rotation for all customer-managed CMKs (Customer Master Keys). | A.8.24, A.10.1 | CC6.7, CC6.8 |
| KMS-02 | High | Key Policies | Implement restrictive key policies that follow the principle of least privilege for key usage. | A.5.15, A.10.1 | CC6.1, CC6.7 |
| KMS-03 | High | Key Administrators | Limit key administrative access to only authorized personnel with clear business justification. | A.5.15, A.9.2 | CC6.1, CC6.3 |
| KMS-04 | Medium | CloudTrail Integration | Enable CloudTrail logging for all KMS API operations to audit key usage and management. | A.8.15, A.8.16 | CC7.1, CC7.2 |
| KMS-05 | Medium | Import Key Deletion | Set appropriate deletion waiting periods for imported key material to prevent accidental key loss. | A.8.13, A.8.14 | CC3.2, Availability |

## Amazon API Gateway
API Gateway security controls focus on authentication, authorization, and rate limiting.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| APIGW-01 | High | Authentication | Implement strong authentication mechanisms using Cognito User Pools, Lambda authorizers, or IAM authentication. | A.5.17, A.9.4 | CC6.1, CC6.3 |
| APIGW-02 | High | Authorization | Enforce fine-grained authorization controls to ensure users can only access permitted resources and actions. | A.5.15, A.9.2 | CC6.1, CC6.5 |
| APIGW-03 | High | Rate Limiting & Throttling | Configure rate limiting and throttling to prevent abuse and ensure service availability. | A.8.23, A.12.4 | CC6.6, CC7.1 |
| APIGW-04 | Medium | WAF Integration | Integrate with AWS WAF to protect against common web attacks and vulnerabilities. | A.8.23, A.14.2 | CC6.6, CC7.1 |
| APIGW-05 | Medium | Logging & Monitoring | Enable detailed logging and monitoring of API calls, including request/response details for troubleshooting and audit. | A.8.15, A.8.16 | CC7.1, CC7.2 |

## Amazon DynamoDB
NoSQL database security controls for data protection and access management.

| Control ID | Severity | AWS Resource/Feature | Control Description | ISO 27001 Annex A | SOC 2 Common Criteria (CC) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| DDB-01 | High | Encryption at Rest | Enable server-side encryption for all DynamoDB tables using AWS managed CMKs or customer-managed CMKs. | A.8.24 | CC6.7, Confidentiality |
| DDB-02 | High | Encryption in Transit | Enforce encryption of data in transit by using HTTPS endpoints for all DynamoDB API calls. | A.8.24 | CC6.7, Confidentiality |
| DDB-03 | Critical | IAM Policies | Implement restrictive IAM policies that grant least privilege access to DynamoDB tables and indexes. | A.5.15, A.9.2 | CC6.1, CC6.5 |
| DDB-04 | High | VPC Endpoints | Use VPC endpoints to keep DynamoDB traffic within your VPC and avoid internet exposure. | A.8.23 | CC6.1, CC6.6 |
| DDB-05 | Medium | Point-in-Time Recovery | Enable Point-in-Time Recovery (PITR) for critical tables to protect against accidental data loss or corruption. | A.8.13 | CC3.2, Availability |
| DDB-06 | Medium | DynamoDB Accelerator (DAX) Security | If using DAX, ensure encryption is enabled and appropriate VPC security controls are in place. | A.8.24, A.8.23 | CC6.7, CC6.6 |

## Implementation Summary & Prioritization

### Critical Priority Controls (Immediate Implementation Required)
These controls prevent severe security breaches and must be implemented immediately.

| Service | Control IDs | Risk Mitigated | Implementation Timeline |
| :--- | :--- | :--- | :--- |
| IAM | IAM-01, IAM-02, IAM-03 | Account compromise, unauthorized access | 0-30 days |
| S3 | S3-01 | Data exposure, public access breaches | 0-30 days |
| EC2/RDS | EC2-06, RDS-03, RDS-04 | Unpatched systems, public database exposure | 0-30 days |
| CloudTrail | CT-01, CT-02 | Lack of audit trail, undetected breaches | 0-30 days |
| DynamoDB | DDB-03 | Unauthorized data access | 0-30 days |

### High Priority Controls (Complete within 90 days)
These controls address significant security risks and compliance requirements.

| Service | Control IDs | Risk Mitigated | Implementation Timeline |
| :--- | :--- | :--- | :--- |
| S3 | S3-02, S3-03, S3-04, S3-05 | Data theft, interception, accidental deletion | 30-60 days |
| EC2/RDS | EC2-04, EC2-05, EC2-07, EC2-08, EC2-09, RDS-01, RDS-02, RDS-05, RDS-06 | Data exposure, unauthorized access, lack of monitoring | 30-90 days |
| IAM | IAM-04, IAM-05, IAM-06 | Long-term credential abuse, weak authentication | 30-60 days |
| CloudTrail | CT-03, CT-04 | Log tampering, lack of real-time monitoring | 30-60 days |
| Lambda | LAMBDA-01, LAMBDA-02, LAMBDA-04 | Privilege escalation, unauthorized code execution | 60-90 days |
| CloudFront | CF-01, CF-02 | Man-in-the-middle attacks, weak encryption | 60-90 days |
| KMS | KMS-01, KMS-02, KMS-03 | Key compromise, unauthorized encryption/decryption | 60-90 days |
| API Gateway | APIGW-01, APIGW-02, APIGW-03 | API abuse, unauthorized access, service disruption | 60-90 days |
| DynamoDB | DDB-01, DDB-02, DDB-04 | Data exposure, traffic interception | 60-90 days |

### Medium Priority Controls (Complete within 180 days)
These controls enhance security posture and support mature security operations.

| Service | Control IDs | Risk Mitigated | Implementation Timeline |
| :--- | :--- | :--- | :--- |
| All Services | S3-06, S3-07, S3-08, EC2-02, EC2-03, RDS-07, CT-05, CT-06, LAMBDA-03, LAMBDA-05, LAMBDA-06, CF-03, CF-04, CF-05, KMS-04, KMS-05, APIGW-04, APIGW-05, DDB-05, DDB-06 | Limited visibility, insufficient monitoring, compliance gaps | 90-180 days |

## Implementation Guidance

### Automation Tools
- **AWS Config**: Use to continuously monitor and evaluate configuration compliance
- **AWS Security Hub**: Aggregate security findings and compliance status across services
- **AWS Control Tower**: Implement guardrails for multi-account environments
- **AWS CloudFormation**: Infrastructure as Code to ensure consistent, secure deployments

### Monitoring & Alerting
- Configure Amazon CloudWatch Alarms for critical security events
- Set up AWS GuardDuty for threat detection
- Implement AWS Security Hub for comprehensive security monitoring
- Create SNS notifications for security teams

### Compliance Validation
- Regular security assessments using AWS Audit Manager
- Automated compliance checks using AWS Config rules
- Third-party penetration testing and vulnerability assessments
- Internal security reviews and architecture assessments

### Documentation Requirements
- Maintain documentation of all security configurations
- Create runbooks for incident response procedures
- Document exception processes and approvals
- Regular review and update of security controls

## Related Documents
- [Secure Coding Standard for Developers](../Application/Secure%20Coding%20Standard.md)
- [Secure CI/CD Pipeline](../../2.%20CICD%20Checklist/Secure%20CI-CD%20Pipeline.md)
- [Kubernetes Security Standards](../../6.%20Kubernetes/K8s-Standards.md)
- [Application Security Compliance Checklist](../../3.%20Application%20Coding%20Checklist/Application%20Security%20Compliance%20Checklist.md)
