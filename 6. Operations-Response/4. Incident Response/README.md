# Corporate Incident Response Plan

## 1. Introduction and Purpose

This document outlines the plan and procedures for companies as an example to manage and respond to information security incidents. The purpose of this plan is to ensure a swift, effective, and coordinated response to limit the impact of any security breach, minimize disruption to business operations, and reduce financial and reputational damage.

### Automated Incident Response Playbooks

This repository includes **Terraform-based automated incident response playbooks** that implement the procedures outlined in this document. Each playbook is deployed as infrastructure-as-code and follows **NIST CSF**, **SOC 2**, and **MITRE ATT&CK** frameworks:

| Playbook | Use Case | NIST Phase | Automation Level |
|----------|---------|------------|------------------|
| **[Compromised Server](Playbook/Compromised/)** | EC2 instance compromise | Identify → Contain → Eradicate → Recover | 🤖 Fully Automated |
| **[File Known Virus to Quarantine](Playbook/File%20Known%20Virus%20to%20Quarantine/)** | S3 malware detected | Identify → Contain → Eradicate | 🤖 Fully Automated |
| **[Compromised IAM User](Playbook/Compromised%20IAM%20User/)** | IAM credential compromise | Identify → Contain → Eradicate | 🤖 Fully Automated |

**Key Features of Automated Playbooks:**
- ✅ **Zero Configuration**: Auto-discovers AMIs, subnets, VPCs
- ✅ **Human-in-the-Loop**: Security team approvals before eradication
- ✅ **Forensic Evidence Vault**: Immutable S3 storage with WORM protection
- ✅ **Compliance Ready**: NIST CSF, SOC 2, MITRE ATT&CK mappings
- ✅ **Real-time Alerts**: SNS email notifications throughout response
- ✅ **Complete Audit Trail**: CloudWatch Logs + X-Ray tracing

---

## 2. Roles and Responsibilities

Clear roles are critical for an orderly response. The following roles are established for the Incident Response Team (IRT).

| Role | Primary Responsibilities | Assigned Personnel |
| :--- | :--- | :--- |
| **Incident Commander (IC)** | Overall leader of the incident response effort. Makes key decisions, allocates resources, and serves as the final point of escalation. | *e.g., Chief Information Security Officer (CISO)* |
| **Technical Lead** | Leads the technical investigation and containment efforts. Manages the Security Analysts and coordinates with IT/DevOps teams. | *e.g., Lead Security Engineer* |
| **Communications Lead** | Manages all internal and external communications. Ensures stakeholders, customers, and regulatory bodies are informed as required. | *e.g., Head of Corporate Communications* |
| **Security Analyst(s)** | Performs the hands-on forensic analysis, monitors systems, and executes containment procedures under the direction of the Technical Lead. | *e.g., Security Operations Center (SOC) Team* |
| **Legal Counsel** | Provides guidance on legal and regulatory obligations, including data breach notification laws and evidence preservation. | *e.g., General Counsel* |
| **Executive Sponsor** | A member of the executive leadership team who provides support and resources, and liaises with the board of directors. | *e.g., Chief Technology Officer (CTO)* |

---

## 3. Incident Severity Levels

Incidents will be classified to prioritize response efforts.

| Level | Severity | Description | Examples |
| :--- | :--- | :--- | :--- |
| **1** | **Critical** | Poses an imminent threat to the business. Significant data loss, service unavailability, or reputational damage is occurring or is highly likely. | - Ransomware outbreak on critical systems - Confirmed breach of sensitive customer data (PII, PHI) - Widespread production outage |
| **2** | **High** | A serious incident that could escalate to Critical if not addressed immediately. May involve a limited breach or significant system degradation. | - Malware infection on multiple user endpoints - Successful phishing attack against a privileged user - Denial-of-Service (DoS) attack impacting performance |
| **3** | **Medium** | An incident with potential for impact but is currently contained or limited in scope. | - A single endpoint infected with malware - Suspicious activity detected on a non-critical server - A lost or stolen employee laptop |
| **4** | **Low** | A minor security event that requires investigation but poses no immediate threat. | - A policy violation - Unsuccessful port scan detected by a firewall |

---

## 4. Communication Plan

Timely and accurate communication is essential.

### Internal Communication

* **Incident Response Team:** A dedicated, secure channel (e.g., encrypted chat, conference bridge) will be established immediately upon incident declaration.
* **Executive Leadership:** The Communications Lead will provide regular, concise updates to the Executive Sponsor and other key leaders.
* **All Employees:** General notifications will be sent as needed to inform staff of any impacts to their work or required actions (e.g., password resets).

### External Communication

* **Customers:** All communication will be pre-approved by Legal and the Communications Lead. The focus will be on transparency, providing actionable information, and rebuilding trust.
* **Regulatory Bodies:** Legal Counsel will manage all required notifications to regulatory agencies (e.g., GDPR, CCPA) within the mandated timeframes.
* **Law Enforcement:** The Incident Commander, in consultation with Legal, will determine if and when to engage law enforcement agencies like the FBI.

---

## 5. Plan Testing and Maintenance

This plan is a living document and must be kept current.

* **Tabletop Exercises:** The Incident Response Team will conduct a tabletop exercise at least **annually** to walk through a simulated incident scenario and identify gaps in the plan.
* **Plan Review:** This document will be reviewed and updated **semi-annually** or after any significant security incident.
* **Contact List Audit:** The contact information for all roles will be audited on a **quarterly** basis to ensure it is accurate.

---

## 6. Automated Incident Response Playbooks

This section describes the Terraform-based automated playbooks that implement this incident response plan.

### 6.1. Compromised Server Playbook

**Location:** `Playbook/Compromised/`

**Purpose:** Automated response when GuardDuty detects a compromised EC2 instance.

**Trigger:** GuardDuty Critical Findings (Severity 8.0+)

**Workflow:**
1. **Identification** - Forensic data collection, MITRE tactic mapping
2. **Containment** - Network isolation, forensic snapshot creation, evidence vaulting to S3
3. **Human Approval** - Email sent to security team for eradication approval
4. **Eradication** - Terminate compromised instance
5. **Recovery** - Deploy clean instance from golden AMI

**Deployment:**
```bash
cd "Playbook/Compromised"
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: Set ops_email, approver_email, forensic_access_arns, vpc_id
terraform init
terraform apply
```

**Features:**
- ✅ Auto-discovers latest Amazon Linux 2 AMI
- ✅ Auto-creates quarantine and recovery security groups
- ✅ Auto-discovers private subnets
- ✅ Immutable forensic S3 vault with WORM protection
- ✅ Human-in-the-loop approval before eradication
- ✅ Complete chain of custody logging

**Compliance:**
- NIST CSF (Identify, Protect, Detect, Respond, Recover)
- SOC 2 (CC6.1, CC6.6, CC7.2, CC7.3)
- MITRE ATT&CK (Impact, Defense Evasion, Persistence)

**Documentation:** [Compromised/README.md](Playbook/Compromised/README.md)

### 6.2. File Known Virus to Quarantine Playbook

**Location:** `Playbook/File Known Virus to Quarantine/`

**Purpose:** Automatically scan and quarantine malicious files uploaded to S3.

**Trigger:** GuardDuty Malware Protection (S3) detects threats

**Workflow:**
1. **Detection** - GuardDuty scans file in pre-processing S3 bucket
2. **Containment** - File moved to quarantine bucket (restricted access)
3. **Eradication** - File deleted after retention period
4. **Recovery** - Clean file can be reprocessed

**Deployment:**
```bash
cd "Playbook/File Known Virus to Quarantine"
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: Set ops_email, alert_email, security_admin_iam_arns
terraform init
terraform apply
```

**Features:**
- ✅ Automatic S3 malware scanning with GuardDuty
- ✅ EventBridge triggers on threat detection
- ✅ Step Functions + Lambda for quarantine workflow
- ✅ Quarantine bucket with restricted access (security admins only)
- ✅ Human-in-the-loop notifications
- ✅ CloudWatch logging and alarms

**Compliance:**
- NIST CSF (Detect, Respond, Recover)
- SOC 2 (Incident Response, Monitoring)
- MITRE ATT&CK (Initial Access, Execution)

**Documentation:** [File Known Virus to Quarantine/README.md](Playbook/File%20Known%20Virus%20to%20Quarantine/README.md)

### 6.3. Compromised IAM User Playbook

**Location:** `Playbook/Compromised IAM User/`

**Purpose:** Automated response when IAM credentials are compromised.

**Trigger:** GuardDuty IAM anomaly detection or manual trigger

**Workflow:**
1. **Identification** - Collect IAM usage logs, identify compromised credentials
2. **Containment** - Disable access keys, revoke sessions
3. **Eradication** - Reset credentials, remove unauthorized IAM entities
4. **Recovery** - Issue new credentials, update access policies

**Deployment:**
```bash
cd "Playbook/Compromised IAM User"
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: Set ops_email, compromised_user_name
terraform init
terraform apply
```

**Features:**
- ✅ Automatic IAM key deactivation
- ✅ Session revocation
- ✅ Password reset workflow
- ✅ Access policy cleanup
- ✅ Audit logging

**Compliance:**
- NIST CSF (Identify, Protect, Detect, Respond, Recover)
- SOC 2 (Access Control, Incident Response)
- MITRE ATT&CK (Credential Access, Defense Evasion)

**Documentation:** [Compromised IAM User/README.md](Playbook/Compromised%20IAM%20User/README.md)

---

## 7. Quick Start - Deploying All Playbooks

To deploy all incident response playbooks:

```bash
# 1. Deploy Compromised Server playbook
cd "Playbook/Compromised"
terraform init
terraform apply

# 2. Deploy File Virus Quarantine playbook
cd "../File Known Virus to Quarantine"
terraform init
terraform apply

# 3. Deploy Compromised IAM User playbook
cd "../Compromised IAM User"
terraform init
terraform apply
```

---

## 8. Playbook Comparison

| Feature | Compromised Server | File Virus | IAM User |
|---------|------------------|------------|----------|
| **Detection Source** | GuardDuty | GuardDuty Malware Protection | GuardDuty IAM Anomalies |
| **Target Resource** | EC2 Instance | S3 Object | IAM User/Keys |
| **Isolation Method** | **NACL (stateless) + SG**, stop instance | Move to quarantine bucket | Deactivate keys, revoke sessions |
| **Eradication** | Terminate instance | Delete after retention | Reset credentials |
| **Recovery** | Launch new instance from AMI | Reprocess clean file | Issue new credentials |
| **Forensics** | EC2 snapshots + S3 vaulting | S3 object metadata | CloudTrail logs |
| **HITL Required** | Yes (before termination) | Yes (before deletion) | Yes (before reset) |

**Critical Security Note**: The Compromised Server playbook uses **stateless NACL isolation** that immediately drops ALL traffic including established reverse shell connections. This addresses the critical security gap where Security Groups (stateful) won't block existing TCP connections.

---

## 9. Testing Your Playbooks

### Test Compromised Server Workflow

```bash
cd "Playbook/Compromised"

# Manual trigger for testing
aws stepfunctions start-execution \
  --state-machine-arn <STATE_MACHINE_ARN> \
  --input '{
    "instance_id": "i-test1234567890abcdef0",
    "trigger_source": "manual",
    "severity": "8.5",
    "finding_title": "Manual Security Test"
  }'
```

### Test File Virus Workflow

```bash
cd "File Known Virus to Quarantine"

# Upload a test file (EICAR test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > test.txt
aws s3 cp test.txt s3://your-preprocessing-bucket/test.txt

# GuardDuty will auto-scan and trigger quarantine
```

### Test IAM User Workflow

```bash
cd "Compromised IAM User"

# Simulate IAM compromise detection
aws events put-events --entries '[{
  "Source": "aws.iam",
  "DetailType": "IAM User Anomaly Detected",
  "Detail": "{\"user_name\": \"test-user\", \"anomaly_type\": \"suspicious_api_usage\"}"
}]'
```

---

## 10. Monitoring and Alerting

All playbooks include comprehensive monitoring:

- **CloudWatch Logs**: All Lambda and Step Functions executions logged
- **CloudWatch Alarms**: Alerts on failures and DLQ messages
- **X-Ray Tracing**: Distributed tracing for debugging
- **SNS Notifications**: Email alerts at each phase
- **Metric Filters**: Custom metrics for KPI dashboards

Create a CloudWatch Dashboard to monitor all playbooks:
```bash
aws cloudwatch put-dashboard --dashboard-name "IncidentResponse" \
  --dashboard-body file://dashboard.json
```

---

## 11. Runbooks and Procedures

### Compromised Server Runbook

1. **Detection**: GuardDuty finding received → Automated trigger
2. **Investigation**: Security team reviews forensic evidence in S3 vault
3. **Decision**: Approve or reject eradication (via email link)
4. **Eradication**: If approved, instance terminated
5. **Recovery**: New instance deployed
6. **Post-Incident**: Review logs, update runbook

### Malware File Runbook

1. **Detection**: File uploaded to pre-processing bucket
2. **Scan**: GuardDuty malware protection scan completes
3. **Trigger**: If threat found, auto-quarantine to restricted bucket
4. **Investigation**: Security team reviews file
5. **Decision**: Delete or retain for analysis
6. **Post-Incident**: Update scanning rules

### Compromised Credentials Runbook

1. **Detection**: Anomaly detected in IAM usage
2. **Investigation**: Security team reviews CloudTrail logs
3. **Containment**: Disable compromised credentials
4. **Eradication**: Remove unauthorized access
5. **Recovery**: Issue new credentials
6. **Post-Incident**: Review IAM policies

---

## 12. Continuous Improvement

### Incident Metrics to Track

- **MTTD** (Mean Time To Detect): Average time from incident start to detection
- **MTTR** (Mean Time To Respond): Average time from detection to containment
- **MTTI** (Mean Time To Identify): Average time to identify root cause
- **Recovery Time**: Average time to restore services

### Post-Incident Activities

1. **Root Cause Analysis**: Determine how the incident occurred
2. **Lessons Learned**: Document what went well and what needs improvement
3. **Playbook Updates**: Update Terraform code based on findings
4. **Team Training**: Conduct tabletop exercises using real scenarios
5. **Process Improvement**: Refine detection rules and response procedures

### Feedback Loop

After each incident:
1. Review execution logs from Step Functions
2. Analyze forensic evidence from S3 vault
3. Update detection rules in GuardDuty
4. Modify Terraform code if automation needs improvement
5. Update this documentation with lessons learned

---

For more detailed documentation on each playbook, see the individual README files in their respective directories.
