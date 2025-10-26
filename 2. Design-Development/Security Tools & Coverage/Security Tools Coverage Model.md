# Security Tools Coverage Model & Implementation Guide

> A comprehensive guide to the core security tooling stack, coverage areas, and implementation strategies for shift-left security

## 🎯 Executive Summary

This document outlines our security tooling strategy based on a **minimal yet comprehensive 3-tool stack** that provides optimal coverage across all critical security domains while minimizing tool overlap and maintenance overhead.

### Core Philosophy
- **Minimal Toolset**: Maximize coverage with minimal tools
- **Open Source优先**: All tools are actively maintained, open-source projects
- **Shift-Left Focus**: Detect issues early in the development lifecycle
- **Developer Integration**: Tools integrate seamlessly with existing workflows

---

## 🛠️ Core Security Tool Stack

### 1. Semgrep (SAST & Supply Chain)

**Primary Domain**: Static Application Security Testing (SAST)

| Feature | Details |
|---------|---------|
| **Purpose** | Code-level vulnerability detection across multiple languages |
| **Strengths** | Custom rules, taint analysis, supply chain reachability |
| **Languages** | 30+ languages including Python, JavaScript, Go, Java, C#, Ruby |
| **When to Use** | Every commit, pre-push, PR validation |
| **Cost** | Free tier available, Pro features for enterprise |

**Key Capabilities:**
- ✅ **Multi-language SAST**: Comprehensive code analysis across your stack
- ✅ **Custom Rule Writing**: Tailored security rules for your codebase
- ✅ **Supply Chain Analysis**: Reachable vulnerability detection
- ✅ **Taint Analysis**: Complex vulnerability flow detection
- ✅ **IDE Integration**: Real-time feedback in developer environments

**Example Detection:**
```python
# ❌ Vulnerable code detected by Semgrep
import yaml
def load_config(file_path):
    with open(file_path) as f:
        return yaml.load(f)  # ⚠️ Unsafe YAML loading
```

### 2. Trivy (Swiss Army Knife)

**Primary Domain**: Multi-vector security scanning

| Feature | Details |
|---------|---------|
| **Purpose** | Comprehensive vulnerability scanning across multiple domains |
| **Strengths** | Containers, IaC, dependencies, secrets, licenses - all in one tool |
| **Platforms** | Linux, macOS, Windows, Docker, Kubernetes |
| **When to Use** | Build time, CI/CD pipelines, infrastructure validation |
| **Cost** | Completely free and open source |

**Key Capabilities:**
- ✅ **Container Security**: Image vulnerability scanning, misconfiguration detection
- ✅ **IaC Security**: Terraform, Kubernetes, CloudFormation, ARM templates
- ✅ **Dependency Scanning**: Language package vulnerabilities, license compliance
- ✅ **Secrets Detection**: Basic secret detection in files and configurations
- ✅ **Infrastructure Scanning**: Running container and host vulnerability analysis

**Example Detection:**
```dockerfile
# ❌ Vulnerable Dockerfile detected by Trivy
FROM ubuntu:18.04  # ⚠️ Unsupported base image
RUN apt-get update && apt-get install nginx=1.14.*  # ⚠️ Vulnerable package
```

### 3. TruffleHog (Secrets Specialist)

**Primary Domain**: Advanced secrets detection

| Feature | Details |
|---------|---------|
| **Purpose** | Deep, thorough secrets detection across git history |
| **Strengths** | Entropy analysis, historical scanning, verified detectors |
| **Platforms** | Git, filesystem, GitHub, GitLab, S3 |
| **When to Use** | Pre-commit, PR validation, repository audits |
| **Cost** | Free and open source |

**Key Capabilities:**
- ✅ **Deep Git History**: Scans entire commit history for leaked secrets
- ✅ **Entropy Analysis**: Detects high-entropy strings that might be secrets
- ✅ **Verified Detectors**: Reduces false positives with verification logic
- ✅ **Multiple Sources**: Git repos, filesystems, cloud storage
- ✅ **Custom Detectors**: Create custom secret detection patterns

**Example Detection:**
```bash
# ❌ Secret detected by TruffleHog
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"  # ⚠️ AWS access key
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # ⚠️ AWS secret
```

---

## 📊 Coverage Matrix

### Complete Security Coverage Map

| Security Domain | Primary Tool | Secondary Tool | Coverage Level |
|-----------------|--------------|----------------|----------------|
| **Static Analysis (SAST)** | Semgrep ✅ | - | **Complete** |
| **Software Composition Analysis (SCA)** | Trivy ✅ | Semgrep | **Complete** |
| **Infrastructure as Code (IaC)** | Trivy ✅ | Semgrep | **Complete** |
| **Container Security** | Trivy ✅ | - | **Complete** |
| **Secrets Detection** | TruffleHog ✅ | Trivy | **Complete** |
| **License Compliance** | Trivy ✅ | - | **Complete** |
| **Supply Chain Security** | Semgrep ✅ | Trivy | **Complete** |
| **Runtime Vulnerabilities** | Trivy ✅ | - | **Complete** |
| **Configuration Security** | Trivy ✅ | Semgrep | **Complete** |

### Tool Domain Analysis

#### Semgrep Coverage Areas
```
✅ Source Code Vulnerabilities (SAST)
✅ Custom Security Rules
✅ Language-Specific Issues
✅ Business Logic Flaws
✅ API Security Issues
✅ Authentication/Authorization
✅ Input Validation Issues
✅ Cryptographic Misuse
✅ Supply Chain Reachability
```

#### Trivy Coverage Areas
```
✅ Container Image Vulnerabilities
✅ Infrastructure as Code (Terraform, K8s, CloudFormation)
✅ Package Dependencies (Python, Node.js, Go, Java)
✅ License Compliance
✅ Configuration Misconfigurations
✅ OS Package Vulnerabilities
✅ Basic Secrets Detection
✅ Runtime Container Security
✅ Host Vulnerability Scanning
```

#### TruffleHog Coverage Areas
```
✅ Secret Detection in Git History
✅ High-Entropy String Detection
✅ API Keys & Tokens
✅ Database Credentials
✅ SSH Keys & Certificates
✅ Cloud Provider Credentials
✅ Historical Secret Leaks
✅ Custom Secret Patterns
✅ Multi-Repository Scanning
```

---

## 🔄 Integration Strategies

### Development Workflow Integration

#### 1. Pre-Commit Phase (Developer Machine)
```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔍 Running security scans..."

# Quick SAST scan
semgrep --config=auto --error . || {
    echo "❌ Semgrep found security issues"
    exit 1
}

# Check for recent secrets
trufflehog git file://. --since-commit HEAD --only-verified --fail || {
    echo "❌ TruffleHog found potential secrets"
    exit 1
}

echo "✅ Security checks passed!"
```

#### 2. Pull Request Validation (CI/CD)
```yaml
# GitHub Actions Example
name: Security Validation
on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      # Full SAST scan
      - name: Semgrep Security Scan
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/python
            p/javascript

      # Comprehensive vulnerability scan
      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH,MEDIUM'
          scanners: 'vuln,secret,config'

      # Deep secrets scan
      - name: TruffleHog Secrets Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.base_ref }}
          head: HEAD
          extra_args: --only-verified
```

#### 3. Build Pipeline Integration
```bash
#!/bin/bash
# build-with-security.sh

echo "🏗️  Starting secure build process..."

# 1. Code scanning
echo "→ Running Semgrep on source code..."
semgrep --config=p/security-audit --error . || exit 1

# 2. Dependency scanning
echo "→ Scanning dependencies with Trivy..."
trivy fs --scanners vuln,license --severity HIGH,CRITICAL . || exit 1

# 3. Infrastructure validation
echo "→ Validating IaC with Trivy..."
trivy config ./infrastructure/ || exit 1

# 4. Build application
echo "→ Building application..."
docker build -t myapp:${BUILD_NUMBER} . || exit 1

# 5. Image security scan
echo "→ Scanning built image..."
trivy image --severity HIGH,CRITICAL myapp:${BUILD_NUMBER} || exit 1

echo "✅ Secure build completed successfully!"
```

### Infrastructure as Code Coverage

#### Terraform Security with Trivy
```bash
# Scan Terraform configurations
trivy config ./terraform/

# Example Terraform issues caught:
resource "aws_security_group" "example" {
  # ❌ Trivy detects: Open inbound ports
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ⚠️ Overly permissive
  }

  # ❌ Trivy detects: Missing egress rules
  # No egress block defined - default allows all outbound traffic
}
```

#### Kubernetes Security with Trivy
```yaml
# Example Kubernetes security issues detected
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  securityContext: {}  # ❌ Missing security context
  containers:
  - name: app
    image: ubuntu:18.04  # ❌ Trivy detects: Vulnerable base image
    securityContext:
      runAsRoot: true   # ❌ Trivy detects: Running as root
      privileged: true  # ❌ Trivy detects: Privileged container
    ports:
    - containerPort: 80
      hostPort: 80      # ❌ Trivy detects: Host port mapping
```

#### CloudFormation Security with Trivy
```yaml
# Example CloudFormation issues detected
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-sensitive-bucket
      # ❌ Trivy detects: Missing access control
      # No PublicAccessBlockConfiguration defined

  MyFunction:
    Type: AWS::Lambda::Function
    Properties:
      Role: arn:aws:iam::123456789012:role/lambda-exec
      # ❌ Trivy detects: Missing VPC configuration
      # Function deployed in default VPC
```

### Container Security Workflow

#### Multi-Stage Container Security
```bash
#!/bin/bash
# secure-container-build.sh

IMAGE_NAME="myapp"
IMAGE_TAG="${BUILD_NUMBER:-dev}"

# 1. Pre-build Dockerfile scan
echo "🔍 Scanning Dockerfile..."
trivy config Dockerfile || exit 1

# 2. Build container
echo "🏗️  Building container image..."
docker build -t ${IMAGE_NAME}:${IMAGE_TAG} . || exit 1

# 3. Post-build vulnerability scan
echo "🔍 Scanning built image..."
trivy image --severity HIGH,CRITICAL ${IMAGE_NAME}:${IMAGE_TAG} || {
    echo "❌ Container scan failed - vulnerabilities found"
    exit 1
}

# 4. Runtime configuration scan
echo "🔍 Validating runtime configuration..."
# Check if image runs as non-root, etc.
docker run --rm ${IMAGE_NAME}:${IMAGE_TAG} id || exit 1

echo "✅ Container security validation passed!"
```

#### Dockerfile Security Best Practices
```dockerfile
# ✅ Secure Dockerfile example
FROM python:3.11-slim as builder  # ✅ Use specific version, slim image

# Install security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install --no-install-recommends -y build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim
WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --chown=appuser:appuser . .

USER appuser  # ✅ Run as non-root user
EXPOSE 8000

CMD ["python", "app.py"]
```

---

## 📈 Implementation Roadmap

### Phase 1: Foundation Setup (Week 1-2)
- [ ] Install and configure core tools in development environments
- [ ] Set up basic pre-commit hooks
- [ ] Configure CI/CD pipeline integrations
- [ ] Create initial security scanning workflows

### Phase 2: Coverage Expansion (Week 3-4)
- [ ] Implement custom Semgrep rules for business logic
- [ ] Set up comprehensive IaC scanning
- [ ] Configure container security workflows
- [ ] Establish baseline security metrics

### Phase 3: Advanced Integration (Week 5-6)
- [ ] Implement advanced TruffleHog configurations
- [ ] Set up license compliance scanning
- [ ] Configure supply chain security monitoring
- [ ] Establish security metrics dashboard

### Phase 4: Optimization & Monitoring (Week 7-8)
- [ ] Fine-tune scanning rules to reduce false positives
- [ ] Implement performance optimizations
- [ ] Set up security metrics and alerting
- [ ] Create developer training materials

---

## 🎯 Success Metrics

### Development Metrics
- **Vulnerability Detection Rate**: >95% of issues caught in development
- **Mean Time to Remediation**: <24 hours for high/critical findings
- **Developer Adoption Rate**: >90% of developers using tools regularly
- **False Positive Rate**: <5% for high-severity findings

### Operational Metrics
- **Scan Performance**: <5 minutes for incremental scans, <30 minutes for full scans
- **CI/CD Integration**: 100% of pipelines include security scanning
- **Coverage**: 100% of codebases and infrastructure scanned
- **Tool Reliability**: >99% uptime for security scanning services

### Business Impact
- **Cost Reduction**: 80% reduction in security remediation costs
- **Risk Reduction**: 90% reduction in production security incidents
- **Compliance**: 100% audit coverage for security requirements
- **Developer Velocity**: No measurable slowdown in development speed

---

## 🔧 Tool Configuration Examples

### Semgrep Advanced Configuration
```yaml
# .semgrep.yaml
rules:
  - id: custom-api-security
    pattern: |
      @app.route("/api/$ROUTE")
      def $FUNC(...):
          ...
    message: "API endpoint $ROUTE should include authentication and rate limiting"
    languages: [python]
    severity: WARNING
    paths:
      include:
        - "app.py"
        - "api/*.py"
    metadata:
      category: security
      owasp: "A07:2021 - Identification and Authentication Failures"

  - id: sensitive-operations
    pattern: |
      subprocess.run($CMD, shell=True, ...)
    message: "Use subprocess.run without shell=True to avoid command injection"
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-78"
```

### Trivy Policy Configuration
```yaml
# trivy-policy.yaml
# Custom security policies for Trivy

policy:
  # Container security policies
  containers:
    - name: "no-root-user"
      message: "Container should not run as root"
      regex: "^USER root"
      severity: "HIGH"

    - name: "specific-base-image"
      message: "Use specific base image versions"
      regex: "^FROM.*:(latest|alpine)$"
      severity: "MEDIUM"

  # IaC security policies
  terraform:
    - name: "no-open-ingress"
      message: "Security group should not allow open ingress"
      regex: "cidr_blocks.*\\[\"0\\.0\\.0\\.0/0\"\\]"
      severity: "CRITICAL"
```

### TruffleHog Custom Configuration
```yaml
# .trufflehog.yaml
version: v3

# Custom detector configurations
detectors:
  - name: AWS Access Key
    type: regex
    regex: 'AKIA[0-9A-Z]{16}'
    keywords: ["aws", "s3", "ec2"]
    verify:
      - endpoint: https://iam.amazonaws.com
        headers:
          Authorization: "AWS4-HMAC-SHA256 ... {{ .Secret }}"

  - name: Database Connection String
    type: regex
    regex: '(mysql|postgresql)://[^:]+:[^@]+@[^/]+'
    keywords: ["database", "db", "connection"]

# Source configuration
sources:
  - name: git
    path: .
    depth: 50

  - name: filesystem
    paths:
      - src/
      - config/
    exclude_paths:
      - tests/
      - node_modules/

# Output configuration
output:
  format: json
  file: trufflehog-results.json
```

---

## 🚨 Incident Response Integration

### Security Finding Triage Process

#### 1. Critical Findings (Immediate Action)
```bash
# Automated response for critical vulnerabilities
if [[ $(trivy image --severity CRITICAL myapp:latest | wc -l) -gt 0 ]]; then
    echo "🚨 CRITICAL: Container vulnerabilities detected"
    # Block deployment
    exit 1
fi
```

#### 2. High Severity Findings (24-hour SLA)
```bash
# Automated ticket creation for high findings
HIGH_FINDINGS=$(semgrep --config=p/security-audit --json . | jq '.results[] | select(.metadata.severity == "ERROR")')
if [[ ! -z "$HIGH_FINDINGS" ]]; then
    echo "🔴 HIGH: Security issues require attention"
    # Create Jira ticket or GitHub issue
    # Assign to security team
fi
```

#### 3. Medium/Low Findings (Planned Remediation)
```bash
# Weekly security digest
MEDIUM_FINDINGS=$(trivy fs --severity MEDIUM . | wc -l)
echo "📊 Weekly security summary: $MEDIUM_FINDINGS medium issues found"
# Add to backlog
# Plan for next sprint
```

---

## 🔍 Advanced Use Cases

### Supply Chain Security Monitoring

#### Dependency Reachability Analysis
```bash
# Semgrep supply chain analysis
semgrep --config=auto --pro . | jq '.results[] | select(.metadata.metadata.dev.semgrep.dev.reachable == true)'

# Trivy dependency scanning with reachability
trivy fs --scanners vuln --pkg-types npm,pypi,maven . | jq '.Results[] | select(.Vulnerabilities[].VulnerabilityID)'
```

#### SBOM Generation and Analysis
```bash
# Generate SBOM with Trivy
trivy image --format spdx-json --output sbom.spdx.json myapp:latest

# Analyze SBOM for compliance
trivy sbom --format table sbom.spdx.json
```

### Multi-Repository Security Scanning

#### Organization-wide Security Assessment
```bash
#!/bin/bash
# scan-all-repos.sh

ORGANIZATION="myorg"
REPOS=$(gh repo list $ORGANIZATION --limit 100 --json name | jq -r '.[].name')

for repo in $REPOS; do
    echo "🔍 Scanning repository: $repo"

    # Clone repository
    gh repo clone $ORGANIZATION/$repo

    # Run security scans
    cd $repo
    semgrep --config=auto --json --output ../results-${repo}.json .
    trivy fs --format json --output ../trivy-${repo}.json .
    trufflehog git file://. --json --output ../secrets-${repo}.json .

    cd ..
    rm -rf $repo
done

# Generate summary report
python3 generate-security-report.py results-*.json trivy-*.json secrets-*.json
```

### Compliance and Auditing

#### Automated Compliance Reporting
```bash
#!/bin/bash
# compliance-report.sh

echo "📋 Generating security compliance report..."

# OWASP Top 10 compliance
OWASP_FINDINGS=$(semgrep --config=p/owasp-top-ten --json . | jq '.results | length')

# CIS Docker Benchmark compliance
CIS_FINDINGS=$(trivy image --compliance docker-cis myapp:latest | jq '.Results | length')

# License compliance
LICENSE_FINDINGS=$(trivy fs --scanners license . | jq '.Results | length')

echo "Compliance Summary:"
echo "- OWASP Top 10 findings: $OWASP_FINDINGS"
echo "- CIS Docker issues: $CIS_FINDINGS"
echo "- License issues: $LICENSE_FINDINGS"

# Generate report
cat > compliance-report.html << EOF
<!DOCTYPE html>
<html>
<head><title>Security Compliance Report</title></head>
<body>
<h1>Security Compliance Report</h1>
<p>Generated on: $(date)</p>
<h2>OWASP Top 10 Compliance</h2>
<p>Findings: $OWASP_FINDINGS</p>
<h2>CIS Docker Benchmark</h2>
<p>Issues: $CIS_FINDINGS</p>
<h2>License Compliance</h2>
<p>Issues: $LICENSE_FINDINGS</p>
</body>
</html>
EOF
```

---

## 📚 Training and Documentation

### Developer Security Training Checklist

#### 1. Tool Installation and Setup
- [ ] Install Semgrep, Trivy, and TruffleHog locally
- [ ] Configure IDE integrations
- [ ] Set up pre-commit hooks
- [ ] Verify tools are working correctly

#### 2. Daily Security Workflow
- [ ] Run pre-commit scans before every commit
- [ ] Review and understand scan results
- [ ] Fix high/critical findings immediately
- [ ] Document any accepted risks

#### 3. Pull Request Security Review
- [ ] Run full security scans before PR
- [ ] Review all security findings
- [ ] Address findings or provide justification
- [ ] Ensure no new high/critical issues introduced

#### 4. Container Security
- [ ] Scan Dockerfiles before building
- [ ] Scan built images before deployment
- [ ] Use minimal, specific base images
- [ ] Run containers as non-root users

#### 5. Infrastructure Security
- [ ] Scan Terraform/IaC files before applying
- [ ] Review all security-related findings
- [ ] Follow cloud security best practices
- [ ] Document any security exceptions

### Quick Reference Guide

```bash
# Daily security commands
semgrep --config=auto .                    # Quick code scan
trufflehog git file://. --since-commit HEAD  # Recent secrets check

# Pre-PR commands
semgrep --config=p/security-audit .        # Deep security scan
trivy fs --severity HIGH,CRITICAL .        # Dependency scan
trufflehog git file://. --since-commit main # Full secrets scan

# Container security
trivy config Dockerfile                    # Scan Dockerfile
trivy image myapp:latest                   # Scan built image

# Infrastructure security
trivy config ./terraform/                  # Scan IaC
semgrep --config=p/terraform ./terraform/ # Additional IaC checks
```

---

## 🔄 Maintenance and Updates

### Regular Maintenance Tasks

#### Weekly
- [ ] Update vulnerability databases (`trivy image --download-db-only`)
- [ ] Review and triage new security findings
- [ ] Update custom rules based on new threats

#### Monthly
- [ ] Update all security tools to latest versions
- [ ] Review and optimize scanning performance
- [ ] Update custom rule configurations
- [ ] Review security metrics and trends

#### Quarterly
- [ ] Conduct comprehensive security tooling review
- [ ] Evaluate new security tools or features
- [ ] Update security policies and procedures
- [ ] Provide security training refreshers

### Tool Update Process

```bash
#!/bin/bash
# update-security-tools.sh

echo "🔄 Updating security tools..."

# Update Semgrep
pip install --upgrade semgrep
semgrep --version

# Update Trivy
brew upgrade trivy  # or use appropriate package manager
trivy --version

# Update TruffleHog
brew upgrade trufflehog
trufflehog --version

# Update vulnerability databases
trivy image --download-db-only

echo "✅ Security tools updated successfully!"
```

---

## 📞 Support and Resources

### Getting Help
- **Semgrep Support**: [support@semgrep.com](mailto:support@semgrep.com)
- **Trivy Issues**: [GitHub Issues](https://github.com/aquasecurity/trivy/issues)
- **TruffleHog Support**: [Discord Community](https://discord.gg/trufflehog)

### Documentation Links
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)

### Community Resources
- [Semgrep Community Slack](https://go.semgrep.dev/slack)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

---

## 📄 Conclusion

This comprehensive security tooling strategy provides complete coverage across all critical security domains while maintaining a minimal, efficient toolset. The combination of **Semgrep**, **Trivy**, and **TruffleHog** offers:

- ✅ **Complete Security Coverage** across code, infrastructure, and dependencies
- ✅ **Minimal Tool Overlap** with clear domain ownership
- ✅ **Open Source Solutions** with active community support
- ✅ **Developer-Friendly** integration and workflows
- ✅ **Scalable Architecture** that grows with your organization

By implementing this tooling stack and following the integration strategies outlined in this document, your organization can achieve robust security coverage while maintaining development velocity and minimizing operational overhead.

---

**Document Version**: 1.0
**Last Updated**: $(date)
**Next Review**: $(date -d "+3 months")
**Maintained by**: Security Engineering Team