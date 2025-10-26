# Security Scanning Guide for Developers

> A comprehensive guide for integrating security scanning into your development workflow

---

## 🔄 GitHub Actions Integration

Your IDE security tools are now integrated with comprehensive GitHub Actions workflows that run automatically on every commit and pull request. This ensures that security vulnerabilities, secrets, and compliance issues are blocked **before** they can be merged into your codebase.

### What Gets Blocked at Commit Time

#### 🚫 **Critical Security Issues**
- **SQL Injection vulnerabilities** in your code
- **Hardcoded secrets** (API keys, passwords, tokens)
- **Command injection** vulnerabilities
- **Cross-site scripting (XSS)** vulnerabilities
- **Insecure cryptographic practices**
- **Debug mode enabled** in production code

#### 🔐 **Secret Detection**
- **AWS Access Keys** and Secret Keys
- **Database credentials** and connection strings
- **API tokens** and service account keys
- **JWT secrets** and private keys
- **SSL certificates** and cryptographic keys
- **Any high-entropy strings** that might be secrets

#### 📦 **Dependency & Container Issues**
- **Known vulnerable dependencies** in package.json, requirements.txt, go.mod
- **Insecure container images** and base images
- **Infrastructure as Code** misconfigurations (Terraform, Kubernetes)
- **License compliance** violations

### How It Works: The Security Pipeline

```
Git Commit → GitHub Actions → Security Scan → Results → Action
     ↓              ↓               ↓           ↓         ↓
  Your Code   →  TruffleHog   →  Secrets? →  Found?  →  ❌ BLOCK
                Semgrep    →  Code Vulns? → Found? →  ❌ BLOCK
                Trivy      →  Deps/IaC? → Found? →  ❌ BLOCK
                All Tools  →  Report    →  Summary →  ✅ PASS
```

### Real-World Examples

#### Example 1: Accidentally Committing an API Key

```python
# ❌ BAD - This will be blocked
api_key = "sk-1234567890abcdef1234567890abcdef"  # TruffleHog detects this

def get_user_data():
    headers = {"Authorization": f"Bearer {api_key}"}
    # ... rest of code
```

**What happens**:
1. You commit the code
2. TruffleHog detects the API key in the GitHub Action
3. The pipeline fails and blocks the merge
4. You get a PR comment: "🚨 SECRETS DETECTED - Please remove immediately"
5. You must remove the secret and re-commit

#### Example 2: SQL Injection Vulnerability

```python
# ❌ BAD - This will be blocked
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id  # Semgrep detects SQL injection
    cursor.execute(query)
    return cursor.fetchall()
```

**What happens**:
1. You create a pull request
2. Semgrep analyzes the code and finds SQL injection
3. The security pipeline fails
4. You get a PR comment with detailed fix instructions
5. You must fix the vulnerability before merge

#### Example 3: Vulnerable Dependency

```json
// package.json - This will be flagged
{
  "dependencies": {
    "lodash": "4.17.15",  // Trivy detects known CVE in this version
    "express": "4.16.0"   // Outdated version with vulnerabilities
  }
}
```

**What happens**:
1. Automatic dependency scanning in GitHub Actions
2. Trivy identifies vulnerable package versions
3. Security report generated with upgrade recommendations
4. Must update dependencies before merge

### 📊 What You'll See in Pull Requests

Every PR gets automated security comments:

```
## 🔍 Security Scan Results

| Tool | Findings | Status |
|------|----------|---------|
| Semgrep | 3 findings | ❌ Needs Review |
| TruffleHog | 1 secret | ❌ BLOCKS MERGE |
| Trivy | 2 vulnerabilities | ⚠️ Recommended Fix |

### 🚨 Action Required
**SECRETS DETECTED** - Please review and remove immediately

### 📍 Issues Found:
- `config.py:15` - AWS Access Key detected
- `user_service.py:23` - SQL injection vulnerability
- `package.json` - Outdated dependencies

### 🔧 Recommended Actions:
1. Remove the AWS key from config.py
2. Use parameterized queries in user_service.py
3. Update lodash to latest version

[View detailed results in Security tab]
```

### ⚡ How to Fix Security Issues Quickly

#### 1. **Remove Secrets Immediately**
```python
# ❌ BEFORE (blocked)
api_key = "sk-1234567890abcdef1234567890abcdef"

# ✅ AFTER (allowed)
import os
api_key = os.getenv("API_KEY")  # Use environment variable
```

#### 2. **Fix Code Vulnerabilities**
```python
# ❌ BEFORE (blocked)
query = "SELECT * FROM users WHERE id = " + user_id

# ✅ AFTER (allowed)
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

#### 3. **Update Dependencies**
```bash
# npm audit fix
npm update

# or pip
pip install --upgrade -r requirements.txt
```

### 🛠️ Local Testing Before Commit

To avoid pipeline failures, test locally first:

```bash
# Run the same tools that run in CI
semgrep --config=auto .
trufflehog git file://. --since-commit HEAD
trivy fs .

# Fix issues before committing
git add .
git commit -m "Fix security issues found in pre-commit scan"
```

### 📋 GitHub Actions Workflows

Your repository has 4 security workflows:

1. **[🔍 Semgrep Security Scan](../../.github/workflows/semgrep-security.yml)** - Static code analysis
2. **[🛡️ Trivy Security Scan](../../.github/workflows/trivy-security.yml)** - Dependencies and containers
3. **[🐷 TruffleHog Secret Detection](../../.github/workflows/trufflehog-security.yml)** - Secret scanning
4. **[🛡️ Comprehensive Security Pipeline](../../.github/workflows/comprehensive-security.yml)** - Master orchestration

### 🚀 Benefits

- **Zero Trust Security**: Nothing gets merged without security review
- **Automated Enforcement**: No manual security reviews needed
- **Fast Feedback**: Issues caught immediately, not in production
- **Developer Friendly**: Clear instructions on how to fix issues
- **Compliance Ready**: Automated audit trails and security reporting

---

**Remember**: The security tools are here to help you build better, more secure code. They catch mistakes before they become problems in production! 

## 📋 Table of Contents

- [Overview](#overview)
- [Why Security Scanning Matters](#why-security-scanning-matters)
- [Tools Overview](#tools-overview)
- [Installation](#installation)
- [Quick Start](#quick-start---what-to-run-when)
- [Detailed Usage](#detailed-usage)
- [Pre-commit Hook Setup](#pre-commit-hook-setup)
- [CI/CD Integration](#cicd-integration-examples)
- [Understanding Results](#understanding-results)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Quick Reference](#quick-reference-card)
- [Resources](#resources)

## Overview

This guide helps you integrate security scanning into your development workflow. Running these scans early catches vulnerabilities before they reach production, reducing security debt and remediation costs.

## Why Security Scanning Matters

- **Shift Left**: Catch vulnerabilities during development, not in production
- **Compliance**: Meet security requirements for audits and certifications
- **Cost Reduction**: Fixing issues early is 10-100x cheaper than post-deployment
- **Developer Empowerment**: Get immediate feedback on security issues you can fix

---

## Tools Overview

| Tool | Purpose | When to Use |
|------|---------|-------------|
| **[Semgrep](https://semgrep.dev)** | Static code analysis (SAST) | Every commit, pre-push |
| **[Trivy](https://trivy.dev)** | Container, IaC, dependencies, secrets | Before builds, in CI/CD |
| **[TruffleHog](https://trufflesecurity.com)** | Deep secrets detection | Pre-commit, before PRs |

---

## Installation

### Semgrep

```bash
# Using pip
pip install semgrep

# Using Homebrew (macOS)
brew install semgrep

# Using Docker
docker pull semgrep/semgrep
```

**Verify installation:**
```bash
semgrep --version
```

### Trivy

```bash
# Using Homebrew (macOS/Linux)
brew install aquasecurity/trivy/trivy

# Using apt (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Using Docker
docker pull aquasec/trivy
```

**Verify installation:**
```bash
trivy --version
```

### TruffleHog

```bash
# Using Homebrew (macOS/Linux)
brew install trufflesecurity/trufflehog/trufflehog

# Using Docker
docker pull trufflesecurity/trufflehog:latest

# Using Go
go install github.com/trufflesecurity/trufflehog/v3@latest
```

**Verify installation:**
```bash
trufflehog --version
```

---

## Quick Start - What to Run When

### ⚡ Before Every Commit

```bash
# Scan your code changes for vulnerabilities
semgrep --config=auto .

# Check for secrets in staged files
trufflehog git file://. --since-commit HEAD --only-verified
```

### 🔍 Before Opening a Pull Request

```bash
# Full code scan with custom rules
semgrep --config=p/security-audit --config=p/owasp-top-ten .

# Scan dependencies and licenses
trivy fs --scanners vuln,secret,license .

# Deep secrets scan including git history
trufflehog git file://. --since-commit main
```

### 🐳 Before Building Container Images

```bash
# Scan Dockerfile for misconfigurations
trivy config Dockerfile

# After building, scan the image
trivy image your-image:tag
```

### ☁️ For Infrastructure as Code

```bash
# Scan Terraform files
trivy config ./terraform/

# Scan Kubernetes manifests
trivy config ./k8s/

# Additional IaC checks with Semgrep
semgrep --config=p/terraform ./terraform/
```

---

## Detailed Usage

### Semgrep - Static Application Security Testing (SAST)

#### Basic Scan
```bash
# Auto-detect and scan with community rules
semgrep --config=auto .
```

#### Targeted Scans
```bash
# OWASP Top 10 vulnerabilities
semgrep --config=p/owasp-top-ten .

# Language-specific rules (e.g., Python)
semgrep --config=p/python .

# Security audit ruleset
semgrep --config=p/security-audit .
```

#### Custom Rules
```bash
# Scan with your organization's rules
semgrep --config=./custom-rules/ .
```

#### CI/CD Integration
```bash
# Exit with error code if findings
semgrep --config=auto --error .

# JSON output for automation
semgrep --config=auto --json -o results.json .
```

#### What Semgrep Catches:
- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Insecure cryptography
- Authentication/authorization flaws
- Hardcoded credentials (basic detection)

---

### Trivy - Comprehensive Security Scanner

#### Filesystem Scanning
```bash
# Scan current directory for vulnerabilities, secrets, and licenses
trivy fs .

# Scan only for high/critical vulnerabilities
trivy fs --severity HIGH,CRITICAL .

# Scan specific types
trivy fs --scanners vuln,secret .
```

#### Container Image Scanning
```bash
# Scan a Docker image
trivy image nginx:latest

# Scan with specific severity
trivy image --severity HIGH,CRITICAL myapp:1.0

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed myapp:1.0
```

#### Infrastructure as Code
```bash
# Scan Terraform
trivy config ./terraform/

# Scan Kubernetes manifests
trivy config ./k8s/

# Scan with specific policy
trivy config --policy ./policy/ ./infra/
```

#### Dependency Scanning
```bash
# Scan package files
trivy fs --scanners vuln package.json
trivy fs --scanners vuln requirements.txt
trivy fs --scanners vuln go.mod
```

#### What Trivy Catches:
- CVEs in dependencies and OS packages
- Container misconfigurations
- IaC security issues (Terraform, K8s, CloudFormation)
- License compliance violations
- Exposed secrets in files
- Outdated base images

---

### TruffleHog - Secrets Detection

#### Git Repository Scan
```bash
# Scan entire git history
trufflehog git file://. --only-verified

# Scan since specific commit
trufflehog git file://. --since-commit HEAD~10

# Scan specific branch
trufflehog git file://. --branch feature/new-feature
```

#### Filesystem Scan
```bash
# Scan files and directories
trufflehog filesystem ./src/

# Scan with JSON output
trufflehog filesystem . --json
```

#### GitHub/GitLab Scanning
```bash
# Scan remote repository
trufflehog github --repo https://github.com/org/repo

# Scan organization
trufflehog github --org your-org
```

#### What TruffleHog Catches:
- API keys (AWS, Azure, GCP, GitHub, etc.)
- Private keys and certificates
- Database credentials
- OAuth tokens
- Slack tokens
- Generic secrets via entropy detection
- Historical secrets in git commits

---

## Pre-commit Hook Setup

Add this to `.git/hooks/pre-commit` (make it executable with `chmod +x`):

```bash
#!/bin/bash

echo "Running security scans..."

# Run Semgrep
echo "→ Running Semgrep..."
semgrep --config=auto --error . || exit 1

# Run TruffleHog on staged files
echo "→ Running TruffleHog..."
trufflehog git file://. --since-commit HEAD --only-verified --fail || exit 1

echo "✓ Security scans passed!"
```

---

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
      
      - name: Run TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: main
          head: HEAD
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
    - curl -sSL https://github.com/aquasecurity/trivy/releases/download/v0.45.0/trivy_0.45.0_Linux-64bit.tar.gz | tar -xz
  script:
    - docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config=auto /src
    - ./trivy fs --severity HIGH,CRITICAL .
    - docker run --rm -v "${PWD}:/scan" trufflesecurity/trufflehog:latest filesystem /scan
```

---

## Understanding Results

### Severity Levels

| Severity | Action Required | Description |
|----------|----------------|-------------|
| **CRITICAL** | Immediate | Exploitable vulnerabilities, fix before merge |
| **HIGH** | Soon | Should be fixed before merging |
| **MEDIUM** | Planned | Plan to fix in upcoming sprints |
| **LOW** | Optional | Fix when convenient, or accept risk |
| **INFO** | Awareness | Best practices, informational only |

### Common False Positives

- Test files with intentional vulnerabilities
- Vendored/third-party code
- Configuration files with example credentials

**How to Handle:**
1. Verify it's actually a false positive
2. Add to ignore file (see below)
3. Document why it's ignored

### Ignore Files

#### Semgrep (`.semgrepignore`)
```
tests/
vendor/
node_modules/
*.test.js
```

#### Trivy (`.trivyignore`)
```
# CVE-2021-1234 is not applicable to our use case
CVE-2021-1234

# Waiting for upstream fix
CVE-2022-5678
```

#### TruffleHog (use `--exclude-paths` flag)
```bash
trufflehog filesystem . --exclude-paths exclude-paths.txt
```

---

## Best Practices

### Development Workflow

1. **Write code** with security in mind
2. **Run quick scans** before committing (`semgrep --config=auto`)
3. **Run full scans** before opening PRs
4. **Review findings** - don't blindly ignore warnings
5. **Fix or document** - either fix the issue or document why it's accepted risk

### Team Practices

- **Educate**: Share findings in code reviews as learning opportunities
- **Don't block unnecessarily**: Use severity thresholds appropriately
- **Maintain scanning speed**: Keep scans under 5 minutes for developer workflow
- **Regular updates**: Update tools and rulesets monthly
- **Track metrics**: Monitor trends in vulnerability introduction and remediation

### Performance Tips

- Scan only changed files in pre-commit hooks
- Use caching in CI/CD pipelines
- Run full scans nightly, quick scans on every commit
- Parallelize scans when possible

---

## Troubleshooting

### Semgrep is slow
- Use specific configs instead of `--config=auto`
- Add exclusions to `.semgrepignore`
- Scan only changed files in hooks

### Trivy database update fails
```bash
# Manually update the vulnerability database
trivy image --download-db-only
```

### TruffleHog too many false positives
- Use `--only-verified` flag to reduce noise
- Create verified detector configurations
- Use `--exclude-paths` for test/vendor directories

### Tool not found in CI/CD
- Verify installation commands for specific CI environment
- Check tool versions are compatible
- Use Docker images for consistency

---

## Quick Reference Card

```bash
# Daily workflow
semgrep --config=auto .                    # Quick code scan
trufflehog git file://. --since-commit HEAD  # Check for secrets

# Before PR
semgrep --config=p/security-audit .        # Deep code scan
trivy fs .                                 # Full dependency scan
trufflehog git file://. --since-commit main  # Historical secrets

# Container workflow
trivy config Dockerfile                    # Scan Dockerfile
docker build -t myapp:dev .               # Build image
trivy image myapp:dev                     # Scan image

# IaC workflow
trivy config ./terraform/                  # Scan Terraform
semgrep --config=p/terraform ./terraform/  # Additional checks
```

---

## Resources

### Documentation
- [Semgrep Documentation](https://semgrep.dev/docs/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog)

### Security Resources
- [OWASP Top 10](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVE Database](https://cve.mitre.org/)

### Community
- [Semgrep Community Slack](https://go.semgrep.dev/slack)
- [r/netsec](https://reddit.com/r/netsec)
- [DevSecOps Community](https://www.devsecops.org/)

---

## Contributing

Found an issue or have a suggestion? Please open an issue or submit a pull request!

## License

This documentation is provided as-is for educational purposes.

---

**Made with ❤️ for secure development**