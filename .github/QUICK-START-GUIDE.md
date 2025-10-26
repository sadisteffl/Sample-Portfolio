# 🚀 Quick Start Guide: GitHub Security Automation

## ⚡ 5-Minute Setup

### 1. Required Secrets

Add these secrets to your GitHub repository (`Settings` > `Secrets and variables` > `Actions`):

```bash
# For Semgrep (optional but recommended)
SEMGREP_APP_TOKEN=your_semgrep_app_token

# For Slack notifications (optional)
SLACK_WEBHOOK_URL=your_slack_webhook_url
```

### 2. Enable GitHub Actions Security Features

1. Go to `Settings` > `Security & analysis`
2. Enable:
   - ✅ **Dependabot alerts**
   - ✅ **Dependabot security updates**
   - ✅ **Code scanning** (if GitHub Advanced Security is available)

### 3. Configure Branch Protection

1. Go to `Settings` > `Branches`
2. Add branch protection rule for `main` branch:
   - ✅ **Require status checks to pass before merging**
   - ✅ **Require branches to be up to date before merging**
   - ✅ Add required status checks:
     - `security-scan / trivy-scan`
     - `security-scan / semgrep-scan`
     - `security-scan / trufflehog-scan`

## 🔧 First Run

### Trigger Security Scan

```bash
# Option 1: Push a change
git add .
git commit -m "🛡️ Enable security automation"
git push origin main

# Option 2: Manual trigger
# Go to Actions tab > "🛡️ Comprehensive Security Scan" > "Run workflow"
```

### Check Results

1. **GitHub Actions Tab**: Monitor scan progress
2. **Security Tab**: View SARIF results
3. **Pull Requests**: See security comments
4. **Issues**: Check for auto-created security issues

## 📊 Understanding Results

### Severity Levels

| Level | Action Required | Example |
|-------|-----------------|---------|
| 🚨 **CRITICAL** | **IMMEDIATE** | Remote code execution |
| ⚠️ **HIGH** | **URGENT** | SQL injection, XSS |
| ⚡ **MEDIUM** | **Important** | Outdated dependencies |
| ℹ️ **LOW** | **Monitor** | Minor security issues |
| ℹ️ **INFO** | **Review** | Best practices |

### Tool-Specific Results

#### 🔍 Trivy Results
- **File System Scan**: Local file vulnerabilities
- **Configuration Scan**: IaC misconfigurations
- **Container Scan**: Docker image vulnerabilities

#### 🔎 Semgrep Results
- **Code Analysis**: Security vulnerabilities in source code
- **Best Practices**: Code quality and security patterns
- **Custom Rules**: Organization-specific security checks

#### 🐗 TruffleHog Results
- **Secret Detection**: Exposed credentials and sensitive data
- **Git History**: Historical secret detection
- **Entropy Analysis**: High-entropy pattern detection

## 🛠️ Common Configuration Changes

### Scan Only Specific Files

Update `.github/trivy.yaml`:
```yaml
scan:
  skip-dirs:
    - node_modules
    - vendor
    - .git
  skip-files:
    - "*.log"
    - "*.tmp"
```

### Adjust Severity Levels

Update `.github/semgrep.yaml`:
```yaml
config:
  severity: ERROR  # Only show errors, not warnings
```

### Add Custom Patterns

Update `.github/exclude-patterns.txt`:
```bash
# Exclude test files
**/test/**
**/spec/**
**/mock/**

# Exclude documentation
**/*.md
**/docs/**
```

## 🚨 Troubleshooting

### Scan Fails with Permission Error
```bash
# Check GitHub Actions permissions
Settings > Actions > General > Workflow permissions
# Set to: "Read and write permissions"
```

### Semgrep App Token Issues
```bash
# Generate new token at: https://semgrep.dev/login
# Add to repository secrets as SEMGREP_APP_TOKEN
```

### High False Positive Rate
```bash
# Update exclude patterns
echo "**/test-data/**" >> .github/exclude-patterns.txt
echo "**/fixtures/**" >> .github/exclude-patterns.txt

# Adjust Semgrep severity
sed -i 's/severity: ERROR/severity: WARNING/' .github/semgrep.yaml
```

### Performance Issues
```bash
# Reduce scan scope
# In .github/workflows/security-scan.yml
# Add path filters:
on:
  push:
    paths:
      - '**/*.py'
      - '**/*.js'
      - '**/*.ts'
      - '**/*.java'
      - '**/*.go'
```

## 📈 Optimization Tips

### 1. Reduce Scan Time
```yaml
# Enable caching in workflows
- name: Cache Trivy DB
  uses: actions/cache@v3
  with:
    path: /tmp/trivy-cache
    key: trivy-${{ runner.os }}-${{ hashFiles('**/go.sum', '**/package-lock.json') }}
```

### 2. Focus on High-Risk Changes
```yaml
# Only run full scans on main branch
- if: github.ref == 'refs/heads/main'
  run: semgrep --config=auto .

# Run partial scans on feature branches
- if: github.ref != 'refs/heads/main'
  run: semgrep --config=auto --git-changed-only .
```

### 3. Customize Notifications
```yaml
# Add Slack notifications
- name: Slack Notification
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: failure
    text: "🚨 Security scan failed! Check the results."
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## 🔄 Integration Examples

### With Dependabot

Update `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
```

### With Code Owners

Create `.github/CODEOWNERS`:
```yaml
# Security team owns security findings
.github/workflows/security-scan.yml @security-team

# All findings require security review
**/SECURITY-* @security-team
```

### With Project Management

Auto-create issues for critical findings:
```yaml
# In workflow, add:
- name: Create Jira Issue
  if: failure()
  uses: atlassian/gajira-create@v3
  with:
    project: SEC
    issuetype: Security Issue
    summary: "Security scan failure detected"
    description: "Review security findings and remediate vulnerabilities"
```

## 📱 Mobile Development Specific

### React Native
```yaml
# Add to .github/exclude-patterns.txt
**/ios/Pods/**
**/android/app/build/**
**/node_modules/**
**/.expo/**
```

### iOS Development
```yaml
# Update .github/trivy.yaml
scan:
  skip-dirs:
    - Pods
    - build
    - DerivedData
```

### Android Development
```yaml
# Update .github/trivy.yaml
scan:
  skip-dirs:
    - app/build
    - build
    - .gradle
```

## 🏢 Enterprise Considerations

### Self-Hosted Runners
```yaml
# Use self-hosted runners for security
jobs:
  security-scan:
    runs-on: self-hosted
    # or
    runs-on: [self-hosted, linux, security]
```

### Private Registry Support
```yaml
env:
  TRIVY_USERNAME: ${{ secrets.REGISTRY_USERNAME }}
  TRIVY_PASSWORD: ${{ secrets.REGISTRY_PASSWORD }}
  SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

### Compliance Reporting
```yaml
# Add compliance checks
- name: Compliance Check
  run: |
    # Check for required security headers
    # Verify encryption standards
    # Validate access controls
```

## 📚 Next Steps

1. **Day 1**: Enable basic security scanning
2. **Week 1**: Review and tune configurations
3. **Month 1**: Add custom rules and integrations
4. **Quarter 1**: Optimize performance and coverage
5. **Year 1**: Full security automation maturity

## 🆘 Getting Help

### Documentation Links
- [Trivy Docs](https://aquasecurity.github.io/trivy/)
- [Semgrep Docs](https://semgrep.dev/docs/)
- [TruffleHog Docs](https://trufflesecurity.com/documentation/trufflehog/)
- [GitHub Actions Docs](https://docs.github.com/en/actions)

### Community Support
- GitHub Issues: Create issue in this repository
- Slack: `#security-automation` channel
- Email: `security-team@company.com`

### Emergency Contact
- **Security Pager**: `security-pager@company.com`
- **Incident Response**: Follow incident response playbook
- **Critical Issues**: Contact security team immediately

---

**Need more help?** Check out the comprehensive [Security Automation Documentation](SECURITY-AUTOMATION-README.md) for detailed configuration options and advanced features.

**Quick Tip**: Start with the default configuration, then gradually customize based on your organization's security requirements and development workflow.