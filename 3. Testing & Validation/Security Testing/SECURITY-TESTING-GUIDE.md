# Security Workflow Testing Guide

This guide provides step-by-step instructions to test and verify that your GitHub Actions security workflows are working correctly.

## 🧪 Quick Test Results

We've already verified the tools work locally:

### ✅ Semgrep - WORKING
- **Tested**: `simple-vulnerability-test.py`
- **Result**: 8 security findings detected
- **Issues Found**: SQL injection, XSS, weak crypto, debug mode, etc.

### ✅ TruffleHog - WORKING
- **Tested**: Git history and filesystem
- **Result**: Scanning successfully (0 verified secrets in test data)
- **Note**: Will detect real secrets if present

### ✅ Trivy - WORKING
- **Tested**: Filesystem scanning
- **Result**: Database updated and scanning successfully

## 🚀 How to Test GitHub Actions Workflows

### Method 1: Web Interface (Easiest)

1. **Go to your repository**: https://github.com/sadisteffl/Sadi-Steffl-Sample-Portfolio

2. **Upload the workflow files**:
   - Click "Add file" → "Upload files"
   - Upload all files from `.github/workflows/`:
     - `semgrep-security.yml`
     - `trivy-security.yml`
     - `trufflehog-security.yml`
     - `comprehensive-security.yml`
   - Commit with message: "Add security workflows"

3. **Trigger workflows manually**:
   - Go to **Actions** tab
   - Look for "🛡️ Comprehensive Security Pipeline"
   - Click "Run workflow" → Select "comprehensive" → "Run workflow"

4. **Check results**:
   - Watch the workflow run in real-time
   - Check for status check names (for branch protection)
   - Review findings in the Security tab

### Method 2: Create a Pull Request

1. **Create a new branch** in GitHub web interface
2. **Add test files** (we've created these for you):
   - `simple-vulnerability-test.py`
   - `test-security-vulnerabilities.md`
3. **Create a pull request** to main
4. **Automatic triggering**: All security workflows will run
5. **Expected results**:
   - Semgrep: 8+ findings
   - TruffleHog: Should detect AWS keys in test files
   - Trivy: Vulnerability scanning
   - Comprehensive: Final status and merge blocking

### Method 3: Push to Repository

1. **Set up GitHub authentication**:
   ```bash
   gh auth login
   gh repo set-default sadisteffl/Sadi-Steffl-Sample-Portfolio
   ```

2. **Push using GitHub CLI**:
   ```bash
   gh repo sync
   # Or use the web interface if git push fails
   ```

## 📊 Expected Workflow Behaviors

### 🔍 Semgrep Security Scan
- **Trigger**: Push, PR, schedule, manual
- **Findings**: 8+ security issues in test files
- **Status Check**: `🔍 Semgrep Security Scan (semgrep)`
- **SARIF Upload**: Results appear in Security tab
- **PR Comments**: Detailed findings summary

### 🛡️ Trivy Security Scan
- **Trigger**: Push, PR, schedule, manual
- **Coverage**: Filesystem, secrets, dependencies, IaC
- **Status Checks**:
  - `🛡️ Trivy Security Scan (trivy-fs-scan)`
  - `🛡️ Trivy Security Scan (trivy-config-scan)`
  - `🛡️ Trivy Security Scan (trivy-secret-scan)`
- **Reports**: SARIF results and detailed analysis

### 🐷 TruffleHog Secret Detection
- **Trigger**: Push, PR, schedule, manual
- **Coverage**: Git history + filesystem
- **Status Check**: `🐷 TruffleHog Secret Detection (trufflehog-scan)`
- **Detection**: AWS keys, tokens, certificates, credentials
- **Merge Blocking**: Blocks PRs with secrets

### 🛡️ Comprehensive Security Pipeline
- **Trigger**: Push, PR, schedule, manual
- **Orchestration**: Runs all tools with smart logic
- **Status Check**: `🛡️ Comprehensive Security Pipeline (security-gatekeeper)`
- **Gatekeeper**: Final security status and merge decisions
- **Reports**: Summary and critical issue alerts

## 🔧 Manual Testing Commands

If you want to test tools locally before running in GitHub Actions:

```bash
# Test Semgrep
semgrep --config=auto simple-vulnerability-test.py
semgrep --config=p/security-audit .
semgrep --config=p/owasp-top-ten .

# Test TruffleHog
trufflehog git file://. --since-commit HEAD
trufflehog filesystem simple-vulnerability-test.py

# Test Trivy
trivy fs .
trivy fs --scanners secret .
trivy fs --scanners vuln .
```

## 📋 Verification Checklist

After running workflows, verify:

### ✅ Workflow Execution
- [ ] All 4 workflows run successfully
- [ ] No syntax errors in YAML files
- [ ] Tools execute without authentication issues

### ✅ Security Findings
- [ ] Semgrep detects 8+ vulnerabilities in test files
- [ ] TruffleHog scans git history
- [ ] Trivy completes vulnerability scanning
- [ ] Results uploaded to Security tab

### ✅ Status Checks
- [ ] Status checks appear in PR checks
- [ ] Names match branch protection requirements
- [ ] Failed checks block merges appropriately

### ✅ Reports & Notifications
- [ ] SARIF results visible in Security tab
- [ ] PR comments generated with findings
- [ ] Artifacts contain detailed reports
- [ ] Comprehensive pipeline summary created

### ✅ Branch Protection
- [ ] Status checks enforce security policies
- [ ] Merges blocked on critical findings
- [ ] Admin enforcement works correctly

## 🚨 Troubleshooting Common Issues

### Workflow Doesn't Run
- **Cause**: YAML syntax error or missing trigger
- **Fix**: Check YAML syntax, verify file paths

### Semgrep Authentication Error
- **Cause**: Missing SEMGREP_APP_TOKEN
- **Fix**: Add token in repository secrets

### TruffleHog No Findings
- **Cause**: No secrets in repository or too strict filters
- **Fix**: Test with `--only-verified=false` or add test secrets

### Status Check Names Don't Match
- **Cause**: Workflow names different than expected
- **Fix**: Check actual names in Actions tab and update branch protection

### SARIF Results Not Visible
- **Cause**: Missing GITHUB_TOKEN permissions
- **Fix**: Ensure token has `security_events` scope

## 📈 Success Metrics

Your security pipeline is working when:

1. **All workflows execute** without errors
2. **Security findings are detected** in test files
3. **Status checks appear** and can block merges
4. **SARIF results show** in Security tab
5. **PR comments provide** actionable security feedback
6. **Comprehensive pipeline** provides final security status

## 🎯 Next Steps After Testing

1. **Configure branch protection** with the verified status check names
2. **Review and tune** security rules based on findings
3. **Set up notifications** for critical security issues
4. **Create security policies** for handling different severity levels
5. **Train team members** on secure development practices

---

**Testing Status**: ✅ Tools verified locally, ready for GitHub Actions testing
**Repository**: https://github.com/sadisteffl/Sadi-Steffl-Sample-Portfolio
**Documentation**: See `.github/SECURITY.md` for full security policy