# Security Quick Reference Cards

These quick reference cards provide condensed summaries of critical security requirements for developers. Use these as daily checklists and reminders while developing software.

Feedback: Does this include all of the items we talked about in a quick what to do it and what tools to use? 

## 🚨 CRITICAL SECURITY REQUIREMENTS

### 🔐 Secrets Management
**ALWAYS DO:**
- ✅ Use approved secrets management tools (AWS Secrets Manager, Vault)
- ✅ Implement automatic secret rotation
- ✅ Use least-privilege access for secrets

**NEVER DO:**
- ❌ Hardcode secrets in code, config files, or environment variables
- ❌ Commit secrets to version control
- ❌ Share credentials via email or chat

**Tools:** HashiCorp Vault, AWS Secrets Manager, Azure Key Vault

### 🛡️ Input Validation & Output Encoding
**ALWAYS DO:**
- ✅ Validate all input data on server-side
- ✅ Use parameterized queries for database operations
- ✅ Encode output before rendering in browsers
- ✅ Use framework-provided security functions

**NEVER DO:**
- ❌ Trust client-side validation alone
- ❌ Concatenate strings for SQL queries
- ❌ Display raw user input without encoding

**Common Attacks to Prevent:** SQL Injection, XSS, Command Injection

### 🔑 Authentication & Authorization
**ALWAYS DO:**
- ✅ Use company's standard authentication services
- ✅ Implement MFA for privileged operations
- ✅ Enforce authorization checks on every protected resource
- ✅ Follow principle of least privilege

**NEVER DO:**
- ❌ Build custom authentication systems
- ❌ Assume authentication implies authorization
- ❌ Use overly permissive roles (admin, *)

### 📋 Dependency Management
**ALWAYS DO:**
- ✅ Scan dependencies for vulnerabilities
- ✅ Update dependencies regularly
- ✅ Review security advisories for used libraries
- ✅ Use SCA tools integrated in CI/CD

**NEVER DO:**
- ❌ Use libraries with known critical vulnerabilities
- ❌ Ignore dependency update notifications
- ❌ Use untrusted package sources

**Tools:** Snyk, OWASP Dependency-Check, GitHub Dependabot

### 📊 Secure Logging
**ALWAYS DO:**
- ✅ Log authentication successes/failures
- ✅ Log authorization decisions
- ✅ Include relevant context (user ID, timestamp, action)
- ✅ Protect log files from unauthorized access

**NEVER DO:**
- ❌ Log passwords, session tokens, or API keys
- ❌ Log sensitive PII in plain text
- ❌ Store logs with insufficient access controls

## 🏗️ INFRASTRUCTURE SECURITY

### ☁️ Cloud Security (AWS)
**CRITICAL CONTROLS:**
- 🔐 Enable MFA for all IAM users
- 🚫 Block public S3 access
- 🔒 Encrypt EBS volumes and S3 buckets
- 📝 Enable CloudTrail logging
- 🌐 Use VPC with private subnets

**Quick Checks:**
- [ ] IAM users have MFA enabled?
- [ ] S3 buckets block public access?
- [ ] Database instances not publicly accessible?
- [ ] CloudTrail enabled in all regions?

### 🐳 Container Security
**IMAGE SECURITY:**
- ✅ Use minimal base images (distroless, Alpine)
- ✅ Run containers as non-root user
- ✅ Use specific image tags (not latest)
- ✅ Sign and scan all images
- ✅ Multi-stage builds for production images

**RUNTIME SECURITY:**
- ✅ Implement network policies
- ✅ Monitor for anomalous behavior
- ✅ Use secrets management
- ✅ Set resource limits
- ✅ Enable runtime scanning

### 🌐 API Security
**AUTHENTICATION:**
- ✅ Use OAuth 2.0 / OpenID Connect
- ✅ Implement token expiration
- ✅ Use HTTPS/TLS for all communications
- ✅ Validate all input data

**AUTHORIZATION:**
- ✅ Implement scope-based access control
- ✅ Rate limiting and throttling
- ✅ API key management
- ✅ Resource-based permissions

## 🚨 IMMEDIATE ACTION ITEMS

### Before Committing Code
1. [ ] Review code for security vulnerabilities
2. [ ] Ensure no hardcoded secrets
3. [ ] Verify input validation is implemented
4. [ ] Check error handling doesn't leak information
5. [ ] Run security scanning tools

### Before Deployment
1. [ ] Run automated security tests
2. [ ] Scan dependencies for vulnerabilities
3. [ ] Verify configurations are secure
4. [ ] Check logging doesn't expose sensitive data
5. [ ] Review access permissions

### Security Incident Response
1. 🚨 **IMMEDIATELY** report suspected incidents to Security Team
2. 📞 Contact: security-team@company.com or Emergency: +1-XXX-XXX-XXXX
3. 📝 Document everything you observe
4. 🚫 Don't attempt to investigate alone
5. 🔄 Follow documented incident response procedures

## 🛠️ SECURITY TOOLS INTEGRATION

### Development Environment
- **IDE Security:** Enable security extensions
- **Local Scanning:** Run SAST scans locally
- **Secrets Detection:** Use git-secrets or similar
- **Container Security:** Scan images locally

### CI/CD Pipeline
- **SAST:** SonarQube, Veracode, Checkmarx
- **SCA:** Snyk, OWASP Dependency-Check
- **Container Scanning:** Trivy, Clair, Anchore
- **DAST:** OWASP ZAP, Burp Suite
- **IaC Security:** Checkov, tfsec

### Monitoring & Alerting
- **Security Monitoring:** SIEM integration
- **Vulnerability Alerts:** Automated notifications
- **Compliance Reporting:** Regular security reports
- **Performance Impact:** Monitor security tool overhead

## 📚 RESOURCES AND CONTACTS

### Security Team Contact
- **Email:** security-team@company.com
- **Slack:** #security-team
- **Office Hours:** Tuesdays & Thursdays 2-4 PM
- **Emergency:** 24/7 hotline available

### Documentation
- **Full Standards:** [Developer Documentation](README.md)
- **Glossary:** [Security Terms](Glossary.md)
- **Compliance:** ISO 27001 & SOC 2 requirements
- **Training:** Security awareness platform

### Reporting Security Issues
- **Vulnerability Reporting:** security@company.com
- **Bug Bounty:** [Company Bug Bounty Program]
- **Incident Response:** [Incident Response Procedures]
- **Questions:** #security-help Slack channel

## ✅ DAILY SECURITY CHECKLIST

### ☐ Start of Day
- Review security notifications and alerts
- Check for new vulnerability advisories
- Verify no unusual account activities

### ☐ During Development
- Follow secure coding standards
- Use secrets management tools
- Validate all input data
- Implement proper error handling

### ☐ Before Commit
- Run security scanning tools
- Review code for security issues
- Ensure no sensitive data in code
- Verify dependencies are secure

### ☐ End of Day
- Review security logs and alerts
- Update any outdated dependencies
- Document any security-related work
- Report any security concerns

---

**Remember:** Security is everyone's responsibility. When in doubt, ask the Security Team for guidance. It's better to ask a question than to introduce a vulnerability.

**Last Updated:** [Current Date]
**Maintained By:** Security Team