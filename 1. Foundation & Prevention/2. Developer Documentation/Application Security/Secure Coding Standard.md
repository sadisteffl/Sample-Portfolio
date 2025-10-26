# Secure Coding Standard for Developers

Engineers are the first line of defense for their security. Writing secure code is not a separate task - it is a fundamental part of writing high-quality code.

This document provides the essential security standards that all developers are expected to follow. Adhering to these guidelines helps us:

1. **Protect Customers and Data**: Preventing breaches is the most critical responsibility
2. **Build Resilient Products**: Secure applications are more robust and less prone to unexpected failures
3. **Maintain Compliance**: The ability to meet standards like SOC 2 and ISO 27001 depends directly on the security of the code you write
4. **Increase Velocity**: Finding and fixing security flaws early in the development lifecycle is exponentially cheaper and faster than fixing them after a breach

---

## Core Security Principles

### 1. Principle of Least Privilege
Grant services and users only the permissions they absolutely need to perform their function. Never use overly permissive roles (e.g., admin, `*`).

**Why this matters**: If an account is compromised, the attacker only has access to what that specific account needs, not the entire system.

### 2. Defense in Depth
Don't rely on a single security control. Layer defenses so that if one fails, others are in place to stop an attack.

**Why this matters**: Multiple layers make it much harder for attackers to succeed, and they provide time to detect and respond to attacks.

### 3. Never Trust User Input
Treat all data received from a user or another service as potentially malicious.

**Why this matters**: This mindset prevents injection attacks and ensures you always validate and sanitize external data.

---

## Essential Security Standards

### 1. Secrets Management

**❌ NEVER** hardcode secrets (API keys, passwords, database credentials, tokens) in your code, configuration files, or environment variables.

```python
# BAD - Hardcoded secret
api_key = "sk-1234567890abcdef1234567890abcdef"
db_password = "supersecretpassword123"
```

**✅ ALWAYS** use the company's approved secrets management tool (AWS Secrets Manager, HashiCorp Vault) to store and retrieve all secrets programmatically.

```python
# GOOD - Environment variables
import os
api_key = os.getenv("API_KEY")
db_password = os.getenv("DB_PASSWORD")

# GOOD - AWS Secrets Manager
import boto3
secrets_client = boto3.client('secretsmanager')
secret = secrets_client.get_secret_value(SecretId='my-app/credentials')
```

**Relevant Compliance**: SOC 2: CC6.1; ISO 27001: A.9.4.1

### 2. Input Validation and Output Encoding

**✅ ALWAYS** validate all incoming data for type, length, format, and range on the server-side.

```python
# GOOD - Input validation
def validate_user_id(user_id):
    if not isinstance(user_id, int):
        raise ValueError("User ID must be an integer")
    if user_id < 1 or user_id > 1000000:
        raise ValueError("User ID out of valid range")
    return user_id
```

**✅ ALWAYS** use parameterized queries or prepared statements to prevent SQL injection. Never construct database queries by concatenating strings.

```python
# BAD - SQL injection vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# GOOD - Parameterized query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

**✅ ALWAYS** properly encode all data before rendering it in a user's browser to prevent Cross-Site Scripting (XSS). Use the encoding functions provided by your framework.

```python
# BAD - XSS vulnerable
def render_comment(comment):
    return f"<div>User said: {comment}</div>"

# GOOD - Properly encoded
from markupsafe import escape
def render_comment(comment):
    return f"<div>User said: {escape(comment)}</div>"
```

**Relevant Compliance**: SOC 2: CC7.2; ISO 27001: A.14.2.5

### 3. Dependency Management

**✅ ALWAYS** use the Software Composition Analysis (SCA) tool integrated into the CI/CD pipeline to scan for vulnerabilities in your third-party libraries.

**❌ NEVER** use libraries with known critical or high-severity vulnerabilities.

**✅ ALWAYS** keep dependencies up to date and follow the company's policy for patching vulnerabilities within the required timeframe.

```bash
# Regular updates
npm audit fix
pip install --upgrade -r requirements.txt
go get -u ./...
```

**Relevant Compliance**: SOC 2: CC9.2; ISO 27001: A.12.6.1

### 4. Authentication and Authorization

**✅ ALWAYS** use the company's standard authentication services. Do not build your own authentication.

**✅ ALWAYS** enforce authorization checks on every request for a protected resource, ensuring the authenticated user has the explicit right to perform that action.

```python
# GOOD - Authorization check
@app.route('/admin/users')
@require_auth
@require_permission('admin:users')
def list_users():
    # Your code here
    pass
```

**Relevant Compliance**: SOC 2: CC6.1, CC6.3; ISO 27001: A.9.2, A.9.1.2

### 5. Secure Logging

**✅ ALWAYS** log all security-relevant events, such as successful/failed logins, access control decisions, and significant transactions.

**❌ NEVER** log sensitive data, such as passwords, session tokens, API keys, or personally identifiable information (PII), in plain text.

```python
# GOOD - Secure logging
import logging

def log_login_attempt(username, success, ip_address):
    logging.info(f"Login attempt - User: {username}, Success: {success}, IP: {ip_address}")

# BAD - Logging sensitive data
def log_login_attempt(username, password, success):
    logging.info(f"Login attempt - User: {username}, Password: {password}") # NEVER DO THIS
```

**Relevant Compliance**: SOC 2: CC7.3; ISO 27001: A.12.4.1

---

## Language-Specific Guidelines

### Python Security

```python
# ✅ Use secure file operations
import os
import tempfile

# Create files with secure permissions
with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
    f.write(sensitive_data)
    os.chmod(f.name, 0o600)  # Only owner can read/write
```

### JavaScript Security

```javascript
// ✅ Use secure cookie settings
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // Not accessible via JavaScript
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ✅ Use Helmet.js for security headers
const helmet = require('helmet');
app.use(helmet());
```

### Go Security

```go
// ✅ Use secure random number generation
import "crypto/rand"

func generateSecureToken() (string, error) {
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

---

## Common Security Mistakes to Avoid

### 1. Hardcoded Configuration
```python
# ❌ BAD
DATABASE_URL = "postgresql://user:pass@localhost/db"

# ✅ GOOD
DATABASE_URL = os.getenv("DATABASE_URL")
```

### 2. Weak Cryptography
```python
# ❌ BAD - MD5 is broken
hashed_password = hashlib.md5(password.encode()).hexdigest()

# ✅ GOOD - Use strong hashing
hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 3. Insecure File Handling
```python
# ❌ BAD - Path traversal vulnerability
def read_file(filename):
    return open(f"/var/www/{filename}").read()

# ✅ GOOD - Validate and sanitize paths
def read_file(filename):
    safe_path = os.path.join("/var/www", os.path.basename(filename))
    if not safe_path.startswith("/var/www/"):
        raise ValueError("Invalid file path")
    return open(safe_path).read()
```

---

## Security Tools and Resources

### Our Security Stack
- **Static Analysis (SAST)**: Semgrep, SonarQube
- **Dependency Scanning (SCA)**: Snyk, Dependabot
- **Secret Detection**: TruffleHog, GitGuardian
- **Container Security**: Trivy, Docker Security Scanning
- **Infrastructure Security**: Checkov, Terraform Security

### Getting Help
- **Security Team**: security@company.com
- **Slack**: #security-help
- **Security Review Process**: Create a PR with the `security-review` label

### Training Resources
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Secure Coding Checklist**: [Quick Reference Cards](Quick%20Reference%20Cards.md)
- **Security Glossary**: [Glossary.md](Glossary.md)

---

## Our Commitment to You

Security is committed to making it easy to write secure code. Security will provide you with:

1. **Tools**: Integrated security testing in your IDE and CI/CD pipeline
2. **Training**: Regular security workshops and office hours
3. **Support**: Quick response to security questions and code reviews
4. **Documentation**: Clear, actionable security standards and examples

### What Security Provides:
- **Automated Security Testing**: Your code is automatically scanned for vulnerabilities
- **Security PR Reviews**: Security team reviews PRs for security issues
- **Tooling Setup**: Help setting up local security tools
- **Incident Response**: 24/7 support for security incidents

### What We Need From You:
- **Write secure code from the start** - it's easier than fixing it later
- **Run security tools locally** before committing
- **Ask questions** when you're unsure about security requirements
- **Report security issues** immediately if you find them
- **Participate in security training** and stay current on threats

---

## Checklist for Every Feature

Before merging any code, ask yourself:

- [ ] Have I validated all input data?
- [ ] Are all database queries parameterized?
- [ ] Are all secrets properly managed (not hardcoded)?
- [ ] Have I checked for XSS vulnerabilities?
- [ ] Are all authentication and authorization checks in place?
- [ ] Am I logging security events without sensitive data?
- [ ] Have I run the security tools locally?
- [ ] Are all dependencies up to date and free of known vulnerabilities?
- [ ] Have I tested for common security issues?

---

## Compliance Framework Mappings

### ISO 27001:2022 Annex A Controls

| ISO Control | Secure Coding Implementation | What This Means for Your Code |
| :--- | :--- | :--- |
| **A.8.16 - Secure Development Life Cycle** | Security in software development | Include security requirements, threat modeling, and security testing |
| **A.8.21 - Secure Coding** | Secure coding practices | Follow secure coding standards and conduct code reviews |
| **A.8.25 - Secure System Engineering** | Security in system design | Design security controls into system architecture |
| **A.14.2 - Secure Development** | Development security practices | Implement secure coding, testing, and deployment practices |
| **A.14.3 - Test Data** | Secure test data management | Use synthetic or anonymized data for testing |

### SOC 2 Trust Services Criteria

| SOC 2 Criteria | Secure Coding Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Security (Common Criteria)** | Comprehensive secure coding practices | Implement input validation, output encoding, and access controls |
| **Availability** | Resilient software development | Design for error handling, retry logic, and graceful degradation |
| **Confidentiality** | Data protection in code | Implement encryption, data masking, and secure data handling |
| **Processing Integrity** | Data integrity and validation | Implement input validation, checksums, and audit logging |

### NIST Cybersecurity Framework

| NIST Function | Secure Coding Controls | Practical Implementation |
| :--- | :--- | :--- |
| **Identify** | Software asset and risk management | Document software components, conduct threat modeling |
| **Protect** | Secure development practices | Implement secure coding, dependency management, and testing |
| **Detect** | Security testing and monitoring | Conduct SAST, DAST, and implement security monitoring |
| **Respond** | Incident response for code issues | Have procedures for addressing security vulnerabilities |
| **Recover** | Recovery and improvement | Patch management and post-incident improvements |

### OWASP Secure Coding Practices

| OWASP Practice | Implementation | What Developers Must Do |
| :--- | :--- | :--- |
| **Input Validation** | Validate all input data | Implement whitelist validation and type checking |
| **Output Encoding** | Encode output data | Use context-appropriate encoding (HTML, URL, JSON) |
| **Authentication & Session Management** | Secure authentication | Use strong authentication and secure session handling |
| **Communication Security** | Secure data transmission | Use TLS 1.2+ and secure API communication |
| **Data Protection** | Sensitive data handling | Encrypt sensitive data and implement proper key management |

### Common Weakness Enumeration (CWE) Mappings

| CWE Category | Secure Coding Control | Code Examples |
| :--- | :--- | :--- |
| **CWE-20: Input Validation** | Input validation and sanitization | Parameterized queries, input validation |
| **CWE-79: XSS** | Output encoding and CSP | HTML encoding, Content Security Policy |
| **CWE-89: SQL Injection** | Safe database access | Parameterized queries, ORM usage |
| **CWE-22: Path Traversal** | File access validation | Validate file paths, use whitelist |
| **CWE-352: CSRF** | CSRF protection | Use anti-CSRF tokens, same-site cookies |

### PCI DSS Requirements (for payment applications)

| PCI Requirement | Secure Coding Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Requirement 3** | Protect cardholder data | Implement tokenization, encryption, data masking |
| **Requirement 4** | Secure transmission | Use TLS for all network communications |
| **Requirement 6** | Secure development | Follow secure coding practices, regular security testing |
| **Requirement 7** | Access control | Implement principle of least privilege in code |
| **Requirement 8** | Authentication methods | Implement strong authentication mechanisms |

### GDPR Considerations

| GDPR Principle | Secure Coding Implementation | Developer Actions |
| :--- | :--- | :--- |
| **Data Protection by Design** | Security in software architecture | Include privacy controls in system design |
| **Data Minimization** | Limit data collection and processing | Store only necessary data and implement retention policies |
| **Accountability** | Demonstrate compliance | Maintain security documentation and audit trails |
| **Security of Processing** | Appropriate technical measures | Implement encryption, access controls, and logging |

### Industry Standards Mapping

| Standard | Key Requirements | Implementation Examples |
| :--- | :--- | :--- |
| **SANS Top 25** | Critical security weaknesses | Address most common and critical software weaknesses |
| **CERT Secure Coding** | Secure coding standards | Language-specific secure coding guidelines |
| **CWE/SANS Top 25** | Most dangerous software errors | Prioritize fixing of critical vulnerabilities |

---

**Document Version**: 2.0
**Last Updated**: 2024-10-24
**Maintained By**: Security Team
**Review Frequency**: Quarterly
**Next Review**: 2025-01-24

---

*Security is a team sport. When you write secure code, you're not just following rules - you're protecting our customers, our company, and your fellow engineers. Thank you for taking security seriously.*