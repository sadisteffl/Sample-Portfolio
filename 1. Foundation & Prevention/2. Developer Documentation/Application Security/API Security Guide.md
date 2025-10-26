# API Security Guide for Developers

This guide helps you build secure APIs from day one. Instead of just listing requirements, we'll show you **how** to implement common security patterns and **why** each control matters.

## What You'll Learn

- How to design secure API architectures
- Practical authentication and authorization patterns
- Input validation and output encoding techniques
- Rate limiting and monitoring strategies
- Common API security pitfalls and how to avoid them

---

## API Security by Design

### Start with Security, Don't Add It Later

Security should be a primary consideration when designing your API, not something you bolt on at the end.

**Why this matters**: It's much easier and cheaper to design security into your API from the start than to try and add it later when you're dealing with production issues.

### Core Security Principles

#### 1. Least Privilege
Every API endpoint and user should have only the permissions they absolutely need.

```python
# ❌ BAD: Overly permissive endpoint
@app.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
@auth_required
def users():
    # Can read, create, update, and delete all users
    pass

# ✅ GOOD: Specific permissions per endpoint
@app.route('/api/users', methods=['GET'])
@auth_required
@permission_required('users:read')
def get_users():
    # Can only read users
    pass

@app.route('/api/users', methods=['POST'])
@auth_required
@permission_required('users:create')
def create_user():
    # Can only create users
    pass
```

#### 2. Stateless Design
Design your APIs to be stateless where possible. Store session state in tokens, not on your servers.

```python
# ❌ BAD: Server-side session state
session_storage = {}

@app.route('/api/data')
def get_data():
    user_id = session_storage.get(request.remote_addr)
    return data_for_user(user_id)

# ✅ GOOD: JWT tokens with claims
@app.route('/api/data')
@auth_required
def get_data():
    user_id = request.jwt_claims.get('sub')
    return data_for_user(user_id)
```

#### 3. Minimal Data Exposure
Only return the data that's absolutely necessary for each request.

```python
# ❌ BAD: Returning everything
@app.route('/api/users/123')
def get_user():
    user = get_user_from_db(123)
    return jsonify({
        'id': user.id,
        'name': user.name,
        'email': user.email,  # PII exposure
        'ssn': user.ssn,        # Sensitive PII
        'salary': user.salary,  # Confidential data
        'address': user.address, # PII
        'phone': user.phone,   # PII
    })

# ✅ GOOD: Only necessary data
@app.route('/api/users/123')
def get_user():
    user = get_user_from_db(123)
    # Check if requester has permission to see each field
    response = {'id': user.id}

    if has_permission(request.user, 'users:read:name'):
        response['name'] = user.name

    if has_permission(request.user, 'users:read:email'):
        response['email'] = user.email

    return jsonify(response)
```

---

## Authentication & Authorization

### Choose the Right Authentication Method

#### For Public APIs
Use API keys with proper management.

```python
# ✅ GOOD: API key authentication
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

@app.middleware("http")
async def api_key_middleware(request: Request):
    api_key = request.headers.get("X-API-Key")
    if not api_key or not validate_api_key(api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return await call_next(request)

def validate_api_key(api_key: str) -> bool:
    # Check against database or API management service
    return api_key in valid_api_keys
```

#### For User-Facing APIs
Use OAuth 2.0 or OpenID Connect.

```python
# ✅ GOOD: OAuth 2.0 with JWT
from fastapi import Depends, HTTPBearer
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(
    token: str = Depends(oauth2_scheme)
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=["HS256"]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        return get_user(user_id)
    except JWTError:
        raise credentials_exception
```

### Implement Fine-Grained Authorization

Use role-based or attribute-based access control.

```python
# ✅ GOOD: Role-based access control
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"
    READONLY = "readonly"

class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"

def check_permission(user: User, resource: str, permission: Permission) -> bool:
    # Check user's role against resource permissions
    role_permissions = get_role_permissions(user.role)
    resource_permissions = get_resource_permissions(resource)

    return (permission in role_permissions and
            resource_permissions.get(permission, False))

@app.route('/api/reports/<report_id>')
@auth_required
def get_report(report_id: str):
    user = get_current_user()

    if not check_permission(user, f"report:{report_id}", Permission.READ):
        raise HTTPException(status_code=403, detail="Access denied")

    return get_report(report_id)
```

---

## Input Validation & Output Encoding

### Never Trust Input

Validate all input data, even if it comes from "trusted" sources.

```python
# ❌ BAD: No input validation
@app.route('/api/users', methods=['POST'])
def create_user():
    user_data = request.json  # Direct use without validation
    return create_user_in_db(user_data)

# ✅ GOOD: Comprehensive validation
from pydantic import BaseModel, EmailStr, validator
from typing import Optional

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    age: int
    role: UserRole

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if not v.isalnum():
            raise ValueError("Username must be alphanumeric")
        return v

    @validator('age')
    def validate_age(cls, v):
        if v < 18 or v > 120:
            raise ValueError("Age must be between 18 and 120")
        return v

@app.route('/api/users', methods=['POST'])
async def create_user(user_data: UserCreate):
    # Pydantic automatically validates the input
    return create_user_in_db(user_data.dict())
```

### Prevent Injection Attacks

Use parameterized queries and proper encoding.

```python
# ❌ BAD: SQL injection vulnerability
@app.route('/api/users/<int:user_id>')
def get_user_posts(user_id: int):
    query = f"SELECT * FROM posts WHERE user_id = {user_id}"
    results = db.execute(query)
    return jsonify(results)

# ✅ GOOD: Parameterized queries
@app.route('/api/users/<int:user_id>')
def get_user_posts(user_id: int):
    query = "SELECT * FROM posts WHERE user_id = ?"
    results = db.execute(query, (user_id,))
    return jsonify(results)

# ❌ BAD: XSS in output
@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    results = search_database(query)
    return f"<div>Search results for {query}: {results}</div>"

# ✅ GOOD: Proper output encoding
from markupsafe import escape

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    results = search_database(query)
    return {
        'query': query,
        'results': results,
        'safe_output': escape(f"Search results for {query}")
    }
```

---

## Rate Limiting & Throttling

### Protect Your APIs from Abuse

Implement rate limiting to prevent abuse and ensure fair usage.

```python
# ✅ GOOD: Rate limiting middleware
from fastapi import Request, HTTPException
from collections import defaultdict
import time
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 3600):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        now = time.time()
        # Remove old requests outside the window
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if now - req_time < self.window_seconds
        ]

        # Check if under the limit
        if len(self.requests[client_id]) < self.max_requests:
            self.requests[client_id].append(now)
            return True
        return False

# Global rate limiter instance
rate_limiter = RateLimiter(max_requests=100, window_seconds=3600)  # 100 requests per hour

@app.middleware("http")
async def rate_limit_middleware(request: Request):
    # Use API key or IP address as client identifier
    client_id = request.headers.get("X-API-Key") or request.client.host

    if not rate_limiter.is_allowed(client_id):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": "3600"}
        )
    return await call_next(request)

# Endpoint-specific rate limiting
endpoint_rate_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 requests per minute

@app.route('/api/expensive-operation')
@auth_required
def expensive_operation():
    client_id = request.headers.get("X-API-Key") or request.client.host

    if not endpoint_rate_limiter.is_allowed(client_id):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this endpoint",
            headers={"Retry-After": "60"}
        )

    # Perform expensive operation
    return process_expensive_request()
```

---

## Monitoring & Logging

### Log Security Events

Log authentication attempts, authorization decisions, and potential security issues.

```python
# ✅ GOOD: Security logging
import logging
from datetime import datetime
import json

# Configure security logging
security_logger = logging.getLogger('api.security')
security_logger.setLevel(logging.INFO)

# Create a security log handler
handler = logging.FileHandler('security.log')
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s - %(ip)s'
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    ip_address = request.client.host

    # Log authentication attempt
    security_logger.info(
        f"Login attempt - Username: {username}, IP: {ip_address}",
        extra={'ip': ip_address, 'username': username}
    )

    if authenticate_user(username, password):
        security_logger.info(
            f"Login successful - Username: {username}, IP: {ip_address}",
            extra={'ip': ip_address, 'username': username, 'success': True}
        )
        return {"token": generate_token(username)}
    else:
        security_logger.warning(
            f"Login failed - Username: {username}, IP: {ip_address}",
            extra={'ip': ip_address, 'username': username, 'success': False}
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.route('/api/protected')
@auth_required
@permission_required('admin:read')
def protected_data():
    user = get_current_user()
    ip_address = request.client.host

    security_logger.info(
        f"Protected data access - User: {user.username}, IP: {ip_address}",
        extra={'ip': ip_address, 'user': user.username, 'resource': 'protected_data'}
    )

    return get_protected_data()
```

### Implement API Health Checks

```python
# ✅ GOOD: Health check endpoint
@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'database': 'connected' if check_database() else 'disconnected',
        'cache': 'connected' if check_cache() else 'disconnected'
    }
```

---

## Common API Security Pitfalls

### 1. Hardcoded Secrets

```python
# ❌ BAD: Hardcoded API key
API_KEY = "sk-1234567890abcdef1234567890abcdef"

def call_external_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    # Make API call

# ✅ GOOD: Environment variables
import os

API_KEY = os.getenv("EXTERNAL_API_KEY")

def call_external_api():
    if not API_KEY:
        raise ValueError("API key not configured")

    headers = {"Authorization": f"Bearer {API_KEY}"}
    # Make API call
```

### 2. Insecure Token Generation

```python
# ❌ BAD: Predictable JWT tokens
import jwt

def generate_token(user_id: str):
    payload = {"user_id": user_id}
    return jwt.encode(payload, "secret", algorithm="HS256")

# ✅ GOOD: Secure JWT with expiration
import jwt
from datetime import datetime, timedelta
import secrets

def generate_token(user_id: str):
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "jti": secrets.token_hex(16)  # Unique token identifier
    }

    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def validate_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        # Check expiration
        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            raise HTTPException(status_code=401, detail="Token expired")

        # Check if token is revoked
        if is_token_revoked(payload.get("jti")):
            raise HTTPException(status_code=401, detail="Token revoked")

        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### 3. Missing CORS Configuration

```python
# ❌ BAD: No CORS configuration (default allows all origins)
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# ✅ GOOD: Restrictive CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com", "https://www.yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=6000,
)
```

### 4. Exposing Sensitive Data

```python
# ❌ BAD: Debug mode in production
app = FastAPI(debug=True)  # Never do this in production!

# ✅ GOOD: Configuration-based debug mode
import os

DEBUG_MODE = os.getenv("DEBUG", "false").lower() == "true"

app = FastAPI(debug=DEBUG_MODE)

if DEBUG_MODE:
    print("⚠️  WARNING: Debug mode enabled - do not use in production!")
```

---

## API Testing Checklist

### Before Deployment

- [ ] **Input Validation**: All input is validated and sanitized
- [ ] **Authentication**: Strong authentication for all protected endpoints
- [ ] **Authorization**: Proper permissions checked for each operation
- [ ] **Rate Limiting**: Protection against abuse and DoS
- [ ] **Security Logging**: All security events are logged
- [ ] **Error Handling**: Errors don't expose sensitive information
- [ ] **CORS Configuration**: Proper CORS settings for your domain
- [ ] **HTTPS Enforcement**: All endpoints use HTTPS
- [ ] **Token Security**: JWT tokens are properly signed and validated
- [ ] **Database Security**: All queries use parameterized statements

### Regular Security Reviews

- [ ] **Audit Logs**: Regular review of security logs
- [ ] **Penetration Testing**: Regular security testing of endpoints
- [ ] **Dependency Updates**: Keep dependencies updated and secure
- [ ] **Security Headers**: Implement security headers (HSTS, CSP, etc.)
- [ ] **API Documentation**: Keep API docs current with security requirements

---

## Security Tools for API Development

### Static Analysis
- **Semgrep**: Static analysis to find security vulnerabilities in code
- **Bandit**: Security linter for Python code
- **CodeQL**: Semantic code analysis for security issues

### Dynamic Testing
- **OWASP ZAP**: Web application security scanner
- **Burp Suite**: Web vulnerability scanner
- **Postman**: API testing with security focus

### API-Specific Tools
- **OpenAPI Validator**: Validate OpenAPI specifications
- **Schemathesis**: Property-based testing for APIs
- **42Crunch**: API security testing tool

---

## Compliance Framework Mappings

### ISO 27001:2022 Annex A Controls

| ISO Control | API Implementation | What This Means for Your Code |
| :--- | :--- | :--- |
| **A.9.2 - Access Control** | Implement API authentication and authorization | Every endpoint must validate user identity and permissions before processing requests |
| **A.9.4 - System Use Monitoring** | Log and monitor API usage patterns | Track authentication attempts, access decisions, and unusual usage patterns |
| **A.12.6 - Technical Vulnerability Management** | Regular API security testing | Run automated scans and conduct manual penetration testing on APIs |
| **A.14.2 - Secure Development** | Security in API development lifecycle | Include security reviews, threat modeling, and secure coding practices |
| **A.14.3 - Test Data** | Secure test data management | Never use production data in API testing environments |

### SOC 2 Trust Services Criteria

| SOC 2 Criteria | API Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Security (Common Criteria)** | Comprehensive API security controls | Implement all critical and high-severity security controls |
| **Availability** | High availability and resilience | Design APIs with proper error handling and fallback mechanisms |
| **Confidentiality** | Protect sensitive data in API communications | Encrypt data in transit and implement proper data filtering |
| **Processing Integrity** | Ensure data integrity and processing accuracy | Validate inputs, implement proper error handling, and log transactions |

### NIST Cybersecurity Framework

| NIST Function | API Security Controls | Practical Implementation |
| :--- | :--- | :--- |
| **Identify** | API asset management and risk assessment | Document all APIs, classify data sensitivity, conduct threat modeling |
| **Protect** | Security controls and safeguards | Implement authentication, authorization, encryption, and input validation |
| **Detect** | Security monitoring and anomaly detection | Set up logging, monitoring, and alerting for security events |
| **Respond** | Incident response and recovery | Have incident response procedures specific to API security incidents |
| **Recover** | Recovery planning and improvements | Document lessons learned and improve API security posture |

### OWASP API Security Top 10 Mapping

| OWASP API Risk | Prevention Strategies | Code Examples |
| :--- | :--- | :--- |
| **API1: Broken Object Level Authorization** | Implement proper authorization checks | Validate user permissions for each resource access |
| **API2: Broken User Authentication** | Strong authentication mechanisms | Use JWT, OAuth 2.0, or multi-factor authentication |
| **API3: Excessive Data Exposure** | Filter sensitive data | Return only necessary fields, implement data masking |
| **API4: Lack of Resources & Rate Limiting** | Implement rate limiting | Use token bucket or sliding window algorithms |
| **API5: Broken Function Level Authorization** | Role-based access control | Check permissions before executing sensitive operations |

### PCI DSS Requirements (for payment APIs)

| PCI Requirement | API Implementation | What Developers Must Do |
| :--- | :--- | :--- |
| **Requirement 3** | Protect cardholder data | Encrypt payment data, implement tokenization |
| **Requirement 4** | Secure transmission | Use TLS 1.2+ for all payment API communications |
| **Requirement 6** | Secure development | Follow secure coding practices, conduct security testing |
| **Requirement 7** | Access control | Implement strong authentication and authorization |
| **Requirement 8** | Authentication methods | Use multi-factor authentication for administrative access |

### GDPR Considerations

| GDPR Principle | API Security Implementation | Developer Actions |
| :--- | :--- | :--- |
| **Data Protection by Design** | Security controls built into API design | Include privacy considerations in API architecture |
| **Data Minimization** | Return only necessary data | Implement field filtering and data masking |
| **Accountability** | Demonstrate compliance | Maintain security logs, audit trails, and documentation |
| **Security of Processing** | Appropriate technical measures | Implement encryption, access controls, and monitoring |

## Getting Help

### Security Team Contact
- **Slack**: #api-security
- **Email**: api-security@company.com
- **Emergency**: security-emergency@company.com

### Common Issues
- **Authentication problems**: Contact security team
- **API key issues**: Use API management portal
- **Rate limiting**: Request limits review
- **Security vulnerabilities**: Report immediately

---

**Last Updated**: 2024-10-24
**Version**: 1.0
**Next Review**: 2025-01-24
**Maintained By**: API Security Team