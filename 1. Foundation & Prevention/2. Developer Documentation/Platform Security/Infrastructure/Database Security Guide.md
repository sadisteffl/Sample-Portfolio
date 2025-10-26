# Database Security Guide for Developers

This practical guide helps you build secure database applications and manage database access properly. Instead of abstract requirements, you'll find **how** to implement secure database patterns and **why** each control matters for your applications.

## What You'll Learn

- How to design secure database schemas
- Proper authentication and authorization patterns
- Encryption and data protection techniques
- Common database security pitfalls and how to avoid them
- Practical examples for SQL and NoSQL databases

---

## Database Security Fundamentals

### Principle 1: Least Privilege Access
Grant the minimum necessary permissions to every database user and application.

**Why this matters**: If a database account is compromised, the attacker only has access to what that specific account needs, not your entire database.

### Principle 2: Defense in Depth
Layer security controls at multiple levels (network, database, application, and data).

**Why this matters**: Multiple layers make it much harder for attackers to succeed and provide time to detect and respond to breaches.

### Principle 3: Encrypt Everything
Encrypt data at rest, in transit, and, when necessary, at the column level.

**Why this matters**: Encryption protects your data even if other security controls fail.

---

## Secure Database Design Patterns

### 1. Use Separate Environments

Never use production databases for development, testing, or staging.

```python
# ✅ GOOD: Environment-specific database connections
import os
from typing import Dict, Any

def get_database_config() -> Dict[str, Any]:
    env = os.getenv("ENVIRONMENT", "development")

    configs = {
        "development": {
            "host": "localhost",
            "database": "myapp_dev",
            "user": "dev_user",
            "password": os.getenv("DEV_DB_PASSWORD"),
            "port": 5432
        },
        "staging": {
            "host": "staging-db.company.com",
            "database": "myapp_staging",
            "user": "staging_user",
            "password": os.getenv("STAGING_DB_PASSWORD"),
            "port": 5432
        },
        "production": {
            "host": "prod-db.company.com",
            "database": "myapp_production",
            "user": "app_user",
            "password": os.getenv("PROD_DB_PASSWORD"),
            "port": 5432,
            "sslmode": "require"
        }
    }

    return configs[env]

# Usage
db_config = get_database_config()
connection = create_connection(db_config)
```

### 2. Implement Role-Based Access

Create specific database roles for different application functions.

```sql
-- ✅ GOOD: Specific database roles for PostgreSQL
-- Read-only role for reporting applications
CREATE ROLE read_only_app;
GRANT CONNECT ON DATABASE myapp TO read_only_app;
GRANT USAGE ON SCHEMA public TO read_only_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO read_only_app;

-- Read-write role for main application
CREATE ROLE app_user;
GRANT CONNECT ON DATABASE myapp TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;

-- Admin role for database maintenance
CREATE ROLE db_admin;
GRANT ALL PRIVILEGES ON DATABASE myapp TO db_admin;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO db_admin;

-- Assign users to roles
CREATE USER reporting_app WITH PASSWORD 'secure_password';
GRANT read_only_app TO reporting_app;

CREATE USER main_app WITH PASSWORD 'another_secure_password';
GRANT app_user TO main_app;
```

### 3. Design Secure Table Structures

Implement table-level and column-level security from the start.

```sql
-- ✅ GOOD: Secure table design with proper constraints
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- Never store plain text passwords
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    phone_number VARCHAR(20),  -- Consider if this PII is really needed
    ssn VARCHAR(11) ENCRYPTED WITH COLUMN_ENCRYPTION_KEY,  -- Column-level encryption
    -- Add constraints
    CONSTRAINT users_username_length CHECK (LENGTH(username) >= 3),
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Create views for different user roles
CREATE VIEW public_users AS
SELECT
    id,
    username,
    created_at,
    is_active,
    last_login
FROM users;

CREATE VIEW support_users AS
SELECT
    id,
    username,
    email,
    phone_number,  -- Support team needs contact info
    created_at,
    is_active,
    last_login
FROM users;

-- Grant different permissions on views
GRANT SELECT ON public_users TO read_only_app;
GRANT SELECT ON support_users TO support_team_app;
GRANT SELECT ON users TO db_admin;
```

---

## Authentication & Authorization

### Secure Database Connections

Always use secure connections with proper authentication.

```python
# ✅ GOOD: Secure database connection with SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import ssl

# SSL context for secure connections
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Database URL with SSL
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "sslcontext": ssl_context,
        "sslmode": "require"
    },
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,   # Recycle connections every hour
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
```

### Application-Level Authorization

Don't rely solely on database permissions. Implement authorization in your application.

```python
# ✅ GOOD: Application-level authorization with database
from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

def check_user_permission(db: Session, user_id: int, resource: str, action: str) -> bool:
    """Check if user has permission to perform action on resource"""
    query = text("""
        SELECT COUNT(*)
        FROM user_permissions up
        JOIN permissions p ON up.permission_id = p.id
        WHERE up.user_id = :user_id
        AND p.resource = :resource
        AND p.action = :action
    """)

    result = db.execute(query, {
        "user_id": user_id,
        "resource": resource,
        "action": action
    })

    return result.scalar() > 0

@app.get("/api/users/{user_id}")
def get_user(
    user_id: int,
    current_user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db_session)
):
    # Check if current user can read this user's data
    if user_id != current_user_id:  # Can only read own data
        if not check_user_permission(db, current_user_id, "users", "read_all"):
            raise HTTPException(status_code=403, detail="Access denied")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user
```

---

## Data Protection & Encryption

### Encryption at Rest

Use database encryption features to protect data stored on disk.

```sql
-- ✅ GOOD: Enable Transparent Data Encryption (TDE) for SQL Server
USE master;
GO
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!';
GO

USE myapp;
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE myapp_cert;
GO

ALTER DATABASE myapp SET ENCRYPTION ON;
GO

-- ✅ GOOD: Enable TDE for PostgreSQL (requires EnterpriseDB or similar)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create encrypted columns
CREATE TABLE sensitive_data (
    id SERIAL PRIMARY KEY,
    data VARCHAR(255) ENCRYPTED WITH COLUMN_ENCRYPTION_KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Generate encryption key
SELECT pgp_sym_encrypt('sensitive_data', 'encryption_key') as encrypted_data;
```

### Encryption in Transit

Always use SSL/TLS for database connections.

```python
# ✅ GOOD: PostgreSQL with SSL
import psycopg2
import ssl

def create_secure_connection():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    conn = psycopg2.connect(
        host="your-db-host.com",
        database="myapp",
        user="app_user",
        password=os.getenv("DB_PASSWORD"),
        sslmode="verify-full",
        sslcert="client-cert.pem",
        sslkey="client-key.pem",
        sslrootcert="ca-cert.pem"
    )

    return conn

# ✅ GOOD: MongoDB with SSL
from pymongo import MongoClient
import ssl

client = MongoClient(
    "mongodb+srv://user:password@cluster.mongodb.net/myapp",
    ssl=True,
    ssl_cert_reqs=ssl.CERT_REQUIRED,
    ssl_ca_certs="ca.pem",
    ssl_certfile="client.pem",
    ssl_keyfile="client.key"
)
```

### Application-Level Encryption

For highly sensitive data, implement application-level encryption.

```python
# ✅ GOOD: Application-level encryption for sensitive fields
from cryptography.fernet import Fernet
import os

# Generate and store encryption key securely
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY").encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

class EncryptedField:
    """Custom field type for encrypted database columns"""

    def __init__(self, value: str = None):
        if value:
            self.encrypted_value = cipher_suite.encrypt(value.encode()).decode()
        else:
            self.encrypted_value = None

    def decrypt(self) -> str:
        if self.encrypted_value:
            return cipher_suite.decrypt(self.encrypted_value.encode()).decode()
        return None

# Usage in models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    encrypted_ssn = Column(String(255))  # Encrypted SSN

    @property
    def ssn(self):
        if self.encrypted_ssn:
            return EncryptedField(self.encrypted_ssn).decrypt()
        return None

    @ssn.setter
    def ssn(self, value):
        if value:
            self.encrypted_ssn = EncryptedField(value).encrypted_value
        else:
            self.encrypted_ssn = None
```

---

## Input Validation & SQL Injection Prevention

### Never Trust Input

Always validate and sanitize input data before database operations.

```python
# ✅ GOOD: Parameterized queries prevent SQL injection
import sqlite3
from typing import Optional, List

def get_user_by_id(db: sqlite3.Connection, user_id: int) -> Optional[dict]:
    """Get user by ID safely using parameterized query"""
    cursor = db.cursor()

    # ✅ SAFE: Parameterized query
    query = "SELECT id, username, email FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    result = cursor.fetchone()
    if result:
        return {"id": result[0], "username": result[1], "email": result[2]}
    return None

def search_users(db: sqlite3.Connection, search_term: str, limit: int = 10) -> List[dict]:
    """Search users safely with parameterized query and limit"""
    if not search_term or len(search_term.strip()) < 2:
        return []

    cursor = db.cursor()

    # ✅ SAFE: Parameterized query with wildcards
    query = """
    SELECT id, username, email
    FROM users
    WHERE username LIKE ? OR email LIKE ?
    ORDER BY username
    LIMIT ?
    """

    search_pattern = f"%{search_term.strip()}%"
    cursor.execute(query, (search_pattern, search_pattern, limit))

    results = cursor.fetchall()
    return [
        {"id": row[0], "username": row[1], "email": row[2]}
        for row in results
    ]

# ❌ BAD: SQL injection vulnerable
def get_user_bad(db: sqlite3.Connection, user_id: str):
    cursor = db.cursor()

    # DANGEROUS: String concatenation - SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    return cursor.fetchall()
```

### NoSQL Injection Prevention

Apply similar principles to NoSQL databases.

```python
# ✅ GOOD: MongoDB injection prevention
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from bson.objectid import ObjectId
import re

class UserRepository:
    def __init__(self, db_client):
        self.db = db_client.myapp
        self.users = self.db.users

    def get_user_by_id(self, user_id: str):
        """Safely get user by ID"""
        try:
            # Validate ObjectId format
            if not ObjectId.is_valid(user_id):
                return None

            return self.users.find_one({"_id": ObjectId(user_id)})
        except PyMongoError:
            return None

    def search_users(self, search_term: str, limit: int = 10):
        """Safely search users with input validation"""
        if not search_term or len(search_term.strip()) < 2:
            return []

        # Sanitize search term
        search_pattern = re.escape(search_term.strip())

        # Use regex with escaped pattern
        query = {
            "$or": [
                {"username": {"$regex": search_pattern, "$options": "i"}},
                {"email": {"$regex": search_pattern, "$options": "i"}}
            ]
        }

        return list(
            self.users.find(query)
            .limit(limit)
            .sort("username", 1)
        )

# ❌ BAD: MongoDB injection vulnerable
def search_users_bad(db, search_term):
    users = db.users

    # DANGEROUS: Direct use of user input in query
    query = {"username": {"$regex": search_term}}  # Injection risk
    return users.find(query)
```

---

## Common Database Security Pitfalls

### 1. Hardcoded Database Credentials

```python
# ❌ BAD: Hardcoded credentials
DATABASE_URL = "postgresql://admin:password123@localhost:5432/myapp"

# ✅ GOOD: Environment variables
import os

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")
```

### 2. Insufficient Error Handling

```python
# ❌ BAD: Exposes database information
def get_user(user_id):
    try:
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        return cursor.fetchone()
    except Exception as e:
        print(f"Database error: {e}")  # Exposes sensitive info
        return None

# ✅ GOOD: Secure error handling
import logging

logger = logging.getLogger(__name__)

def get_user(user_id):
    try:
        # Input validation
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user ID")

        cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()
    except ValueError as e:
        logger.warning(f"Invalid input: {e}")
        return None
    except DatabaseError as e:
        logger.error(f"Database error occurred")  # Don't expose details
        return None
```

### 3. Insecure Database Backups

```python
# ✅ GOOD: Secure database backup process
import subprocess
import os
import datetime
from cryptography.fernet import Fernet

def create_encrypted_backup():
    """Create and encrypt database backup"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"backup_{timestamp}.sql"
    encrypted_file = f"{backup_file}.enc"

    try:
        # Create database backup
        subprocess.run([
            "pg_dump",
            "-h", os.getenv("DB_HOST"),
            "-U", os.getenv("DB_USER"),
            "-d", os.getenv("DB_NAME"),
            "-f", backup_file
        ], check=True)

        # Encrypt the backup file
        cipher_suite = Fernet(os.getenv("BACKUP_ENCRYPTION_KEY"))

        with open(backup_file, 'rb') as f:
            backup_data = f.read()

        encrypted_data = cipher_suite.encrypt(backup_data)

        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)

        # Remove unencrypted backup
        os.remove(backup_file)

        # Upload encrypted backup to secure storage
        upload_to_secure_storage(encrypted_file)

        return True
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        return False
```

---

## Database Monitoring & Auditing

### Security Logging

Log all database security events.

```python
# ✅ GOOD: Database security logging
import logging
import json
from datetime import datetime

security_logger = logging.getLogger('database.security')

class DatabaseAuditor:
    def __init__(self, db_session):
        self.db = db_session

    def log_access_attempt(self, user_id: int, table: str, action: str, success: bool):
        """Log database access attempt"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "table": table,
            "action": action,
            "success": success,
            "ip_address": getattr(get_current_request(), 'client', {}).get('host', 'unknown')
        }

        security_logger.info(f"Database access: {json.dumps(event)}")

    def log_sensitive_data_access(self, user_id: int, table: str, columns: List[str]):
        """Log access to sensitive data columns"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "table": table,
            "sensitive_columns": columns,
            "ip_address": getattr(get_current_request(), 'client', {}).get('host', 'unknown')
        }

        security_logger.warning(f"Sensitive data access: {json.dumps(event)}")

# Usage in queries
auditor = DatabaseAuditor(db_session)

def get_user_sensitive_data(user_id: int):
    try:
        user = db.query(User).filter(User.id == user_id).first()

        if user:
            # Log access to sensitive fields
            sensitive_columns = ['ssn', 'phone_number', 'address']
            auditor.log_sensitive_data_access(user_id, 'users', sensitive_columns)

            # Only return appropriate data based on permissions
            if has_permission(user_id, 'view_sensitive_data'):
                return user
            else:
                return {k: v for k, v in user.__dict__.items()
                       if k not in sensitive_columns}

        auditor.log_access_attempt(user_id, 'users', 'read', False)
        return None
    except Exception as e:
        security_logger.error(f"Database error in get_user_sensitive_data: {e}")
        return None
```

---

## Database Security Checklist

### Before Deployment

- [ ] **Least Privilege**: Database users have minimum necessary permissions
- [ ] **Environment Separation**: Different databases for dev/test/production
- [ ] **Encryption Enabled**: Data encrypted at rest and in transit
- [ ] **Input Validation**: All inputs validated before database operations
- [ ] **Parameterized Queries**: SQL injection prevention implemented
- [ ] **Error Handling**: Secure error handling without information leakage
- [ ] **Security Logging**: Access to sensitive data is logged
- [ ] **Backup Security**: Backups are encrypted and stored securely
- [ ] **Authentication**: Strong authentication methods implemented
- [ ] **Connection Security**: SSL/TLS enforced for all connections

### Regular Maintenance

- [ ] **Review Permissions**: Quarterly review of database user permissions
- [ ] **Update Credentials**: Regular password/credential rotation
- [ ] **Monitor Logs**: Regular review of database security logs
- [ ] **Vulnerability Scanning**: Scan database for vulnerabilities
- [ ] **Backup Testing**: Regular testing of backup and restore procedures
- [ ] **Performance Monitoring**: Monitor for unusual database activity

---

## Compliance Framework Mappings

### ISO 27001:2022 Annex A Controls

| ISO Control | Database Security Implementation | What This Means for Your Code |
| :--- | :--- | :--- |
| **A.8.2 - Classification of Information** | Data classification and labeling | Classify database data sensitivity levels and handle accordingly |
| **A.8.24 - Use of Cryptography** | Database encryption at rest and in transit | Use Transparent Data Encryption (TDE) and TLS for database connections |
| **A.10.1 - Cryptographic Controls** | Encryption key management | Implement proper key rotation and secure key storage practices |
| **A.13.2 - Information Security Incident Management** | Database incident response | Have procedures for database breaches and unauthorized access |
| **A.14.2 - Secure Development** | Secure database development practices | Include security in database design and access control implementation |

### SOC 2 Trust Services Criteria

| SOC 2 Criteria | Database Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Security (Common Criteria)** | Comprehensive database security controls | Implement access controls, encryption, and monitoring |
| **Availability** | Database high availability and backup | Implement proper backup strategies and disaster recovery |
| **Confidentiality** | Protect sensitive data at rest and in transit | Use encryption, data masking, and access controls |
| **Processing Integrity** | Ensure data integrity and accuracy | Implement constraints, validation, and audit trails |

### NIST Cybersecurity Framework

| NIST Function | Database Security Controls | Practical Implementation |
| :--- | :--- | :--- |
| **Identify** | Database asset management | Document all databases, classify data sensitivity |
| **Protect** | Security controls and safeguards | Implement encryption, access controls, and audit logging |
| **Detect** | Security monitoring and anomaly detection | Set up database activity monitoring and alerting |
| **Respond** | Incident response and recovery | Have procedures for database security incidents |
| **Recover** | Recovery planning and improvements | Maintain backup and restore procedures |

### PCI DSS Requirements (for payment databases)

| PCI Requirement | Database Security Implementation | What Developers Must Do |
| :--- | :--- | :--- |
| **Requirement 3** | Protect cardholder data | Use database encryption, tokenization, and data masking |
| **Requirement 4** | Secure transmission | Use TLS for all database connections |
| **Requirement 6** | Secure development | Follow secure coding practices for database access |
| **Requirement 7** | Access control | Implement principle of least privilege for database users |
| **Requirement 8** | Authentication methods | Use strong authentication for database access |

### GDPR Considerations

| GDPR Principle | Database Security Implementation | Developer Actions |
| :--- | :--- | :--- |
| **Data Protection by Design** | Security in database architecture | Include privacy controls in database design |
| **Data Minimization** | Limit data collection and retention | Store only necessary data and implement retention policies |
| **Accountability** | Demonstrate compliance | Maintain database audit logs and documentation |
| **Security of Processing** | Appropriate technical measures | Implement encryption, pseudonymization, and access controls |

### HIPAA Considerations (for healthcare databases)

| HIPAA Requirement | Database Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Administrative Safeguards** | Access management and training | Implement proper user roles and conduct security training |
| **Physical Safeguards** | Database server security | Secure physical access to database servers |
| **Technical Safeguards** | Access controls and audit logs | Implement unique user authentication and access controls |
| **Breach Notification** | Incident response procedures | Have procedures for detecting and reporting breaches |

### Common Database Security Standards Mapping

| Standard | Key Requirements | Implementation Examples |
| :--- | :--- | :--- |
| **OWASP Top 10** | SQL injection, insecure data access | Use parameterized queries, implement proper access controls |
| **CIS Controls** | Access control, malware defense | Implement database activity monitoring, regular security updates |
| **NIST SP 800-53** | Security and privacy controls | Implement audit logging, encryption, incident response |

## Getting Help

### Database Security Team
- **Slack**: #database-security
- **Email**: db-security@company.com
- **Emergency**: db-emergency@company.com

### Common Issues
- **Connection problems**: Check SSL configuration and credentials
- **Permission issues**: Review database user roles and permissions
- **Performance problems**: Review query optimization and indexing
- **Security incidents**: Contact security team immediately

---

**Last Updated**: 2024-10-24
**Version**: 1.0
**Next Review**: 2025-01-24
**Maintained By**: Database Security Team