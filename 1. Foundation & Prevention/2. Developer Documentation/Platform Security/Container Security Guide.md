# Container Security Guide for Developers

This practical guide helps you build and deploy secure containers. Instead of abstract requirements, you'll find **how** to implement secure container patterns and **why** each control matters for your applications.

## What You'll Learn

- How to write secure Dockerfiles
- Container image scanning and vulnerability management
- Runtime security best practices
- Secrets management in containers
- Kubernetes security patterns
- Common container security pitfalls and how to avoid them

---

## Container Security Fundamentals

### Principle 1: Minimal Attack Surface
Use minimal base images and only install what's absolutely necessary.

**Why this matters**: Smaller images mean fewer vulnerabilities and faster deployment times.

### Principle 2: Immutable Infrastructure
Treat containers as immutable - patch by rebuilding, not by modifying running containers.

**Why this matters**: Immutable containers are more predictable, easier to audit, and reduce configuration drift.

### Principle 3: Defense in Depth
Layer security controls at the image, container, and orchestration levels.

**Why this matters**: Multiple layers provide comprehensive protection and visibility.

---

## Secure Dockerfile Patterns

### 1. Use Minimal Base Images

```dockerfile
# ❌ BAD: Large base image with unnecessary packages
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    vim \
    net-tools

# ✅ GOOD: Minimal base image
FROM python:3.11-alpine
# Alpine is small and secure
# Python:3.11-alpine includes only what's needed
```

### 2. Multi-Stage Builds

```dockerfile
# ✅ GOOD: Multi-stage build for smaller final image
# Build stage
FROM node:18-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM node:18-alpine AS production
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app

# Copy only necessary files from builder
COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json

USER nextjs

EXPOSE 3000
CMD ["npm", "start"]
```

### 3. Secure User Configuration

```dockerfile
# ❌ BAD: Running as root
FROM python:3.11-alpine
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]

# ✅ GOOD: Non-root user with proper permissions
FROM python:3.11-alpine

# Create non-root user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and set permissions
COPY --chown=appuser:appgroup . .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads && \
    chown -R appuser:appgroup /app/logs /app/uploads

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "app.py"]
```

### 4. Secure Configuration Management

```dockerfile
# ✅ GOOD: Environment variables for configuration
FROM python:3.11-alpine

RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appgroup . .

# Set environment variables (use defaults for development)
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_ENV=production
ENV FLASK_DEBUG=false

# Create non-root directories for data
RUN mkdir -p /app/data /app/logs && \
    chown -R appuser:appgroup /app/data /app/logs

USER appuser

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

CMD ["python", "app.py"]
```

---

## Image Security Best Practices

### 1. Vulnerability Scanning

```bash
# ✅ GOOD: Automated security scanning workflow

# Scan Dockerfile for security issues
hadolint Dockerfile

# Scan image for vulnerabilities
trivy image myapp:latest

# Scan with Grype for additional coverage
grype myapp:latest

# Integrate into CI/CD pipeline
name: Container Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'
```

### 2. Image Signing and Verification

```bash
# ✅ GOOD: Sign images for integrity verification

# Generate key pair for image signing
cosign generate-key-pair

# Sign the image
cosign sign myapp:latest

# Verify image signature
cosign verify myapp:latest

# In CI/CD pipeline
name: Sign and Verify Image
steps:
  - name: Sign container image
    run: |
      echo "${{ secrets.COSIGN_PRIVATE_KEY }}" > cosign.key
      cosign sign --key cosign.key myapp:${{ github.sha }}

  - name: Verify container image
    run: |
      cosign verify myapp:${{ github.sha }}
```

### 3. Minimal Attack Surface

```dockerfile
# ✅ GOOD: Removing unnecessary tools and packages
FROM python:3.11-alpine

# Install only necessary system packages
RUN apk add --no-cache \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Create application user
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=appuser:appgroup . .

# Remove package manager (not needed in production)
RUN apk del --purge apk-tools

USER appuser

EXPOSE 8080

CMD ["python", "app.py"]
```

---

## Runtime Security

### 1. Read-Only File System

```yaml
# ✅ GOOD: Kubernetes security context
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        runAsGroup: 1001
        fsGroup: 2000
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        image: myapp:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /app/logs
          readOnly: false
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}
```

### 2. Resource Limits and Requests

```yaml
# ✅ GOOD: Resource limits prevent DoS
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: myapp:latest
    resources:
      requests:
        memory: "256Mi"
        cpu: "250m"
      limits:
        memory: "512Mi"
        cpu: "500m"
    securityContext:
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: "250m"
          memory: "256Mi"
```

### 3. Network Security

```yaml
# ✅ GOOD: Network policies for isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

---

## Secrets Management

### 1. Never Hardcode Secrets

```dockerfile
# ❌ BAD: Hardcoded secrets in Dockerfile
FROM python:3.11-alpine
ENV DATABASE_PASSWORD="supersecretpassword123"
ENV API_KEY="sk-1234567890abcdef"

# ✅ GOOD: Use environment variables
FROM python:3.11-alpine
# Secrets will be provided at runtime
ENV DATABASE_URL=""
ENV API_KEY=""
```

### 2. Use External Secret Management

```yaml
# ✅ GOOD: Kubernetes secrets
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  database-password: c3VwZXJzZWNyZXRwYXNzd29yZDEyMw==  # base64 encoded
  api-key: c2stMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWY=
---
apiVersion: v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:latest
        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-password
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: api-key
```

### 3. HashiCorp Vault Integration

```python
# ✅ GOOD: Vault integration for secrets
import os
import hvac
from typing import Optional

class VaultSecretManager:
    def __init__(self):
        self.client = hvac.Client()
        self.client.auth.approle.login(
            role_id=os.getenv("VAULT_ROLE_ID"),
            secret_id=os.getenv("VAULT_SECRET_ID")
        )

    def get_secret(self, path: str, key: str) -> Optional[str]:
        try:
            secret = self.client.secrets.kv.v2.read_secret_version(
                path=path
            )
            return secret['data']['data'][key]
        except Exception:
            return None

# Usage in application
vault_manager = VaultSecretManager()

database_url = vault_manager.get_secret("database", "url")
database_password = vault_manager.get_secret("database", "password")
```

---

## Container Security Tools

### 1. Static Analysis Tools

```bash
# Hadolint - Dockerfile linting
hadolint Dockerfile

# Dockerfilelint - Alternative Dockerfile linter
dockerfilelint Dockerfile

# Trivy - Container vulnerability scanning
trivy image myapp:latest

# Grype - Vulnerability scanning for container images
grype myapp:latest

# Clair - Container vulnerability analysis
clairctl analyze myapp:latest
```

### 2. Runtime Security Tools

```yaml
# ✅ GOOD: Falco runtime security monitoring
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
spec:
  template:
    spec:
      serviceAccount: falco
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
        - name: proc
          mountPath: /proc
        - name: dev
          mountPath: /dev
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: proc
        hostPath:
          path: /proc
      - name: dev
        hostPath:
          path: /dev
```

### 3. Image Scanning in CI/CD

```yaml
# ✅ GOOD: Complete CI/CD security pipeline
name: Container Security Pipeline
on: [push, pull_request]

jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: |
          docker build -t myapp:${{ github.sha }} .
          docker tag myapp:${{ github.sha }} myapp:latest

      - name: Run Hadolint
        uses: hadolint/hadolint-action@v2.1.0
        with:
          dockerfile: Dockerfile

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Sign image with Cosign
        run: |
          echo "${{ secrets.COSIGN_PRIVATE_KEY }}" > cosign.key
          cosign sign --key cosign.key myapp:${{ github.sha }}

      - name: Push to registry
        run: |
          echo "${{ secrets.DOCKER_PASSWORD }}" | docker login -u "${{ secrets.DOCKER_USERNAME }}" --password-stdin
          docker push myapp:${{ github.sha }}
          docker push myapp:latest
```

---

## Common Container Security Pitfalls

### 1. Running as Root

```dockerfile
# ❌ BAD: Running as root
FROM python:3.11-alpine
COPY . /app
WORKDIR /app
CMD ["python", "app.py"]

# ✅ GOOD: Non-root user
FROM python:3.11-alpine
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app
COPY --chown=appuser:appgroup . .

USER appuser
CMD ["python", "app.py"]
```

### 2. Debug Mode in Production

```python
# ❌ BAD: Debug mode enabled
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

# ✅ GOOD: Environment-based debug mode
if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host='0.0.0.0' if debug_mode else '127.0.0.1')
```

### 3. Insecure File Permissions

```dockerfile
# ❌ BAD: World-writable files
FROM python:3.11-alpine
COPY . /app
RUN chmod 777 /app
CMD ["python", "app.py"]

# ✅ GOOD: Secure file permissions
FROM python:3.11-alpine
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

WORKDIR /app
COPY --chown=appuser:appgroup . .

# Create directories with proper permissions
RUN mkdir -p /app/data /app/logs && \
    chown -R appuser:appgroup /app/data /app/logs && \
    chmod 755 /app/data /app/logs

USER appuser
CMD ["python", "app.py"]
```

---

## Container Security Checklist

### Image Build Security

- [ ] **Minimal Base Image**: Use minimal, secure base images
- [ ] **Non-Root User**: Container runs as non-root user
- [ ] **Multi-Stage Build**: Use multi-stage builds to reduce image size
- [ ] **No Secrets**: No hardcoded secrets in Dockerfile or image
- [ ] **Security Scanning**: Image scanned for vulnerabilities
- [ ] **Image Signing**: Image signed for integrity verification
- [ ] **File Permissions**: Proper file permissions and ownership
- [ ] **Minimal Packages**: Only install necessary packages

### Runtime Security

- [ ] **Read-Only FS**: Container runs with read-only filesystem
- [ ] **Resource Limits**: CPU and memory limits configured
- [ ] **Security Context**: Proper security context (no privileges)
- [ ] **Network Policies**: Network access restricted as needed
- [ ] **Pod Security**: Pod security policies enforced
- [ ] **Runtime Monitoring**: Runtime security monitoring enabled
- [ ] **Secrets Management**: Proper external secrets management

### Orchestration Security

- [ ] **RBAC**: Role-based access control configured
- [ ] **Network Policies**: Network isolation implemented
- [ ] **Admission Controllers**: Security admission controllers enabled
- [ ] **Audit Logging**: Security events logged and monitored
- [ ] **Image Policies**: Only signed/verified images allowed
- [ ] **Namespace Isolation**: Proper namespace separation

---

## Compliance Framework Mappings

### ISO 27001:2022 Annex A Controls

| ISO Control | Container Security Implementation | What This Means for Your Code |
| :--- | :--- | :--- |
| **A.8.2 - Classification of Information** | Image and data classification | Classify container images and data by sensitivity level |
| **A.8.24 - Use of Cryptography** | Container encryption and secrets | Encrypt container data volumes and use secure secrets management |
| **A.12.6 - Technical Vulnerability Management** | Container vulnerability scanning | Regular scanning of container images for vulnerabilities |
| **A.13.2 - Information Security Incident Management** | Container incident response | Have procedures for container security incidents |
| **A.14.2 - Secure Development** | Secure container development practices | Include security in container image building and deployment |

### SOC 2 Trust Services Criteria

| SOC 2 Criteria | Container Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Security (Common Criteria)** | Comprehensive container security controls | Implement image scanning, runtime protection, and access controls |
| **Availability** | Container high availability and resilience | Use orchestration with proper failover and health checks |
| **Confidentiality** | Protect sensitive data in containers | Use encrypted volumes, secrets management, and image signing |
| **Processing Integrity** | Ensure container integrity and non-repudiation | Use image signing, checksums, and audit logging |

### NIST Cybersecurity Framework

| NIST Function | Container Security Controls | Practical Implementation |
| :--- | :--- | :--- |
| **Identify** | Container asset management | Document all container images, registries, and orchestration |
| **Protect** | Security controls and safeguards | Implement image scanning, runtime security, and network policies |
| **Detect** | Security monitoring and anomaly detection | Set up container runtime monitoring and alerting |
| **Respond** | Incident response and recovery | Have procedures for container security incidents |
| **Recover** | Recovery planning and improvements | Maintain backup images and disaster recovery procedures |

### CIS Controls for Container Security

| CIS Control | Container Implementation | What Developers Must Do |
| :--- | :--- | :--- |
| **Control 1: Inventory of Authorized Devices** | Container and image inventory | Maintain inventory of approved container images |
| **Control 2: Inventory of Software** | Container image management | Track and approve all container images in use |
| **Control 3: Secure Configurations** | Container hardening | Use secure base images and configuration best practices |
| **Control 5: Malware Defenses** | Container malware scanning | Scan images for malware and unauthorized code |

### PCI DSS Requirements (for payment containerized applications)

| PCI Requirement | Container Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Requirement 1** | Network security controls | Implement container network segmentation |
| **Requirement 2** | Secure configuration | Use hardened container configurations |
| **Requirement 3** | Protect cardholder data | Encrypt data in container volumes and use secrets management |
| **Requirement 6** | Secure development | Secure container image building practices |

### GDPR Considerations

| GDPR Principle | Container Security Implementation | Developer Actions |
| :--- | :--- | :--- |
| **Data Protection by Design** | Security in container architecture | Include privacy controls in container design |
| **Data Minimization** | Limit data in containers | Store only necessary data in containers |
| **Accountability** | Demonstrate compliance | Maintain container audit logs and documentation |
| **Security of Processing** | Appropriate technical measures | Implement encrypted volumes and secure configurations |

### NIST SP 800-190 Container Security Guidelines

| NIST Guideline | Container Security Control | Implementation Example |
| :--- | :--- | :--- |
| **Image Security** | Use trusted base images | Use official images or verified third-party images |
| **Configuration Management** | Secure container configurations | Implement least privilege and read-only file systems |
| **Runtime Security** | Container runtime protection | Use security contexts, policies, and monitoring |
| **Orchestration Security** | Secure container orchestration | Implement RBAC, network policies, and secrets management |

### Container Security Standards Mapping

| Standard | Key Requirements | Implementation Examples |
| :--- | :--- | :--- |
| **OWASP Container Security Verification** | Image security, runtime security | Implement image scanning, runtime monitoring |
| **Docker CIS Benchmark** | Docker daemon and container security | Secure Docker configuration and container settings |
| **Kubernetes CIS Benchmark** | Kubernetes cluster security | Implement pod security policies and network policies |

## Getting Help

### Container Security Team
- **Slack**: #container-security
- **Email**: container-security@company.com
- **Emergency**: container-emergency@company.com

### Common Issues
- **Image vulnerabilities**: Use automated scanning and base image updates
- **Runtime security**: Implement proper security contexts and policies
- **Secrets management**: Use external secret management systems
- **Network issues**: Configure proper network policies and service discovery

---

**Last Updated**: 2024-10-24
**Version**: 1.0
**Next Review**: 2025-01-24
**Maintained By**: Container Security Team