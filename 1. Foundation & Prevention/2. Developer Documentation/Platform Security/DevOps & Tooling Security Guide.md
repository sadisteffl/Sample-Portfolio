# DevOps & Tooling Security Guide

This practical guide helps DevOps engineers implement secure CI/CD pipelines, infrastructure as code, and development tools. Instead of abstract requirements, you'll find **how** to implement secure DevOps patterns and **why** each control matters for your delivery pipeline.

## What You'll Learn

- Secure CI/CD pipeline implementation
- Infrastructure as Code (IaC) security best practices
- Container registry and image security
- Secrets management in DevOps workflows
- Monitoring and logging for security
- Common DevOps security pitfalls and how to avoid them

---

## DevOps Security Fundamentals

### Principle 1: Secure by Default
All systems and tools should be secure by default, with security features enabled rather than opt-in.

**Why this matters**: Default-secure configurations prevent accidental misconfigurations that could lead to security breaches.

### Principle 2: Automated Security
Security controls should be automated and integrated into every stage of the delivery pipeline.

**Why this matters**: Automation ensures consistent security enforcement and reduces the risk of human error.

### Principle 3: Principle of Least Privilege
DevOps tools and services should have only the permissions they absolutely need.

**Why this matters**: If a DevOps tool is compromised, the attacker only has access to what that tool needs, not your entire infrastructure.

---

## Secure CI/CD Pipeline Implementation

### 1. GitHub Actions Security

```yaml
# ✅ GOOD: Secure GitHub Actions workflow
name: Secure CI/CD Pipeline
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

permissions:
  contents: read
  packages: write
  pull-requests: write
  issues: write
  checks: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run security scanning
        run: |
          echo "🔒 Running comprehensive security scan..."

          # Run Semgrep for code analysis
          docker run --rm -v "$(pwd):/app" returntocorp/semgrep --config=auto .

          # Run TruffleHog for secrets
          docker run --rm -v "$(pwd):/app" trufflesecurity/trufflehog:latest \
            git file://. --since-commit HEAD --only-verified

          # Run Trivy for vulnerabilities
          docker run --rm -v "$(pwd):/app" aquasecurity/trivy:latest fs .

          echo "✅ Security scan completed"

      - name: Upload security findings
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-scan-results
          path: security-reports/
          retention-days: 30

  build-and-deploy:
    runs-on: ubuntu-latest
    needs: security-scan
    if: github.ref == 'refs/heads/main'

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Login to container registry
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ secrets.GITHUB_ACTOR }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build container image
        run: |
          docker build \
            --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
            --build-arg VCS_REF=${{ github.sha }} \
            -t ghcr.io/${{ github.repository }}:${{ github.sha }} \
            -t ghcr.io/${{ github.repository }}:latest .

      - name: Scan container image
        run: |
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasecurity/trivy:latest image \
            ghcr.io/${{ github.repository }}:${{ github.sha }}

      - name: Push container image
        run: |
          docker push ghcr.io/${{ github.repository }}:${{ github.sha }}
          docker push ghcr.io/${{ github.repository }}:latest

      - name: Deploy to staging
        run: |
          # Deployment logic here
          echo "Deploying to staging environment"
          # kubectl apply -f k8s/staging/
```

### 2. Jenkins Security Configuration

```groovy
// ✅ GOOD: Secure Jenkins configuration
pipeline {
    agent any

    environment {
        // Use environment variables for secrets
        DOCKER_REGISTRY_CREDENTIALS = credentials('docker-registry-creds')
        SONARQUBE_TOKEN = credentials('sonarqube-token')
        SLACK_WEBHOOK_URL = credentials('slack-webhook-url')
    }

    stages {
        checkout
        security-scan
        build
        test
        deploy
    }

    stage('checkout') {
        steps {
            checkout scm
            script {
                // Verify git integrity
                sh 'git verify-commit HEAD'

                // Check for secrets in code
                sh 'trufflehog git file://. --since-commit HEAD~10'
            }
        }
    }

    stage('security-scan') {
        steps {
            script {
                // Static code analysis
                sh 'semgrep --config=auto . || true'

                // Container security scan
                sh 'trivy fs .'

                // Dependency vulnerability scan
                sh 'npm audit --audit-level=high || true'

                // Infrastructure as Code security
                sh 'checkov terraform/ || true'
                sh 'tfsec . || true'
            }

            post {
                // Upload results to security dashboard
                uploadSonarqubeResults()
                uploadTrivyResults()

                // Send alerts if vulnerabilities found
                sendSecurityAlerts()
            }
        }
    }
}

// ✅ GOOD: Secure Jenkins configuration
import jenkins.model.*

// Disable CLI interface
Jenkins.instance.setCrumbCrumbIssuer(null)
Jenkins.instance.setCrumbCrumbTarget(null)

// Enable security headers
System.setProperty('hudson.model.DirectoryBrowserSupport', 'false')

// CSRF protection
Jenkins.instance.setDescriptor(
    Jenkins.getInstance().getDescriptor()
        .addCSRFProtection(true)
)

// Enable script security for sandboxing
System.setProperty('hudson.model.DirectoryBrowserSupport', 'false')
```

### 3. GitLab CI/CD Security

```yaml
# ✅ GOOD: Secure GitLab CI configuration
stages:
  - security-scan
  - test
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: /certs
  DOCKER_TLS_CERTDIR: /certs/client
  DOCKER_TLS_KEY: /certs/client/key.pem
  DOCKER_TLS_CA_CERT: /certs/ca.crt

# Security scanning
security-scan:
  stage: security-scan
  image: owasp/zap2docker-stable
  script:
    - mkdir -p /zap/wrk/
    - /zap/zap.sh -cmd quickscan -t http://target-app:8080 -r /zap/wrk/ -l pass || true
  artifacts:
    reports:
      reports/zap-report.html
      reports/zap-baseline.json

secrets-scanning:
  stage: security-scan
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://. --since-commit HEAD~10 --only-verified
  artifacts:
    reports:
      trufflehog-report.json

# Static code analysis
sast:
  stage: test
  image: python:3.9
  script:
    - pip install semgrep
    - semgrep --config=auto --sarif -o semgrep-report.sarif .
  artifacts:
    reports:
      semgrep-report.sarif

# Container security
container-scanning:
  stage: test
  image: aquasec/trivy:latest
  script:
    - trivy image --format sarif --output container-report.sarif $CI_REGISTRY_IMAGE
  artifacts:
    reports:
      container-report.sarif

# Secure deployment
deploy:
  stage: deploy
  image: alpine:latest
  script:
    - echo "Deploying to production"
    - kubectl apply -f k8s/production/
  only:
    - main
  when: manual
```

---

## Infrastructure as Code Security

### 1. Terraform Security

```hcl
# ✅ GOOD: Secure Terraform configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    Environment = var.environment
    ManagedBy = "Terraform"
    Security = "Compliant"
    CostCenter = var.cost_center
  }
}

# Secure S3 bucket configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "${var.project_name}-${var.environment}-secure-storage"

  # Enable encryption
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default = true
      sse_algorithm = "AES256"
    }
  }

  # Enable versioning
  versioning {
    enabled = true
  }

  # Block public access
  public_access_block {
    block_public_acls = true
    block_public_policy = true
  }

  # Enable logging
  logging {
    bucket_prefix = "logs/"
  }

  # Enable MFA delete
  object_lock_configuration {
    object_lock_enabled = true
  }

  # Network restrictions
  restrict_public_buckets = true

  tags = {
    Name = "Secure Storage Bucket"
    Environment = var.environment
    DataClassification = "Sensitive"
  }
}

# Secure IAM role for Terraform
resource "aws_iam_role" "terraform_role" {
  name = "terraform-${var.environment}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation"
        ],
        Resource = "*"
      }
    ]
  })

  inline_policy {
    name = "terraform-inline-policy"
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [
        {
          Effect = "Allow",
          Action = [
            "logs:*",
            "monitoring:*"
          ],
          Resource = "*"
        }
      ]
    }
  }
}

# Secure networking
resource "aws_security_group" "web_server_sg" {
  name        = "${var.project_name}-web-server-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  # HTTPS inbound traffic only
  ingress {
    description = "HTTPS inbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.lb_sg.id]
  }

  # SSH access from bastion hosts only
  ingress {
    description = "SSH from bastion"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.bastion_cidrs
    security_groups = [aws_security_group.bastion_sg.id]
  }

  # Egress restrictions
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS queries"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Web Server Security Group"
    Environment = var.environment
  }
}

# Secure database credentials
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${var.project_name}-${var.environment}-db-credentials"
  description             = "Database credentials for production database"
  recovery_window_in_days = 30

  kms_key_id = aws_kms_key.secrets_key.arn

  secret_string = jsonencode({
    username = var.db_username,
    password = var.db_password,
    host     = var.db_host,
    port     = var.db_port,
    database = var.db_name
  })

  tags = {
    Name = "Database Credentials"
    Environment = var.environment
  }
}
```

### 2. Kubernetes Security

```yaml
# ✅ GOOD: Secure Kubernetes deployment
apiVersion: v1
kind: Namespace
metadata:
  name: secure-app
  labels:
    name: secure-app
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secure-app-sa
  namespace: secure-app
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secure-app-role
  namespace: secure-app
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secure-app-rolebinding
  namespace: secure-app
subjects:
- kind: ServiceAccount
  name: secure-app-sa
  namespace: secure-app
roleRef:
  kind: Role
  name: secure-app-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: secure-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      serviceAccountName: secure-app-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 3000
        fsGroup: 2000
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: secure-app
        image: secure-app:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-url
              key: url
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: api-key
              key: key
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: logs
          mountPath: /app/logs
          readOnly: false
        ports:
        - containerPort: 8080
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: tmp
        emptyDir: {}
      - name: logs
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: secure-app-service
  namespace: secure-app
spec:
  selector:
    app: secure-app
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
```

---

## Container Registry Security

### 1. Private Container Registry

```bash
# ✅ GOOD: Setting up secure container registry
# Using AWS ECR
aws ecr create-repository \
  --repository-name secure-app \
  --region us-west-2 \
  --image-scanning-configuration scan-on-push \
  --image-tag-mutability IMMUTABLE

# Set up lifecycle policy
aws ecr put-lifecycle-policy \
  --repository-name secure-app \
  --lifecycle-policy-text "rules.json"

# lifecycle-policy.json
{
  "rules": [
    {
      "rulePriority": 1,
      "description": "Keep last 10 images",
      "selection": {
        "tagStatus": "tagged",
        "tagCount": "moreThan",
        "countType": "imageCount",
        "countNumber": 10
      },
      "action": {
        "type": "expire"
      }
    },
    {
      "rulePriority": 2,
      "description": "Keep untagged images for 1 day",
      "selection": {
        "tagStatus": "untagged",
        "countType": "sinceImagePushed",
        "countUnit": "days"
      },
      "action": {
        "type": "expire",
        "days": 1
      }
    }
  ]
}

# Configure image scanning
aws ecr put-image-scanning-configuration \
  --repository-name secure-app \
  --image-scanning-configuration file://scan-config.json

# scan-config.json
{
  "rules": [
    {
      "name": "vulnerability-scan",
      "description": "Check for image vulnerabilities",
      "configuration": {
        "scanOnPush": true,
        "ignoreFailures": false,
        "timeout": "10",
        "scanLayers": false
      }
    }
  ]
}
```

### 2. Image Signing and Verification

```bash
# ✅ GOOD: Cosign image signing
# Generate key pair
cosign generate-key-pair

# Sign the image
cosign sign \
  --key cosign.key \
  ghcr.io/your-org/secure-app:latest

# Verify the image
cosign verify \
  --key cosign.pub \
  ghcr.io/your-org/secure-app:latest

# In CI/CD pipeline
name: Sign and Verify Container Image
steps:
  - name: Sign container image
    run: |
      echo "${{ secrets.COSIGN_PRIVATE_KEY }}" > cosign.key
      cosign sign \
        --key cosign.key \
        ghcr.io/${{ github.repository }}:${{ github.sha }}

  - name: Verify container image
    run: |
      cosign verify \
        --key cosign.pub \
        ghcr.io/${{ github.repository }}:${{ github.sha }}
```

---

## Secrets Management in DevOps

### 1. HashiCorp Vault Integration

```yaml
# ✅ GOOD: Vault in Kubernetes
apiVersion: v1
kind: Secret
metadata:
  name: vault-token-review
  namespace: vault
type: Opaque
data:
  token: VWZ4b3JlVjFqWk9mS3d6aGVq
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: vault
data:
  vault.hcl: |
    ui = true
    listener "tcp" {
      address = "0.0.0.0:8200"
      tls_disable = "false"
      cluster_addr = "https://vault:8200"
    }
    storage "consul" {
      path = "vault"
    }
  auto_auth:
    enabled = "true"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
  namespace: vault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
    spec:
      serviceAccountName: vault
      securityContext:
        runAsUser: 100
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: vault
        image: hashicorp/vault:1.12.0
        command:
          - server
        - -config=/vault/config/vault.hcl
        env:
        - name: VAULT_ADDR
          value: "https://vault.vault.svc.cluster.local"
        - name: VAULT_K8S_POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: VAULT_K8S_POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: VAULT_K8S_POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: VAULT_SKIP_VERIFY
          value: "true"
        ports:
        - containerPort: 8200
          name: vault
          protocol: TCP
        volumeMounts:
        - name: vault-config
          mountPath: /vault/config
        - name: vault-data
          mountPath: /vault/data
        - name: vault-tls
          mountPath: /vault/tls
      volumes:
      - name: vault-config
        configMap:
          name: vault-config
      - name: vault-data
        persistentVolumeClaim:
          claimName: vault-data
      - name: vault-tls
        secret:
          secretName: vault-server-tls
```

### 2. AWS Secrets Manager Integration

```yaml
# ✅ GOOD: AWS Secrets Manager integration
apiVersion: v1
kind: Secret
metadata:
  name: aws-secrets
  type: Opaque
data:
  access-key-id: QUFBQmFV...  # base64 encoded
  secret-access-key: QUFBQmFV...  # base64 encoded
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: aws-secrets
              key: access-key-id
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: aws-secrets
              key: secret-access-key
        - name: REGION
          value: "us-west-2"
        - name: SECRET_NAME
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-password
```

### 3. Environment Variables vs. Secret Management

```yaml
# ✅ GOOD: Secure secrets management
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  type: Opaque
stringData:
  database-url: cG9zdGdyYW1ZHN0bnJlYWRlY3M6...
  api-key: sk-1234567890abcdef1234567890abcdef...
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        # ✅ GOOD: Using secrets for sensitive data
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-url
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: api-key

        # ✅ ACCEPTABLE: Non-sensitive configuration
        - name: LOG_LEVEL
          value: "INFO"
        - name: NODE_ENV
          value: "production"
        - name: PORT
          value: "8080"

        # ❌ NEVER: Secrets in environment variables
        # - name: PASSWORD
        #   value: "super-secret-password"
```

---

## Monitoring and Security Logging

### 1. Comprehensive Security Logging

```python
# ✅ GOOD: Security logging for DevOps tools
import logging
import json
import os
from datetime import datetime
from typing import Dict, Any

class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('devops.security')
        self.logger.setLevel(logging.INFO)

        # Create file handler for security logs
        handler = logging.FileHandler('/var/log/security.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s - %(user)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Create cloud watch handler for centralized logging
        if os.getenv('CLOUDWATCH_ENABLED'):
            self._setup_cloudwatch_logging()

    def _setup_cloudwatch_logging(self):
        """Setup CloudWatch logging for centralized security logs"""
        import boto3
        cloudwatch = boto3.client('logs')

        log_group = '/aws/devops/security'
        log_stream = 'security-events'

        try:
            cloudwatch.create_log_group(logGroupName=log_group)
            cloudwatch.create_log_stream(
                logGroupName=log_group,
                logStreamName=log_stream
            )
        except Exception as e:
            self.logger.warning(f"Could not create CloudWatch resources: {e}")

    def log_pipeline_event(self, event_type: str, details: Dict[str, Any], user: str = None):
        """Log CI/CD pipeline security events"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'details': details,
            'user': user or 'system',
            'source': 'devops-pipeline',
            'severity': self._get_severity(event_type)
        }

        self.logger.info(json.dumps(log_entry))
        self._send_alert(event_type, log_entry)

    def _get_severity(self, event_type: str) -> str:
        """Determine severity level for events"""
        high_severity_events = [
            'security_scan_failed',
            'unauthorized_access',
            'malicious_code_detected',
            'credential_exposure'
        ]
        return 'HIGH' if event_type in high_severity_events else 'INFO'

    def _send_alert(self, event_type: str, log_entry: Dict[str, Any]):
        """Send alerts for critical security events"""
        if self._get_severity(event_type) == 'HIGH':
            # Send Slack notification
            self._send_slack_alert(event_type, log_entry)

    def _send_slack_alert(self, event_type: str, log_entry: Dict[str, Any]):
        """Send Slack alert for security events"""
        webhook_url = os.getenv('SECURITY_SLACK_WEBHOOK')
        if not webhook_url:
            return

        try:
            import requests

            message = f"🚨 Security Alert: {event_type}\n\n"
            message += f"User: {log_entry['user']}\n"
            message += f"Details: {json.dumps(log_entry['details'], indent=2)}"

            requests.post(
                webhook_url,
                json={'text': message},
                headers={'Content-Type': 'application/json'}
            )
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")

# Usage in CI/CD pipelines
security_logger = SecurityLogger()

def log_build_event(event_type: str, details: Dict[str, Any]):
    """Log build-related security events"""
    security_logger.log_pipeline_event(
        event_type=event_type,
        details=details,
        user=os.getenv('BUILD_USER', 'system')
    )
```

### 2. Infrastructure Security Monitoring

```yaml
# ✅ Good: Falco runtime security monitoring
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: monitoring
spec:
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccount: falco
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        args:
        - /usr/bin/falco
        - /etc/falco/falco_rules.yaml
        - /var/run/docker.sock
        - /dev/null
        - /proc/1/fs
        - /etc/os-release
        - /etc/hostname
        - /etc/passwd
        - /etc/group
        - /etc/fstab
        - /etc/hosts
        - /etc/issue
      securityContext:
        privileged: true
        runAsUser: 0
        volumeMounts:
        - name: host-root
          mountPath: /host
        - name: var-run-docker-sock
          mountPath: /var/run/docker.sock
        - name: proc
          mountPath: /proc
        - name: dev
          mountPath: /dev
        - name: sys
          mountPath: /sys
        - name: etc-falco
          mountPath: /etc/falco
        - name: var-lib-falco
          mountPath: /var/lib/falco
        - name: var-log-falco
          mountPath: /var/log/falco
        - name: var-run-docker-sock
          mountPath: /var/run/docker.sock
      env:
        - name: FALCO_DISABLE_PLUGIN_NOTIFICATIONS
          value: "true"
        - name: FALCO_DISABLE_K8S_AUDIT
          value: "true"
```

---

## Common DevOps Security Pitfalls

### 1. Insecure Container Images

```dockerfile
# ❌ BAD: Running as root, unnecessary packages
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    net-tools \
    python3 \
    python3-pip

# ✅ GOOD: Minimal base image, non-root user
FROM python:3.11-alpine
RUN addgroup -g 1001 appgroup && \
    adduser -u 1001 -G appgroup -s /bin/sh -D appuser

USER appuser
```

### 2. Insecure Secrets in CI/CD

```yaml
# ❌ BAD: Secrets in plain text
name: Build and Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        env:
          DATABASE_PASSWORD: supersecretpassword123
          API_KEY: sk-1234567890abcdef
        run: |
          kubectl apply -f production/
```

```yaml
# ✅ GOOD: Proper secrets management
name: Build and Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        env:
          DATABASE_PASSWORD: ${{ secrets.DATABASE_PASSWORD }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          kubectl apply -f production/
```

### 3. Insufficient Access Controls

```bash
# ❌ BAD: Admin privileges for CI/CD
echo "github-token: $GITHUB_TOKEN" >> ~/.bashrc
docker login -u $DOCKER_USERNAME -p $DOCKER_PASSWORD

# ✅ GOOD: Limited, scoped permissions
echo "github-token: $GITHUB_TOKEN" > ./github-token
export GITHUB_TOKEN=$(cat ./github-token)
chmod 600 ./github-token
```

---

## DevOps Security Checklist

### CI/CD Security
- [ ] **Secure secrets**: No hardcoded secrets in CI/CD pipelines
- [ ] **Image scanning**: All images scanned for vulnerabilities
- [ ] **Code scanning**: Static analysis in CI/CD pipeline
- [ ] **Access controls**: Principle of least privilege for CI/CD tools
- [ ] **Audit logging**: All pipeline activities logged and monitored
- [ ] **Artifact signing**: Build artifacts are signed and verified
- [ ] **Network security**: CI/CD environments are properly secured

### Infrastructure Security
- [ ] **IaC security**: Infrastructure code scanned for misconfigurations
- [ ] **Secrets management**: Proper external secret management
- [ ] **Network security**: Network segmentation and firewalls implemented
- [] **Container security**: Secure container configurations
- [ ] **Access control**: RBAC implemented for infrastructure
- [ ] **Monitoring**: Security events logged and monitored
- [ ] **Backup security**: Backups encrypted and stored securely

### Container Registry Security
- [ ] **Private registry**: Container images stored in private registry
- [] **Image signing**: Images signed and verified
- [   ] **Vulnerability scanning**: All images scanned for vulnerabilities
- [ ] **Access control**: Registry access controls implemented
- [ ] **Immutable tags**: Proper image tagging and lifecycle management
- [ ] **Audit logging**: Registry access logged and monitored

---

## Getting Help

### DevOps Security Team
- **Slack**: #devops-security
- **Email**: devops-security@company.com
- **Emergency**: devops-emergency@company.com

### Common Issues
- **Pipeline failures**: Check security scan results and logs
- **Image vulnerabilities**: Update base images and dependencies
- **Secrets issues**: Use proper secret management systems
- **Access problems**: Review RBAC configurations

---

## Compliance Framework Mappings

### ISO 27001:2022 Annex A Controls

| ISO Control | DevOps Security Implementation | What This Means for Your Code |
| :--- | :--- | :--- |
| **A.8.16 - Secure Development Life Cycle** | Security in DevOps practices | Include security in CI/CD pipeline and infrastructure as code |
| **A.12.6 - Technical Vulnerability Management** | Infrastructure vulnerability management | Regular scanning and patching of infrastructure components |
| **A.14.2 - Secure Development** | Secure DevOps practices | Implement secure pipeline, infrastructure, and deployment practices |
| **A.17.1 - Information Security Continuity** | Business continuity in DevOps | Ensure pipeline resilience and disaster recovery procedures |
| **A.8.23 - Web Filtering** | Network security controls | Implement network segmentation and access controls |

### SOC 2 Trust Services Criteria

| SOC 2 Criteria | DevOps Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Security (Common Criteria)** | Comprehensive DevOps security controls | Secure pipeline, infrastructure, and access management |
| **Availability** | Infrastructure and service availability | Implement monitoring, backup, and disaster recovery |
| **Confidentiality** | Protect sensitive data in operations | Secure secrets, encrypted storage, and access controls |
| **Processing Integrity** | Ensure deployment integrity | Implement code signing, checksums, and audit logging |

### NIST Cybersecurity Framework

| NIST Function | DevOps Security Controls | Practical Implementation |
| :--- | :--- | :--- |
| **Identify** | Infrastructure asset management | Document all infrastructure components and dependencies |
| **Protect** | Security controls in operations | Implement secure pipeline, network security, and access controls |
| **Detect** | Security monitoring and alerting | Set up infrastructure monitoring and security alerting |
| **Respond** | Incident response procedures | Have procedures for infrastructure security incidents |
| **Recover** | Recovery and continuity | Implement backup, disaster recovery, and continuity planning |

### CIS Controls for Cloud and DevOps

| CIS Control | DevOps Implementation | What Developers Must Do |
| :--- | :--- | :--- |
| **Control 1: Inventory of Authorized Devices** | Infrastructure inventory | Maintain inventory of all infrastructure resources |
| **Control 2: Inventory of Software** | Software and container inventory | Track all software, images, and dependencies |
| **Control 3: Secure Configurations** | Infrastructure hardening | Use secure baselines for all infrastructure components |
| **Control 4: Continuous Vulnerability Management** | Ongoing security scanning | Implement continuous scanning and patch management |
| **Control 13: Network Monitoring** | Infrastructure monitoring | Monitor network traffic and security events |

### PCI DSS Requirements (for payment infrastructure)

| PCI Requirement | DevOps Security Implementation | Developer Responsibilities |
| :--- | :--- | :--- |
| **Requirement 1** | Network security controls | Implement network segmentation and firewalls |
| **Requirement 2** | Secure configuration | Use hardened configurations for all infrastructure |
| **Requirement 6** | Secure development | Secure SDLC practices and security testing |
| **Requirement 7** | Access control | Implement principle of least privilege for infrastructure access |
| **Requirement 8** | Authentication methods | Strong authentication for infrastructure access |

### GDPR Considerations

| GDPR Principle | DevOps Security Implementation | Developer Actions |
| :--- | :--- | :--- |
| **Data Protection by Design** | Security in infrastructure design | Include privacy controls in infrastructure architecture |
| **Data Minimization** | Limit data in infrastructure | Store only necessary data and implement retention policies |
| **Accountability** | Demonstrate compliance | Maintain infrastructure documentation and audit trails |
| **Security of Processing** | Appropriate technical measures | Implement encryption, access controls, and monitoring |

### Cloud Security Standards Mapping

| Standard | Key Requirements | Implementation Examples |
| :--- | :--- | :--- |
| **CIS Cloud Benchmarks** | Secure cloud configurations | Use CIS benchmarks for AWS, Azure, GCP configurations |
| **Cloud Controls Matrix (CCM)** | Cloud security controls | Implement controls for cloud service security |
| **ISO 27017** | Cloud security guidelines | Follow cloud-specific security guidelines |
| **NIST SP 800-210** | DevSecOps practices | Implement security in DevOps practices |

### DevSecOps Standards and Frameworks

| Standard | Key Requirements | Implementation Examples |
| :--- | :--- | :--- |
| **OWASP DevSecOps Guideline** | Security in DevOps lifecycle | Integrate security throughout DevOps processes |
| **SANS DevSecOps** | Security automation | Automate security testing and compliance checks |
| **SAMM (Software Assurance Maturity Model)** | Security maturity assessment | Assess and improve security practices maturity |

---

**Last Updated**: 2024-10-24
**Version**: 1.0
**Next Review**: 2025-01-24
**Maintained By**: DevOps Security Team