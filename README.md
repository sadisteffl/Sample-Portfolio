# Overview: Sadi's Guidebook to Shifting Left

This guidebook introduces my comprehensive security philosophy: **prevent security issues before they exist** by making secure choices the easiest choices.

My approach uses automation to embed security directly into development workflows, reducing manual overhead and accelerating launch times. The code within this repo is primarily Terraform and Kubernetes YAML, managed via Git, reflecting the tools required for modern security engineering. All standards are designed with ISO 27001 and SOC 2 compliance requirements built-in.

## The Shift-Left Security Lifecycle

This guidebook follows a **shift-left security philosophy** that prioritizes prevention over detection. The six phases progress from most proactive (left) to most reactive (right), creating a comprehensive security program where each phase builds upon previous ones.

### 🛡️ Phase 1: Foundation & Prevention
**Building security culture and standards before code is written**
- Security training and culture programs
- Organizational security policies and frameworks
- Developer documentation and standards

### 🏗️ Phase 2: Design & Development
**Integrating security into architecture and development processes**
- Security tools and coverage strategy
- Development integration and IDE setup
- Security processes and checklists
- Secure coding standards and guidelines

### 🧪 Phase 3: Testing & Validation
**Comprehensive security testing throughout development lifecycle**
- Security testing workflows and validation
- Vulnerability management processes
- Automated and manual testing procedures
- Continuous security verification

### ⚙️ Phase 4: Deployment & Operations
**Securing deployment pipeline and production environments**
- Infrastructure hardening and configuration
- Container and Kubernetes security
- Runtime protection and monitoring
- Continuous security validation

### ⚖️ Phase 5: Governance & Compliance
**Security governance framework and compliance management**
- Regulatory compliance and risk management
- Security policies and standards
- Audit and assurance processes
- Continuous compliance monitoring

### 🚨 Phase 6: Operations & Response
**Security operations and incident response capabilities**
- Threat intelligence and monitoring
- Incident response and recovery
- Security metrics and reporting
- Continuous improvement processes

---

## 1. Foundation & Prevention

This phase represents the **most proactive** stage in our security lifecycle, where we focus on preventing security issues before they can even be created by building a strong security culture and comprehensive organizational frameworks.

### 1. Security Training & Culture

This directory establishes a comprehensive security training and culture framework designed to embed security into the organizational DNA. By developing security expertise across all teams and fostering a security-first mindset, this program transforms security from a compliance requirement into a competitive advantage.

**Key Components:**
- **Security Champions Program**: Empowers developers to become security advocates within their teams
- **Developer Security Onboarding**: Comprehensive curriculum for new engineers joining the organization
- **Gamification & Recognition**: Incentivizes secure behaviors and vulnerability discovery
- **Continuous Awareness**: Ongoing security education content and campaigns
- **Role-Specific Training**: Tailored security curriculum for different engineering roles

**Why This Matters:** A strong security culture is the foundation of any effective security program. When security becomes part of the organizational DNA, developers naturally make secure choices without additional overhead.

---

## 2. Design & Development

This phase focuses on integrating security into the architecture and development processes where we can catch and fix issues early, when they're cheapest and fastest to resolve through automated security controls and developer-friendly standards.

### 1. Developer Documentation Standards

This comprehensive documentation suite provides engineers with clear, actionable guidance for building secure, compliant, and resilient systems. Each standard is designed to be immediately useful rather than just theoretical.

**Core Security Standards:**
- **Secure Coding Standard**: Practical guidelines for writing secure code across multiple languages, with real examples and common pitfalls to avoid
- **API Security Standard**: Step-by-step guidance for securing REST, GraphQL, and gRPC APIs with implementation examples
- **Database Security Standard**: Actionable controls for protecting data in relational and NoSQL databases
- **Container Security Standard**: Container-specific security practices from image building to runtime protection

**Infrastructure & Platform Security:**
- **Network Security Standard**: Clear network segmentation, firewall rules, and monitoring practices
- **Identity & Access Management**: Authentication, authorization, and privileged access management guidelines
- **Data Security & Privacy**: Data classification, encryption, and privacy compliance requirements

**Quick References:**
- **Security Glossary**: 100+ defined terms and acronyms with context
- **Quick Reference Cards**: Daily security checklists and critical requirements

### 2. IDE Security Tooling

Comprehensive security scanning tools integrated directly into the development environment, providing immediate feedback to developers as they code.

**Available Tools:**
- **Semgrep**: Static code analysis for OWASP Top 10 vulnerabilities
- **Trivy**: Container, dependency, and infrastructure scanning
- **TruffleHog**: Secret detection across git history and file system
- **GitHub Actions**: Automated security workflows with branch protection

### 3. Application Security Checklist

A practical checklist that guides developers through essential security tasks across the entire software development lifecycle, from initial design to post-deployment operations.

**Security Activities:**
- **Design Phase**: Threat modeling, secure architecture patterns
- **Development**: Secure coding practices, dependency scanning
- **Testing**: SAST, DAST, and penetration testing
- **Deployment**: Container scanning, IaC validation
- **Operations**: Logging, monitoring, incident response

### 4. CI/CD Pipeline Security

Security-first CI/CD workflows that embed automated security controls throughout the development lifecycle. By integrating scanning for application code, container images, and Infrastructure as Code, we catch vulnerabilities early.

**Security Controls:**
- **Automated Scanning**: SAST/DAST for code, vulnerability scanning for dependencies
- **Secret Detection**: Prevents credentials from being committed
- **IaC Security**: Scans Terraform and Kubernetes configurations
- **Container Security**: Image vulnerability scanning and runtime protection
- **Branch Protection**: Enforces security checks before merging

---

## 3. Testing & Validation

This phase focuses on comprehensive security testing throughout the development lifecycle, ensuring vulnerabilities are caught early when they're cheapest and fastest to fix through systematic testing and validation procedures.

### Security Testing Workflows
Comprehensive testing procedures to validate our security tools and processes are working effectively. Includes automated tool verification, manual testing procedures, and continuous security validation.

### Vulnerability Management
Systematic approach to identifying, assessing, prioritizing, and remediating security vulnerabilities across our entire technology stack. Includes risk-based prioritization and remediation tracking.

---

## 4. Deployment & Operations

This phase secures the foundational infrastructure and deployment environments where our applications run, implementing security controls at the platform level that automatically enforce security policies.

### 1. Infrastructure Hardening

Terraform modules for IAM password policies and other hardening standards that demonstrate how to bake security directly into cloud infrastructure. This "security-by-default" approach ensures consistency across all accounts, eliminates configuration drift, and simplifies auditing by reducing complex security tasks to reusable modules.

### 2. Control Policies - SCP

Practical Terraform configurations for proactive AWS governance using Service Control Policies. These examples demonstrate implementing high-impact security controls across an AWS Organization, such as preventing IAM privilege escalation and enforcing encryption for data-in-transzmit.

### 3. Kubernetes Security

Comprehensive guide to building a secure Kubernetes ecosystem by embedding security throughout the entire application lifecycle. It emphasizes a proactive approach by integrating vulnerability and secret scanning into CI/CD pipelines, enforcing least privilege with RBAC, hardening pod configurations, and implementing network policies.

### 4. SSM Automation

Serverless, automated security responses that detect and remediate misconfigurations in near real-time. Examples include automated S3 bucket public access remediation using EventBridge, Lambda functions, and SSM Automation documents to enforce security policies without manual overhead.

---

## 5. Governance & Compliance

This phase establishes the security governance structure, compliance requirements, and risk management framework that ensures our security program meets regulatory obligations and business requirements.

### Compliance Management
Regulatory compliance frameworks including ISO 27001, SOC 2, GDPR, and industry-specific requirements like PCI DSS and HIPAA.

### Risk Management
Systematic approach to identifying, assessing, and treating security risks across the organization with continuous monitoring and improvement.

### Policy & Standards Management
Development, maintenance, and enforcement of security policies with regular compliance monitoring and security awareness training.

---

## 6. Operations & Response

This final phase focuses on managing security incidents, monitoring threats, and continuously improving our security posture through comprehensive programs for residual risk management and stakeholder trust.

### 1. Third-Party Risk Management

Comprehensive processes for identifying, assessing, and mitigating risks associated with third-party vendors, suppliers, and technology partners. Essential for maintaining security posture and regulatory compliance in an increasingly interconnected ecosystem.

### 2. Advanced Threat Intelligence

Threat intelligence capability that transforms raw security data into actionable insights, enabling proactive defense against emerging threats through external intelligence integration, security research, and industry collaboration.

### 3. Customer Security Program

Comprehensive approach to customer security that builds trust through transparency, collaboration, and shared security responsibility. Transforms security from a compliance requirement into a competitive advantage that drives customer confidence.

### 4. Incident Response

Comprehensive Incident Response Plan designed to ensure swift, effective, and coordinated response to security breaches. Includes formal Incident Response Team structure, severity classification, communication strategies, and automated Terraform playbooks for rapid containment.

### 5. Security Reporting

Framework for security reporting that combines comprehensive assessment structures with proactive communication strategies. Provides templates for security assessments, multi-audience communication strategies, and automated evidence generation for auditors.

### 6. Security Metrics & KPI

Comprehensive metrics and KPI system to measure, monitor, and improve security program effectiveness. Enables data-driven security decisions, value demonstration, and informed investment prioritization through effectiveness metrics and ROI analysis.

---

# Notes

### Cost

Given the opportunity, I would welcome a discussion with the CTO to provide potential pricing for a full implementation or go over other methods and architectural choices.

### Gaps 

I have also identified several areas that are intentionally not fully built out in this sample but would be critical components of a production-ready environment. These are topics I am prepared to discuss in greater detail:

#### Threat Modeling

Threat modeling is crucial because it helps companies find security problems before building anything. Including threat modeling from the start is important because it's dramatically cheaper and more effective to design security in from the beginning than to try and add it on later. It helps build a fundamentally secure application, rather than just patching holes after they've already been built.

#### Data Security & Governance
Data is the lifeblood of an AI company, so its security and governance are a top-level priority, adding a strategic layer beyond foundational controls like Macie and encryption. A robust data governance program is critical for building and maintaining trust. This starts with clear data classification policies to ensure we understand our data's sensitivity and apply the right protections. It also includes disciplined data lifecycle management to responsibly handle information from creation to secure deletion, which is crucial for minimizing risk when managing vast training datasets. Finally, collaborating with the privacy team on Data Protection Impact Assessments (DPIAs) is non-negotiable. This allows us to proactively identify and mitigate privacy risks before a product launch, ensuring regulatory compliance and demonstrating a deep commitment to customer trust

#### Runtime Security

Runtime security is crucial because it protects companies's application while it's actually running in a live environment. No matter how well the design and scan of the code are before deployment, it's impossible to predict every possible threat. A brand-new vulnerability might be discovered, or an attacker could find a clever way to exploit a minor misconfiguration that only appears in the live system.

Including runtime security from the start is important because it acts as a final and most critical layer of defense. It actively monitors for suspicious behavior - like a container trying to access a file it shouldn't or an application making unexpected network connections - and can block these threats in real-time. Without it, companies would have a major blind spot and be vulnerable to attacks that static checks and firewalls simply cannot see.

---

# Conclusion

This guidebook is more than a collection of configurations and code; it's a practical reflection of my core philosophy. I believe that the concepts we learn and the people we meet within our community have a profound effect on our ability to address the world around us. The most successful people - and the most successful companies - are those who accumulate diverse skills, learn from their mistakes, and are always willing to innovate.

My approach to security is guided by a simple, personal principle: every day is a chance to make things better than they were the day before. I see mistakes and vulnerabilities not as failures, but as opportunities for growth. This is why I am so passionate about the "shift-left" model; it's a software-led initiative that bakes learning and improvement directly into the development process. For me, a successful day is one where I've learned something new while helping my team build more secure, resilient systems.

This mindset directly aligns with my mission to drive progress through software. To build world-changing AI, the underlying security function must be a catalyst, not an obstacle. It must be as agile, automated, and forward-thinking as the technology it protects. My goal is to help build that function - one that empowers engineers, automates compliance, and turns every challenge into a chance to improve.



