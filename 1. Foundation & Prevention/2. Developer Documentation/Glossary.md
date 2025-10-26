# Security Glossary: A Developer's Reference

This comprehensive glossary defines security acronyms and terms you'll encounter throughout our documentation and daily development work. Understanding these terms will help you communicate effectively about security and implement controls correctly.

## How to Use This Glossary

- **Quick Reference**: Look up terms you encounter in security documentation
- **Implementation Guidance**: Understand what security controls actually do
- **Communication**: Speak the same language as security teams
- **Compliance**: Understand requirements for audits and certifications 

## Security Frameworks & Standards

### Core Security Standards
- **ABAC** - **Attribute-Based Access Control** - Access control based on user attributes (department, role, location) rather than just roles
- **AES** - **Advanced Encryption Standard** - Symmetric encryption algorithm used to protect data at rest
- **OAuth** - **Open Authorization** - Protocol allowing applications to access resources on behalf of users without sharing passwords
- **OIDC** - **OpenID Connect** - Authentication layer built on OAuth 2.0
- **OWASP** - **Open Web Application Security Project** - Non-profit foundation providing unbiased, practical, and cost-effective application security guidance

### Compliance Frameworks
- **GDPR** - **General Data Protection Regulation** - EU privacy law protecting personal data
- **CCPA** - **California Consumer Privacy Act** - California state privacy law
- **SOC 2** - **System and Organization Controls 2** - Auditing standard for service organizations
- **ISO 27001** - **International Organization for Standardization 27001** - Information security management standard
- **CIS** - **Center for Internet Security** - Non-profit providing best practices for cybersecurity

### Common Authentication Terms
- **MFA** - **Multi-Factor Authentication** - Requiring two or more verification factors
- **SSO** - **Single Sign-On** - One login for multiple applications
- **SAML** - **Security Assertion Markup Language** - XML-based standard for exchanging authentication data
- **JWT** - **JSON Web Token** - Compact URL-safe means of representing claims to be transferred between parties

## Development & DevOps Security

### Application Security (AppSec)
- **SAST** - **Static Application Security Testing** - Security testing of source code without execution
- **DAST** - **Dynamic Application Security Testing** - Security testing of running applications
- **SCA** - **Software Composition Analysis** - Analyzing third-party components for vulnerabilities
- **IAST** - **Interactive Application Security Testing** - Combines SAST and DAST approaches

### Development Processes
- **CI/CD** - **Continuous Integration/Continuous Deployment** - Automated build, test, and deployment pipeline
- **SDLC** - **Software Development Lifecycle** - Process for planning, creating, testing, and deploying software
- **IaC** - **Infrastructure as Code** - Managing infrastructure through code and automation
- **GitOps** - Using Git as the single source of truth for infrastructure and application configuration

### Security Testing Tools
- **Semgrep** - Static analysis tool for finding security vulnerabilities in code
- **Trivy** - Comprehensive security scanner for containers, infrastructure, and dependencies
- **TruffleHog** - Secret detection tool that finds credentials in code and git history
- **ESLint** - JavaScript linting tool with security rules
- **SonarQube** - Platform for continuous code quality and security testing

## Cloud & Infrastructure Security

### AWS Services & Concepts
- **VPC** - **Virtual Private Cloud** - Isolated network environment in AWS
- **IAM** - **Identity and Access Management** - Service for controlling access to AWS resources
- **EC2** - **Elastic Compute Cloud** - Virtual servers in AWS
- **S3** - **Simple Storage Service** - Object storage service
- **RDS** - **Relational Database Service** - Managed relational database service
- **EKS** - **Elastic Kubernetes Service** - Managed Kubernetes service
- **Security Group** - Virtual firewall for AWS resources

### Network Security
- **NACL** - **Network Access Control List** - Network traffic filtering in AWS VPCs
- **DMZ** - **Demilitarized Zone** - Network segment between internal and external networks
- **VPC Peering** - Private network connection between VPCs
- **Transit Gateway** - Network transit hub that connects VPCs and on-premises networks

### Container & Orchestration
- **Docker** - Platform for developing, shipping, and running applications in containers
- **Kubernetes** - Container orchestration platform for automating deployment and management
- **Pod** - Smallest deployable unit in Kubernetes
- **Namespace** - Virtual cluster within a Kubernetes cluster

## Threats & Vulnerabilities

### Common Attack Types
- **SQL Injection** - Code injection technique that exploits database vulnerabilities
- **XSS** - **Cross-Site Scripting** - Injection of malicious scripts into web applications
- **CSRF** - **Cross-Site Request Forgery** - Attack that forces authenticated users to execute unwanted actions
- **DDoS** - **Distributed Denial of Service** - Attack that overwhelms systems with traffic
- **Zero-Day** - Unknown vulnerability that hasn't been patched

### Vulnerability Management
- **CVE** - **Common Vulnerabilities and Exposures** - List of publicly disclosed cybersecurity vulnerabilities
- **CVSS** - **Common Vulnerability Scoring System** - Method for rating severity of vulnerabilities
- **Patch Management** - Process of applying updates to fix vulnerabilities
- **Vulnerability Scanning** - Automated process of discovering security weaknesses

## Security Controls & Practices

### Access Control
- **RBAC** - **Role-Based Access Control** - Access based on job roles within organization
- **ABAC** - **Attribute-Based Access Control** - Access based on user attributes
- **Least Privilege** - Security principle of granting minimum necessary access
- **Zero Trust** - Security model assuming no implicit trust based on network location

### Encryption & Cryptography
- **TLS** - **Transport Layer Security** - Protocol for secure communication over networks
- **Encryption at Rest** - Protecting data when stored on disk or in databases
- **Encryption in Transit** - Protecting data during transmission
- **Key Rotation** - Process of changing encryption keys regularly
- **HSM** - **Hardware Security Module** - Physical device for cryptographic operations

### Monitoring & Detection
- **SIEM** - **Security Information and Event Management** - System for collecting and analyzing log data
- **IDS/IPS** - **Intrusion Detection System/Intrusion Prevention System** - Systems for detecting/preventing attacks
- **WAF** - **Web Application Firewall** - Firewall that protects web applications
- **EDR** - **Endpoint Detection and Response** - Security solution for endpoints

### Cloud & Infrastructure
- **AWS** - Amazon Web Services
- **AMI** - Amazon Machine Image
- **CDN** - Content Delivery Network
- **CMK** - Customer Master Key
- **EBS** - Elastic Block Store
- **EC2** - Elastic Compute Cloud
- **ECS** - Elastic Container Service
- **EKS** - Elastic Kubernetes Service
- **ELB** - Elastic Load Balancer
- **KMS** - Key Management Service
- **RDS** - Relational Database Service
- **S3** - Simple Storage Service
- **VPC** - Virtual Private Cloud
- **WAF** - Web Application Firewall

### Database & Storage
- **ACID** - Atomicity, Consistency, Isolation, Durability
- **ETCD** - Distributed key-value store (pronounced "et-see-dee")
- **NoSQL** - Not Only SQL
- **OLTP** - Online Transaction Processing
- **RDBMS** - Relational Database Management System

### DevOps & Development
- **Bash** - Bourne Again Shell
- **CLI** - Command Line Interface
- **CI/CD** - Continuous Integration/Continuous Deployment
- **Git** - Distributed version control system
- **IDE** - Integrated Development Environment
- **JSON** - JavaScript Object Notation
- **YAML** - YAML Ain't Markup Language

## Security Terms

### Access Control
- **Authentication** - The process of verifying identity
- **Authorization** - The process of granting or denying permissions
- **Least Privilege** - Security principle of granting minimum necessary access
- **Need-to-Know** - Principle of restricting access based on job requirements
- **Segregation of Duties** - Security practice of separating critical functions

### Cryptography
- **Encryption at Rest** - Protecting data when stored
- **Encryption in Transit** - Protecting data during transmission
- **Hashing** - One-way function for data integrity
- **Key Rotation** - Process of changing encryption keys
- **Symmetric Encryption** - Same key for encryption and decryption
- **Asymmetric Encryption** - Different keys for encryption and decryption

### Threats & Vulnerabilities
- **Attack Vector** - Path or means by which an attacker gains access
- **Breach** - Unauthorized access to data or systems
- **Exploit** - Code or technique that takes advantage of a vulnerability
- **Threat** - Potential cause of an unwanted incident
- **Vulnerability** - Weakness that can be exploited by a threat
- **Zero-Day** - Unknown vulnerability that hasn't been patched

### Network Security
- **DMZ** - Demilitarized Zone (network segment between internal and external networks)
- **Firewall** - Network security device that monitors and filters traffic
- **Intrusion Detection** - System that monitors for malicious activities
- **Microsegmentation** - Network security technique of creating small security zones
- **Network Segmentation** - Division of computer network into smaller segments

### Compliance & Governance
- **Audit Trail** - Record of activities for compliance and security
- **Compliance** - Adherence to laws, regulations, guidelines, and specifications
- **Due Diligence** - Process of researching and gathering information before making a decision
- **Governance** - Framework of rules and practices by which a board ensures accountability
- **Risk Assessment** - Process of identifying, analyzing, and evaluating risks

### Development Security
- **Secure by Design** - Approach where security is built into products from the beginning
- **Security by Default** - Products are secure in their default configuration
- **Secure Coding** - Practice of writing code that follows security guidelines
- **Static Analysis** - Analysis of code without executing it
- **Dynamic Analysis** - Analysis of code while it's running

### Incident Management
- **Breach Notification** - Process of notifying affected parties of a data breach
- **Containment** - Process of limiting the scope of an incident
- **Eradication** - Process of removing the cause of an incident
- **Incident Response** - Organized approach to addressing and managing security incidents
- **Recovery** - Process of returning to normal operations after an incident

### Authentication & Identity
- **Biometrics** - Biological measurements used for identification
- **Credentials** - Information used to verify identity (username/password, certificates, etc.)
- **Identity** - Information that uniquely describes an entity
- **Passwordless** - Authentication methods that don't use passwords
- **Single Sign-On** - Authentication process allowing access to multiple systems with one login

### Data Protection
- **Data Classification** - Process of categorizing data based on sensitivity
- **Data Masking** - Process of hiding original data with modified content
- **Data Retention** - Policies governing how long data is kept
- **PII** - Information that can be used to identify an individual
- **Right to be Forgotten** - Right to have personal data deleted upon request

## Cloud-Specific Terms

### AWS
- **Availability Zone** - Distinct location within an AWS Region
- **Instance** - Virtual server in the AWS Cloud
- **Region** - Geographic area where AWS data centers are located
- **Security Group** - Virtual firewall for instances to control inbound and outbound traffic
- **Snapshot** - Point-in-time backup of volumes

### Containers & Orchestration
- **Container** - Standard unit of software that packages up code and dependencies
- **Container Image** - Read-only template used to create containers
- **Docker** - Platform for developing, shipping, and running applications in containers
- **Kubernetes** - Container orchestration platform for automating deployment and management
- **Pod** - Smallest deployable unit in Kubernetes

## Compliance Framework Terms

### ISO 27001
- **Annex A** - Set of controls for information security management
- **ISMS** - Information Security Management System
- **Statement of Applicability** - Document outlining which controls are applicable and why

### SOC 2
- **Common Criteria** - Security criteria common to all SOC 2 reports
- **Trust Services Criteria** - Set of criteria used to evaluate systems
- **Type I Report** - Report on controls at a specific point in time
- **Type II Report** - Report on controls over a period of time

---

**Note:** This glossary is a living document and will be updated as new terms and technologies are introduced to our security standards.

**Last Updated:** [Current Date]
**Next Review Date:** [Quarterly Schedule]
**Maintained By:** Security Team