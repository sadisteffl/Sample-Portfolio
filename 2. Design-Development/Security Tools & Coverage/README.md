# Security Tools & Coverage

This directory contains documentation about our security tooling strategy, coverage areas, and implementation guidance for shift-left security.

## Contents

### [Security Tools Coverage Model](Security%20Tools%20Coverage%20Model.md)
Comprehensive guide to our minimal yet comprehensive 3-tool stack that provides optimal coverage across all critical security domains.

## Key Philosophy

- **Minimal Toolset**: Maximize coverage with minimal tools
- **Open Source Priority**: All tools are actively maintained, open-source projects
- **Shift-Left Focus**: Detect issues early in the development lifecycle
- **Developer Integration**: Tools integrate seamlessly with existing workflows

## Core Security Stack

1. **Semgrep** - Static Analysis & Supply Chain Security
2. **Trivy** - Container & Infrastructure Scanning
3. **TruffleHog** - Secrets Detection

## Getting Started

1. Read the [Security Tools Coverage Model](Security%20Tools%20Coverage%20Model.md) for an overview
2. Set up local development tools in [Development Integration](../Development%20Integration/)
3. Follow the checklists in [Process & Checklists](../Process%20&%20Checklists/)

## Related Resources

- [Development Integration](../Development%20Integration/) - IDE setup and local tools
- [Process & Checklists](../Process%20&%20Checklists/) - Security processes and checklists
- [Developer Documentation](../1.%20Foundation%20&%20Prevention/2.%20Developer%20Documentation/) - Security standards and guides

---

**Last Updated**: 2024-10-24
**Maintained By**: Security Engineering Team