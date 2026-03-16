<p align="center">
  <img src="assets/banner.png" alt="HRD Security Skills" width="600">
</p>

<p align="center">
  <strong>730+ cybersecurity skills for AI agents &middot; agentskills.io open standard</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg?style=flat" alt="License"></a>
  <img src="https://img.shields.io/badge/skills-730%2B-brightgreen?style=flat" alt="Skills Count">
  <img src="https://img.shields.io/github/stars/HRD-Security/skills?style=flat" alt="Stars">
  <img src="https://img.shields.io/github/last-commit/HRD-Security/skills?style=flat" alt="Last Commit">
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/standard-agentskills.io-purple?style=flat" alt="Agent Skills"></a>
  <img src="https://img.shields.io/badge/platforms-26%2B-orange?style=flat" alt="Platforms">
</p>

---

> **Fork Notice**: This repository is a fork of [mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills), extended with security governance, compliance, and architecture skills aligned with enterprise security management systems.

An open-source collection of cybersecurity skills for AI agents. Every skill follows the [agentskills.io](https://agentskills.io) open standard and works with Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor, Gemini CLI, and 20+ other platforms.

## Quick Start

**Method 1: npx skills**
```bash
npx skills add HRD-Security/skills
```

**Method 2: Claude Code plugin**
```
/plugin marketplace add HRD-Security/skills
```

**Method 3: Manual clone**
```bash
git clone https://github.com/HRD-Security/skills.git
```

## Skill Categories

| Category | Skills | Example Skills |
|----------|-------:|----------------|
| Cloud Security | 48 | AWS S3 Bucket Audit, Azure AD Configuration, GCP Security Assessment |
| Threat Intelligence | 43 | APT Group Analysis with MITRE Navigator, Campaign Attribution, Dark Web Monitoring |
| Web Application Security | 41 | HTTP Request Smuggling, XSS with Burp Suite, Web Cache Poisoning |
| Threat Hunting | 35 | Credential Dumping Detection, DNS Tunneling with Zeek, Living-off-the-Land Binaries |
| Malware Analysis | 34 | Cobalt Strike Beacon Config, Ghidra Reverse Engineering, YARA Rule Development |
| Digital Forensics | 34 | Disk Imaging with dd/dcfldd, Memory Forensics with Volatility3, Browser Forensics |
| SOC Operations | 33 | Windows Event Log Analysis, Splunk Detection Rules, SIEM Use Case Implementation |
| Network Security | 33 | Wireshark Traffic Analysis, VLAN Segmentation, Suricata IDS Configuration |
| Identity & Access Management | 33 | SAML SSO with Okta, Privileged Access Management, RBAC for Kubernetes |
| OT/ICS Security | 28 | SCADA System Attack Detection, Modbus Anomaly Detection, Purdue Model Segmentation |
| API Security | 28 | API Enumeration Detection, BOLA Exploitation, GraphQL Security Assessment |
| Container Security | 26 | Trivy Image Scanning, Falco Runtime Detection, Kubernetes Pod Security |
| Vulnerability Management | 24 | DefectDojo Dashboard, CVSS Scoring, Patch Management Workflow |
| Red Teaming | 24 | Sliver C2 Framework, BloodHound AD Analysis, Kerberoasting with Impacket |
| Incident Response | 24 | Ransomware Response, Cloud Incident Containment, Volatile Evidence Collection |
| Penetration Testing | 23 | External Network Pentest, Kubernetes Pentest, Active Directory Pentest |
| Zero Trust Architecture | 17 | HashiCorp Boundary, Zscaler ZTNA, BeyondCorp Access Model |
| Endpoint Security | 16 | CIS Benchmark Hardening, Windows Defender Configuration, Host-Based IDS |
| DevSecOps | 16 | GitLab CI Pipeline, Semgrep Custom SAST Rules, Secret Scanning with Gitleaks |
| Phishing Defense | 16 | Email Header Analysis, GoPhish Simulation, DMARC/DKIM/SPF Configuration |
| Cryptography | 13 | TLS 1.3 Configuration, HSM Key Storage, Certificate Authority with OpenSSL |
| Mobile Security | 12 | iOS App Analysis with Objection, Android Malware Reverse Engineering, Frida Hooking |
| Ransomware Defense | 5 | Ransomware Precursor Detection, Backup Strategy, Honeypot Detection |
| Compliance & Governance | 5 | GDPR Data Protection, ISO 27001 ISMS, PCI DSS Controls |
| Security Governance | 12 | Policy Authoring, Executive Reporting, AI Governance, Compliance Validation |
| Security Architecture | 6 | Zero Trust Review, Identity Architecture, Network Segmentation, Data Protection |
| Detection & Response | 6 | Detection Engineering, Threat Intelligence, Threat Modeling, Purple Team |

## How It Works

Each skill follows the [agentskills.io](https://agentskills.io) **progressive disclosure** pattern. During discovery, an AI agent reads only the YAML frontmatter (~30-50 tokens) to decide relevance:

```yaml
---
name: performing-memory-forensics-with-volatility3
description: Analyze memory dumps to extract processes, network connections, and malware artifacts using Volatility3.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response]
---
```

If the skill matches the task, the agent loads the full body -- workflow steps, prerequisites, tool commands, and verification checks -- without wasting tokens on irrelevant skills.

## Compatible Platforms

These skills work with any tool that supports the agentskills.io standard or can read structured Markdown:

| Platform | Integration |
|----------|------------|
| **Claude Code** | Native skill loading via `/plugin` |
| **GitHub Copilot** | Workspace context via `.skills/` directory |
| **OpenAI Codex CLI** | File-based context injection |
| **Cursor** | Project rules and docs integration |
| **Gemini CLI** | Context file loading |
| **Amp** | Skill directory mounting |
| **Goose** | Plugin-based skill loading |
| **Windsurf** | Context awareness from project files |
| **Aider** | Repository map integration |
| **Continue** | Custom context providers |
| And 16+ others | Any agent that reads structured Markdown |

## Skill Anatomy

Every skill follows a consistent directory structure:

```
skills/{skill-name}/
├── SKILL.md            # Skill definition with YAML frontmatter
│   ├── Frontmatter     # name, description, domain, subdomain, tags
│   ├── When to Use     # Trigger conditions for AI agents
│   ├── Prerequisites   # Required tools and access
│   ├── Workflow         # Step-by-step execution guide
│   └── Verification    # How to confirm success
├── references/
│   ├── standards.md    # NIST, MITRE ATT&CK, CVE references
│   └── workflows.md    # Deep technical procedure reference
├── scripts/
│   └── process.py      # Practitioner helper scripts
└── assets/
    └── template.md     # Checklists and report templates
```

## Contributing

We welcome contributions from the cybersecurity community. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new skills, improving existing ones, and our review process.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=HRD-Security/skills&type=Date)](https://star-history.com/#HRD-Security/skills&Date)

## License

<a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg?style=flat" alt="License"></a>

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
