<p align="center">
  <img src="assets/banner.png" alt="Anthropic Cybersecurity Skills" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers"><img src="https://img.shields.io/github/stars/mukul975/Anthropic-Cybersecurity-Skills?style=social" alt="Stars"></a>
  <a href="#️-framework-coverage"><img src="https://img.shields.io/badge/frameworks-5%20mapped-brightgreen.svg" alt="Frameworks"></a>
  <a href="#️-whats-inside"><img src="https://img.shields.io/badge/skills-754-orange.svg" alt="Skills"></a>
  <a href="https://agentskills.io"><img src="https://img.shields.io/badge/standard-agentskills.io-purple.svg" alt="agentskills.io"></a>
  <a href="#-compatible-platforms"><img src="https://img.shields.io/badge/platforms-26%2B-blue.svg" alt="Platforms"></a>
</p>

<p align="center">
  <strong>754 production-grade cybersecurity skills for AI agents — mapped to 5 industry frameworks</strong>
</p>

<p align="center">
  <em>MITRE ATT&CK · NIST CSF 2.0 · MITRE ATLAS · MITRE D3FEND · NIST AI RMF</em>
</p>

> ⚠️ **Community Project** — This is an independent, community-created project. Not affiliated with Anthropic PBC.

---
<p align="center">
  <strong>🚀 Learn Claude Cybersecurity Skills (Hands-On)</strong><br>
  Turn these skills into real AI workflows, agents, and SOC execution
</p>

<p align="center">
  👉 <a href="https://casky.ai/?utm_source=github&utm_medium=readme&utm_campaign=cohort_launch#waitlist">Join Casky.AI Cohort</a>  
  📥 <a href="https://casky.ai/resources/top-10-skills?utm_source=github&utm_medium=readme&utm_campaign=top10_skills&utm_content=lead_magnet">Free Download: Top Ten Claude Cybersecurity Skills</a>
</p>


## Why this exists

AI agents are transforming cybersecurity — but they lack structured domain knowledge. A junior analyst knows which Volatility3 plugin to run on a suspicious memory dump. Your AI agent doesn't — unless you give it the skills.

**Anthropic Cybersecurity Skills** gives every AI agent instant access to **754 production-grade cybersecurity skills** spanning 26 security domains. Each skill follows the [agentskills.io](https://agentskills.io) open standard: YAML frontmatter for lightning-fast discovery, structured Markdown for step-by-step execution, and reference files for deep technical context.

**What makes v1.2.0 different from every other security skills repo:**

- **5-framework mapping** — Every skill is mapped to MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS v5.5, MITRE D3FEND v1.3, and NIST AI RMF 1.0. No other open-source library does this.
- **AI-native format** — Skills cost ~30 tokens to scan, provide full expert-level guidance when triggered, and work across 26+ AI agent platforms.
- **Real practitioner knowledge** — Not generated summaries. Structured workflows that mirror how senior security professionals actually work.

## 🚀 Quick start

```bash
# Option 1: npx (recommended)
npx skills add mukul975/Anthropic-Cybersecurity-Skills

# Option 2: Claude Code
/plugin marketplace add mukul975/Anthropic-Cybersecurity-Skills

# Option 3: Manual clone
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills
```

Works immediately with Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor, Gemini CLI, and any MCP-compatible agent.

## 📖 Table of contents

- [🛡️ What's inside](#️-whats-inside)
- [🗺️ Framework coverage](#️-framework-coverage)
- [🤖 Compatible platforms](#-compatible-platforms)
- [📐 Skill structure](#-skill-structure)
- [🧠 How AI agents use these skills](#-how-ai-agents-use-these-skills)
- [📝 Example skills](#-example-skills)
- [👥 Contributing](#-contributing)
- [⭐ Star history](#-star-history)
- [📄 License](#-license)

## 🛡️ What's inside

**754 skills across 26 security domains:**

| Domain | Skills | Example capabilities |
|--------|--------|---------------------|
| ☁️ Cloud Security | 60 | AWS S3 bucket audit, Azure AD config review, GCP IAM assessment |
| 🔍 Threat Hunting | 55 | C2 beaconing detection, DNS tunneling analysis, living-off-the-land |
| 📡 Threat Intelligence | 50 | APT group analysis with MITRE Navigator, campaign attribution, IOC enrichment |
| 🌐 Web Application Security | 42 | HTTP request smuggling, XSS with Burp Suite, web cache poisoning |
| 🔌 Network Security | 40 | Wireshark traffic analysis, VLAN segmentation, Suricata IDS tuning |
| 🦠 Malware Analysis | 39 | Ghidra reverse engineering, YARA rules, .NET decompilation |
| 🔎 Digital Forensics | 37 | Disk imaging with dd/dcfldd, Volatility3 memory forensics, browser artifacts |
| 📊 Security Operations | 36 | SIEM correlation rules, alert triage workflows, SOC playbooks |
| 🔑 IAM Security | 35 | SAML SSO with Okta, PAM deployment, service account hardening |
| 🖥️ SOC Operations | 33 | Tier 1-3 escalation procedures, incident classification, metrics tracking |
| ☸️ Container Security | 30 | Kubernetes RBAC audit, pod security policies, etcd encryption |
| 🏭 OT/ICS Security | 28 | SCADA monitoring, Modbus anomaly detection, Purdue model enforcement |
| 🔗 API Security | 28 | OAuth2 flow analysis, rate limiting, API gateway hardening |
| 🎯 Vulnerability Management | 25 | Nessus scanning, CVSS scoring, risk-based prioritization |
| 🚨 Incident Response | 25 | Containment procedures, evidence preservation, post-incident review |
| 🔴 Red Teaming | 24 | Cobalt Strike operations, LOTL techniques, evasion & persistence |
| 🎯 Penetration Testing | 23 | Active Directory exploitation, OSCP-style methodology, pivoting |
| 💻 Endpoint Security | 17 | EDR deployment, host-based detection, anti-tamper configuration |
| 🔧 DevSecOps | 17 | Pipeline security gates, SAST/DAST integration, IaC scanning |
| 🎣 Phishing Defense | 16 | Email header analysis, phishing simulation, DMARC/DKIM/SPF |
| 🕵️ OSINT | 15 | Domain reconnaissance, social engineering recon, dark web monitoring |
| 🔐 Cryptography | 14 | TLS configuration audit, certificate lifecycle, key management |
| 🏰 Zero Trust | 13 | Microsegmentation, BeyondCorp implementation, continuous verification |
| 📱 Mobile Security | 12 | APK analysis with APKTool, iOS forensics, MDM bypass detection |
| 🛡️ Ransomware Defense | 7 | Backup validation, recovery procedures, negotiation awareness |
| 🪤 Deception Technology | 5 | Honeypot deployment, honey tokens, decoy credential monitoring |
| **TOTAL** | **754** | |

## 🗺️ Framework coverage

v1.2.0 maps every skill to **5 industry-standard frameworks** — a first for any open-source cybersecurity skills library.

### MITRE ATT&CK Enterprise — 754/754 skills mapped

All 14 Enterprise tactics covered with 200+ technique mappings:

| Tactic | ID | Skills |
|--------|----|--------|
| Reconnaissance | TA0043 | 45+ |
| Resource Development | TA0042 | 30+ |
| Initial Access | TA0001 | 55+ |
| Execution | TA0002 | 60+ |
| Persistence | TA0003 | 50+ |
| Privilege Escalation | TA0004 | 55+ |
| Defense Evasion | TA0005 | 65+ |
| Credential Access | TA0006 | 45+ |
| Discovery | TA0007 | 50+ |
| Lateral Movement | TA0008 | 40+ |
| Collection | TA0009 | 35+ |
| Command and Control | TA0011 | 40+ |
| Exfiltration | TA0010 | 30+ |
| Impact | TA0040 | 35+ |

### NIST CSF 2.0 — 754/754 skills aligned

| Function | Skills | Coverage areas |
|----------|--------|---------------|
| Govern (GV) | 80+ | Policy, risk strategy, supply chain oversight |
| Identify (ID) | 120+ | Asset management, risk assessment, improvement |
| Protect (PR) | 150+ | Access control, awareness, data security, platform security |
| Detect (DE) | 200+ | Continuous monitoring, adverse event analysis |
| Respond (RS) | 160+ | Incident management, analysis, mitigation, reporting |
| Recover (RC) | 44+ | Recovery planning, execution, communication |

### 🆕 MITRE ATLAS v5.5 — 81 skills (NEW in v1.2.0)

AI-specific adversarial threat coverage including:
- ML model poisoning and evasion techniques
- AI supply chain compromise scenarios
- LLM prompt injection defense workflows
- AI agent tool abuse detection
- Agentic AI escape-to-host prevention

### 🆕 MITRE D3FEND v1.3 — 139 skills (NEW in v1.2.0)

Defensive technique mappings across all 7 D3FEND tactics:
- **Model** (27 techniques) — Threat modeling, attack surface analysis
- **Harden** (51 techniques) — System hardening, configuration management
- **Detect** (90 techniques) — Monitoring, anomaly detection, behavioral analysis
- **Isolate** (57 techniques) — Segmentation, sandboxing, containment
- **Deceive** (11 techniques) — Honeypots, decoys, misdirection
- **Evict** (19 techniques) — Threat removal, credential rotation
- **Restore** (12 techniques) — Backup, recovery, resilience

### 🆕 NIST AI RMF 1.0 — 85 skills (NEW in v1.2.0)

AI risk management coverage aligned with the four core functions:
- **Govern** — AI governance, accountability, organizational policies
- **Map** — AI system context, risk identification, stakeholder analysis
- **Measure** — AI risk metrics, testing, validation
- **Manage** — AI risk treatment, monitoring, continuous improvement

> 💡 **Why 5 frameworks matter:** Organizations face overlapping compliance requirements. A single skill like "analyzing-network-traffic-of-malware" maps to ATT&CK T1071 (Application Layer Protocol), NIST CSF DE.CM (Continuous Monitoring), ATLAS AML.T0047 (Evade ML Model), D3FEND D3-NTA (Network Traffic Analysis), and AI RMF MEASURE 2.6 (AI system monitoring). One skill, five compliance checkboxes.

## 🤖 Compatible platforms

**AI code assistants:**
Claude Code (Anthropic) · GitHub Copilot (Microsoft) · Cursor · Windsurf · Cline · Aider · Continue · Roo Code · Amazon Q Developer · Tabnine · Sourcegraph Cody · JetBrains AI

**CLI agents:**
OpenAI Codex CLI · Gemini CLI (Google)

**Autonomous agents:**
Devin · Replit Agent · SWE-agent · OpenHands

**Agent frameworks & SDKs:**
LangChain · CrewAI · AutoGen · Semantic Kernel · Haystack · Vercel AI SDK · Any MCP-compatible agent

## 📐 Skill structure

Every skill follows the [agentskills.io](https://agentskills.io) open standard:

```
skills/performing-memory-forensics-with-volatility3/
├── SKILL.md              # Skill definition (YAML frontmatter + Markdown body)
│   ├── Frontmatter       #   → name, description, domain, tags, frameworks
│   ├── When to Use       #   → Trigger conditions for AI agents
│   ├── Prerequisites     #   → Required tools, access, environment
│   ├── Workflow          #   → Step-by-step execution guide
│   └── Verification      #   → How to confirm success
├── references/
│   ├── standards.md      # MITRE ATT&CK, ATLAS, D3FEND, NIST mappings
│   └── workflows.md      # Deep technical procedure reference
├── scripts/
│   └── process.py        # Practitioner helper scripts
└── assets/
    └── template.md       # Checklists, report templates
```

**YAML frontmatter example:**

```yaml
---
name: performing-memory-forensics-with-volatility3
description: >-
  Analyze memory dumps to extract running processes, network connections,
  injected code, and malware artifacts using the Volatility3 framework.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response, dfir]
atlas_techniques: [AML.T0047]
d3fend_techniques: [D3-MA, D3-PSMD]
nist_ai_rmf: [MEASURE-2.6]
nist_csf: [DE.CM-01, RS.AN-03]
version: "1.2"
author: mukul975
license: Apache-2.0
---
```

### Progressive disclosure — why 754 skills don't slow your agent down

| Stage | Token cost | When |
|-------|-----------|------|
| Discovery scan | ~30 tokens | Always — agent reads YAML frontmatter |
| Full skill load | 500–2000 tokens | Only when skill matches the task |
| Deep reference pull | 1000–5000 tokens | Only when agent needs technical depth |

Irrelevant skills cost virtually nothing. Relevant skills provide complete expert-level guidance.

## 🧠 How AI agents use these skills

```
User prompt: "Analyze this memory dump for signs of credential theft"

Agent's internal process:
1. Scans 754 skill frontmatters (~30 tokens each) → finds 12 relevant skills
2. Loads top matches:
   - performing-memory-forensics-with-volatility3
   - hunting-for-credential-dumping-lsass
   - analyzing-windows-event-logs-for-credential-access
3. Follows structured workflow from SKILL.md
4. References ATT&CK T1003 (Credential Dumping) mapping
5. Maps findings to D3FEND D3-PSMD (Process Self-Modification Detection)
6. Outputs structured findings with framework references
```

## 📝 Example skills

<details>
<summary><strong>🔍 Hunting for C2 beaconing</strong></summary>

**Domain:** Threat Hunting · **ATT&CK:** T1071, T1573 · **D3FEND:** D3-NTA · **CSF:** DE.CM-01

Identifies command-and-control communication patterns in network traffic using beacon interval analysis, JA3/JA3S fingerprinting, and DNS request frequency modeling. Includes Zeek scripts for automated detection and SIEM correlation rules.

</details>

<details>
<summary><strong>🦠 Reverse engineering .NET malware with dnSpy</strong></summary>

**Domain:** Malware Analysis · **ATT&CK:** T1027, T1059.001 · **ATLAS:** AML.T0016 · **CSF:** DE.AE-02

Step-by-step decompilation workflow for .NET executables including de-obfuscation techniques, string decryption, C2 extraction, and behavioral analysis. Includes YARA rule templates for family classification.

</details>

<details>
<summary><strong>☸️ Auditing Kubernetes RBAC configurations</strong></summary>

**Domain:** Container Security · **ATT&CK:** T1078.004 · **D3FEND:** D3-ACL · **CSF:** PR.AA-01 · **AI RMF:** GOVERN-1.2

Systematic review of ClusterRoles, RoleBindings, and ServiceAccounts to identify overprivileged workloads, lateral movement paths, and secrets exposure. Includes kubectl audit scripts and remediation playbooks.

</details>

## 👥 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Ways to contribute:**
- 🆕 Add new skills using the [New Skill template](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues/new?template=new-skill.yml)
- 🐛 Report issues with the [Bug Report template](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues/new?template=bug-report.yml)
- 💡 Request features via [Feature Request](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues/new?template=feature-request.yml)
- 📝 Improve documentation or fix typos
- 🗺️ Add framework mappings to existing skills

Every PR gets reviewed for technical accuracy and consistency with the agentskills.io standard. We aim to review within 48 hours.

## ⭐ Star history

[![Star History Chart](https://api.star-history.com/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date)](https://star-history.com/#mukul975/Anthropic-Cybersecurity-Skills&Date)

## 🌐 Community

- 📋 Listed on [SkillsLLM](https://skillsllm.com/skill/anthropic-cybersecurity-skills)
- 📚 Featured in [awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills)
- 🔒 Featured in [awesome-ai-security](https://github.com/ottosulin/awesome-ai-security)
- 🖥️ Featured in [awesome-codex-cli](https://github.com/RoggeOhta/awesome-codex-cli)
- 📖 [Complete guide on Medium](https://fazal-sec.medium.com/claude-skills-ai-powered-cybersecurity-the-complete-guide-to-building-intelligent-security-7bb7e9d14c8e)

## 📄 License

Apache License 2.0 — free for commercial and personal use. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>If these skills help your AI agent defend better, consider giving this repo a ⭐</strong>
</p>

---

<p align="center">
  <strong>🚀 Ready to run these as real AI security workflows?</strong><br><br>

  👉 <a href="https://www.casky.ai?utm_source=github&utm_medium=readme&utm_campaign=bottom_cta">Join Casky.AI</a><br>
  📥 <a href="https://www.casky.ai/top-10-skills?utm_source=github&utm_medium=readme&utm_campaign=bottom_lead">Get the Free Skill Pack</a>
</p>
