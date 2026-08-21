<p align="center">
  <img src="assets/banner.png" alt="Anthropic Cybersecurity Skills" width="100%">
</p>

<div align="center">

#  Anthropic Cybersecurity Skills

### The largest open-source cybersecurity skills library for AI agents

[![GARS-2026 Survey](https://img.shields.io/badge/GARS--2026-Take%20the%20Survey-E8B84B?style=for-the-badge&logo=googleforms&logoColor=black)](https://mahipal.engineer/survey?utm_source=github_badge&utm_medium=readme&utm_campaign=gars2026)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE)
[![Skills](https://img.shields.io/badge/skills-817-brightgreen?style=flat-square)](#whats-inside--29-security-domains)
[![Frameworks](https://img.shields.io/badge/frameworks-6-orange?style=flat-square)](#six-frameworks-one-skill-library)
[![MITRE F3](https://img.shields.io/badge/MITRE-F3_v1.1-blue?style=flat-square)](https://ctid.mitre.org/fraud/)
[![Domains](https://img.shields.io/badge/domains-29-9cf?style=flat-square)](#whats-inside--29-security-domains)
[![Platforms](https://img.shields.io/badge/platforms-26%2B-blueviolet?style=flat-square)](#compatible-platforms)
[![GitHub stars](https://img.shields.io/github/stars/mukul975/Anthropic-Cybersecurity-Skills?style=flat-square)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mukul975/Anthropic-Cybersecurity-Skills?style=flat-square)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/network/members)
[![Last Commit](https://img.shields.io/github/last-commit/mukul975/Anthropic-Cybersecurity-Skills?style=flat-square)](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/commits/main)
[![agentskills.io](https://img.shields.io/badge/standard-agentskills.io-ff6600?style=flat-square)](https://agentskills.io)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
[![Playground](https://img.shields.io/badge/Playground-Casky.ai-blue)](https://casky.ai/?utm_source=github&utm_medium=readme&utm_campaign=cohort_launch#waitlist)
[![Hermes Agent](https://img.shields.io/badge/Hermes_Agent-compatible-blueviolet?style=flat)](https://github.com/NousResearch/hermes-agent)


**817 production-grade cybersecurity skills · 29 security domains · 6 framework mappings · 26+ AI platforms**

[Get Started](#quick-start) · [What's Inside](#whats-inside--29-security-domains) · [Frameworks](#six-frameworks-one-skill-library) · [Platforms](#compatible-platforms) · [Contributing](#contributing)

</div>

---

> ⚠️ **Community Project** — This is an independent, community-created project. Not affiliated with Anthropic PBC.
>
> 🔐 **Authorized & lawful use only.** This library includes offensive and dual-use techniques (e.g. red-team C2, phishing simulation, exploitation) intended for **authorized penetration testing, security research, defense, and education**. Only use them against systems you own or have **explicit written permission** to test, and comply with all applicable laws and rules of engagement. You are solely responsible for how you use these skills. See [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Give any AI agent the security skills of a senior analyst

A junior analyst knows which Volatility3 plugin to run on a suspicious memory dump, which Sigma rules catch Kerberoasting, and how to scope a cloud breach across three providers. **Your AI agent doesn't — unless you give it these skills.**

This repo contains **817 structured cybersecurity skills** spanning **29 security domains**, each following the [agentskills.io](https://agentskills.io) open standard.  The library maps across **six industry frameworks** — MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, and the MITRE Fight Fraud Framework (F3) — with each skill mapped to the frameworks **relevant to its type** (a forensics skill carries ATT&CK + CSF; an AI-security skill adds ATLAS and AI RMF).  Clone it, point your agent at it, and your next security investigation gets expert-level guidance in seconds.

## Six frameworks, one skill library

Each skill maps to the frameworks that fit its subject — ATT&CK and NIST CSF are near-universal, while ATLAS, AI RMF, D3FEND, and F3 apply where they're relevant. **Framework coverage across the 817 skills:** MITRE ATT&CK **805** · NIST CSF 2.0 **804** · MITRE D3FEND **139** · NIST AI RMF **97** · MITRE F3 **94** · MITRE ATLAS **93**.

| Framework | Version | Framework scope | What it maps |
|---|---|---|---|
| [MITRE ATT&CK](https://attack.mitre.org) | v19.1 | 15 tactics · Enterprise/Mobile/ICS | Adversary behaviors and TTPs |
| [NIST CSF 2.0](https://www.nist.gov/cyberframework) | 2.0 | 6 functions · 22 categories · 106 subcategories | Organizational security posture |
| [MITRE ATLAS](https://atlas.mitre.org) | 2026.07 | 101 techniques · 77 sub-techniques | AI/ML adversarial threats |
| [MITRE D3FEND](https://d3fend.mitre.org) | v1.4.0 | 270 techniques | Defensive countermeasures |
| [NIST AI RMF](https://airc.nist.gov/AI_RMF) | 1.0 | 4 functions (Govern/Map/Measure/Manage) | AI risk management |
| [MITRE F3 (Fight Fraud Framework)](https://ctid.mitre.org/fraud/) | v1.1 (2026-04-09) | 8 tactics · 123 techniques · 94 fraud-relevant skills | Cyber-enabled financial fraud TTPs |

**Example — each skill maps only to the frameworks relevant to it (one may hit all six, another just a couple):**

| Skill | ATT&CK | NIST CSF | ATLAS | D3FEND | AI RMF | F3 |
|---|---|---|---|---|---|---|
| `analyzing-network-traffic-of-malware` | T1071 | DE.CM | AML.T0047 | D3-NTA | MEASURE-2.6 | — |
| `detecting-business-email-compromise` | T1566 | DE.AE | — | — | — | F1005.006 · monetization |

### 🆕 MITRE Fight Fraud Framework (F3) — 94 fraud-relevant skills

[![MITRE F3](https://img.shields.io/badge/MITRE-F3_v1.1-blue?style=flat-square)](https://ctid.mitre.org/fraud/)

The **[MITRE Fight Fraud Framework (F3)](https://ctid.mitre.org/fraud/)** was released **April 9, 2026** by MITRE's Center for Threat-Informed Defense (CTID), co-developed with JPMorganChase, Citigroup, Lloyds Banking Group, Standard Chartered, CrowdStrike, Verizon Business, FS-ISAC, and others. It is an ATT&CK-compatible TTP catalog for **cyber-enabled financial fraud** — filling the gap ATT&CK leaves after initial compromise.

F3 v1.1 adds **two fraud-specific tactics** that ATT&CK does not enumerate:
- **Positioning** (`FA0001`) — actions taken after access to collect/manipulate data and prepare the fraud (synthetic-identity seeding, account warming, beneficiary setup, SIM-swap pre-positioning, banking-session hijack).
- **Monetization** (`FA0002`) — converting stolen assets into usable funds (money-mule layering, APP fraud, crypto off-ramping, card cash-out, refund/chargeback abuse).

Fraud-specific techniques use `F1XXX` IDs (e.g. `F1005.003` Add Beneficiary, `F1025.003` Wire Transfer, `F1007` Adversary-in-the-Browser); reused ATT&CK techniques keep their `T1XXX` IDs. Mappings live in each skill's `mitre_f3:` frontmatter block — all 123 F3 v1.1 technique IDs were verified against the upstream STIX bundle. See [`docs/mitre-f3-mapping.md`](docs/mitre-f3-mapping.md) for the schema.

### MITRE ATT&CK v19.1 — 805/817 skills mapped

Every skill carries a `mitre_attack` frontmatter list validated against **MITRE ATT&CK v19.1** (the latest release) using the official `mitreattack-python` library — 290 distinct techniques and sub-techniques (146 base + 144 sub) across Enterprise, ICS, and Mobile. Zero revoked or deprecated IDs. v19.1's restructured Defense Evasion (now split into **Stealth** and **Defense Impairment**) is reflected below.

| Tactic | ID | Skills |
|--------|----|--------|
| Reconnaissance | TA0043 | 103 |
| Resource Development | TA0042 | 22 |
| Initial Access | TA0001 | 467 |
| Execution | TA0002 | 350 |
| Persistence | TA0003 | 444 |
| Privilege Escalation | TA0004 | 464 |
| Stealth | TA0005 | 442 |
| Defense Impairment | TA0112 | 92 |
| Credential Access | TA0006 | 202 |
| Discovery | TA0007 | 237 |
| Lateral Movement | TA0008 | 68 |
| Collection | TA0009 | 172 |
| Command and Control | TA0011 | 123 |
| Exfiltration | TA0010 | 82 |
| Impact | TA0040 | 50 |

## Quick start

```bash
# Option 1: npx (recommended)
npx skills add mukul975/Anthropic-Cybersecurity-Skills

# Option 2: Git clone
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills
```

Works immediately with Claude Code, GitHub Copilot, OpenAI Codex CLI, Cursor, Gemini CLI, and any [agentskills.io](https://agentskills.io)-compatible platform. 

## Backend verification for live agent builds

If you are using the bundled agent/runtime in this repo, do not trust backend changes by vibe alone.

Verification rule:

- force the backend explicitly with `AGENT_BACKEND`
- run the end-to-end harness before calling a backend change good
- treat provider quota blocks as **blocked**, not as false passes

Quick local truth check:

```bash
.venv/bin/python tools/cyberagent-doctor.py
```

Full live verification:

```bash
.venv/bin/python tools/cyberagent-doctor.py --live
```

After committing, check whether the branch is still only local:

```bash
.venv/bin/python tools/publish-status.py
```

Push when the doctor is green, the working tree is clean, and the publish
status says the branch is ready. Commit means saved locally; push means sent to
GitHub.

Named smoke scenarios:

- `exact-load-skill`
- `search-then-load`

See [`tools/README.md`](tools/README.md) for the verification harness details.

## 🌍 GARS-2026 — Global Agentic AI Readiness Survey

I'm running a global academic study measuring how ready security professionals,
developers, and enterprise teams actually are for agentic AI — MCP servers,
tool calling, governance, and human-in-the-loop workflows.

**If you use this repo, your response would be a genuinely valuable data point.**

📋 **Take the survey (10 min):**
[Survey Link](https://mahipal.engineer/survey?utm_source=github_repo&utm_medium=readme&utm_campaign=gars2026)

- 60 questions · Anonymous · Supervised by SRH Berlin
- You get **50 Casky Tokens** for early access to [casky.ai](https://casky.ai)
- Results published open access under CC-BY 4.0

## 🚀 Try it on the Playground

Experience Casky.ai hands-on — no setup required.

**[→ Launch Playground on Casky.ai](https://casky.ai/?utm_source=github&utm_medium=readme&utm_campaign=cohort_launch#waitlist)**

The playground lets you:
- Run live cybersecurity skill exercises against real targets
- See AI agents execute structured skills in real time
- Explore MITRE ATT&CK mapped workflows interactively
- Test threat hunting, DFIR, and penetration testing scenarios

No installation. No configuration. Just open and start.
## Why this exists

The cybersecurity workforce gap hit **4.8 million unfilled roles** globally in 2024 (ISC2). AI agents can help close that gap — but only if they have structured domain knowledge to work from. Today's agents can write code and search the web, but they lack the practitioner playbooks that turn a generic LLM into a capable security analyst.

Existing security tool repos give you wordlists, payloads, or exploit code. None of them give an AI agent the structured decision-making workflow a senior analyst follows: when to use each technique, what prerequisites to check, how to execute step-by-step, and how to verify results. That is the gap this project fills.

**Anthropic Cybersecurity Skills** is not a collection of scripts or checklists. It is an **AI-native knowledge base** built from the ground up for the agentskills.io standard  — YAML frontmatter for sub-second discovery, structured Markdown for step-by-step execution, and reference files for deep technical context.  Every skill encodes real practitioner workflows, not generated summaries. 

## What's inside — 29 security domains

| Domain | Skills | Key capabilities |
|---|---|---|
| Cloud Security | 66 | AWS, Azure, GCP hardening · CSPM · cloud attack emulation · cloud forensics |
| Threat Hunting | 58 | Hypothesis-driven hunts · LOTL detection · EVTX hunting · fleet hunting |
| Threat Intelligence | 52 | STIX/TAXII · MISP · OpenCTI · feed integration · actor profiling |
| Network Security | 43 | IDS/IPS · firewall rules · VLAN segmentation · traffic analysis |
| Web Application Security | 42 | OWASP Top 10 · SQLi · XSS · SSRF · deserialization |
| Digital Forensics | 41 | Disk imaging · memory forensics · Hayabusa/KAPE/Plaso timelines |
| Malware Analysis | 39 | Static/dynamic analysis · reverse engineering · sandboxing |
| Identity & Access Management | 37 | Entra ID/ROADtools · device-code phishing · PAM · zero trust identity |
| SOC Operations | 35 | Playbooks · escalation workflows · Graph-log detection · tabletop exercises |
| Red Teaming | 33 | ADCS/Certipy · BloodHound CE · Sliver/Havoc C2 · NTLM relay |
| Container Security | 33 | K8s RBAC · image scanning · Falco · container escape |
| Security Operations | 28 | SIEM correlation · log analysis · alert triage |
| OT/ICS Security | 28 | Modbus · DNP3 · IEC 62443 · historian defense · SCADA |
| API Security | 28 | GraphQL · REST · OWASP API Top 10 · WAF bypass |
| Incident Response | 26 | Breach containment · ransomware response · IR playbooks |
| Vulnerability Management | 25 | Nessus · scanning workflows · patch prioritization · CVSS |
| Penetration Testing | 21 | Network · web · cloud · mobile · NetExec lateral movement |
| DevSecOps | 18 | CI/CD security · Trivy IaC/image scanning · code signing |
| Zero Trust Architecture | 17 | BeyondCorp · CISA maturity model · microsegmentation |
| Endpoint Security | 17 | EDR · LOTL detection · fileless malware · persistence hunting |
| Cryptography | 16 | TLS · Ed25519 · post-quantum migration · key management |
| Phishing Defense | 15 | Email authentication · BEC detection · phishing IR |
| AI Security | 14 | LLM red-teaming (garak/PyRIT) · prompt injection · MCP/agentic security · guardrails |
| Mobile Security | 13 | Android/iOS analysis · mobile pentesting · MDM forensics |
| Ransomware Defense | 13 | Precursor detection · response · recovery · encryption analysis |
| Compliance & Governance | 9 | NIST 800-30/RMF · CMMC · HIPAA · TPRM · CIS benchmarks |
| Supply Chain Security | 8 | SBOMs · dependency confusion · malicious-package triage · SLSA/Sigstore |
| Deception Technology | 6 | Honeytokens · canarytokens · breach detection |
| Hardware & Firmware Security | 4 | CHIPSEC/UEFI audit · Secure Boot bypass · TPM attestation · bootkit hunting |

## How AI agents use these skills

Each skill costs **~30 tokens to scan** (frontmatter only)  and **500–2,000 tokens to fully load** (complete workflow). This progressive disclosure architecture lets agents search all 817 skills in a single pass without blowing context windows. 

```
User prompt: "Analyze this memory dump for signs of credential theft"

Agent's internal process:

  1. Scans 817 skill frontmatters (~30 tokens each)
     → identifies 12 relevant skills by matching tags, description, domain

  2. Loads top 3 matches:
     • performing-memory-forensics-with-volatility3
     • hunting-for-credential-dumping-lsass
     • analyzing-windows-event-logs-for-credential-access

  3. Executes the structured Workflow section step-by-step
     → runs Volatility3 plugins, checks LSASS access patterns,
        correlates with event log evidence

  4. Validates results using the Verification section
     → confirms IOCs, maps findings to ATT&CK T1003 (Credential Dumping)
```

**Without these skills**, the agent guesses at tool commands and misses critical steps. **With them**, it follows the same playbook a senior DFIR analyst would use. 

## Skill anatomy

Every skill follows a consistent directory structure:

```
skills/performing-memory-forensics-with-volatility3/
├── SKILL.md              ← Skill definition (YAML frontmatter + Markdown body)
├── references/
│   ├── standards.md      ← MITRE ATT&CK, ATLAS, D3FEND, NIST mappings
│   └── workflows.md      ← Deep technical procedure reference
├── scripts/
│   └── process.py        ← Working helper scripts
└── assets/
    └── template.md       ← Filled-in checklists and report templates
```


### YAML frontmatter (real example)

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


### Markdown body sections

```markdown
## When to Use
Trigger conditions — when should an AI agent activate this skill?

## Prerequisites
Required tools, access levels, and environment setup.

## Workflow
Step-by-step execution guide with specific commands and decision points.

## Verification
How to confirm the skill was executed successfully.
```

Frontmatter fields: `name` (kebab-case, 1–64 chars), `description` (keyword-rich for agent discovery), `domain`, `subdomain`, `tags`,  `atlas_techniques` (MITRE ATLAS IDs), `d3fend_techniques` (MITRE D3FEND IDs), `nist_ai_rmf` (NIST AI RMF references), `nist_csf` (NIST CSF 2.0 categories).  MITRE ATT&CK technique mappings are documented in each skill's `references/standards.md` file and in the ATT&CK Navigator layer included with releases. 

<details>
<summary><strong>📊 MITRE ATT&CK Enterprise coverage — all 15 tactics</strong></summary>

&nbsp;

| Tactic | ID | Coverage | Key skills |
|---|---|---|---|
| Reconnaissance | TA0043 | Strong | OSINT, subdomain enumeration, DNS recon |
| Resource Development | TA0042 | Moderate | Phishing infrastructure, C2 setup detection |
| Initial Access | TA0001 | Strong | Phishing simulation, exploit detection, forced browsing |
| Execution | TA0002 | Strong | PowerShell analysis, fileless malware, script block logging |
| Persistence | TA0003 | Strong | Scheduled tasks, registry, service accounts, LOTL |
| Privilege Escalation | TA0004 | Strong | Kerberoasting, AD attacks, cloud privilege escalation |
| Stealth | TA0005 | Strong | Obfuscation, rootkit analysis, evasion detection |
| Defense Impairment | TA0112 | Moderate | Impair Defenses (T1562), log/indicator removal, EDR tampering |
| Credential Access | TA0006 | Strong | Mimikatz detection, pass-the-hash, credential dumping |
| Discovery | TA0007 | Moderate | BloodHound, AD enumeration, network scanning |
| Lateral Movement | TA0008 | Strong | SMB exploits, lateral movement detection with Splunk |
| Collection | TA0009 | Moderate | Email forensics, data staging detection |
| Command and Control | TA0011 | Strong | C2 beaconing, DNS tunneling, Cobalt Strike analysis |
| Exfiltration | TA0010 | Strong | DNS exfiltration, DLP controls, data loss detection |
| Impact | TA0040 | Strong | Ransomware defense, encryption analysis, recovery |

An **ATT&CK Navigator layer file** is included in the [v1.0.0 release assets](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/releases/tag/v1.0.0) for visual coverage mapping. 

> **Note:** ATT&CK v19 lands April 28, 2026 — splitting Defense Evasion (TA0005) into two new tactics: *Stealth* and *Impair Defenses*.  Skill mappings will be updated in a forthcoming release.

</details>

<details>
<summary><strong>📊 NIST CSF 2.0 alignment — all 6 functions</strong></summary>

&nbsp;

| Function | Skills | Examples |
|---|---|---|
| **Govern (GV)** | 30+ | Risk strategy, policy frameworks, roles & responsibilities |
| **Identify (ID)** | 120+ | Asset discovery, threat landscape assessment, risk analysis |
| **Protect (PR)** | 150+ | IAM hardening, WAF rules, zero trust, encryption |
| **Detect (DE)** | 200+ | Threat hunting, SIEM correlation, anomaly detection |
| **Respond (RS)** | 160+ | Incident response, forensics, breach containment |
| **Recover (RC)** | 40+ | Ransomware recovery, BCP, disaster recovery |

NIST CSF 2.0 (February 2024) added the **Govern** function  and expanded scope from critical infrastructure to all organizations.  Skill mappings align to all 22 categories and reference 106 subcategories. 

</details>

<details>
<summary><strong>📊 Framework deep dive — ATLAS, D3FEND, AI RMF</strong></summary>

&nbsp;

### MITRE ATLAS 2026.07 — AI/ML adversarial threats
ATLAS maps adversarial tactics, techniques, and case studies specific to AI and machine learning systems. Release 2026.07 covers **101 techniques and 77 sub-techniques** including agentic AI attack vectors added in late 2025: AI agent context poisoning, tool invocation abuse, MCP server compromises, and malicious agent deployment.  Skills mapped to ATLAS help agents identify and defend against threats to ML pipelines, model weights, inference APIs, and autonomous workflows. 

### MITRE D3FEND v1.4.0 — Defensive countermeasures
D3FEND is an NSA-funded knowledge graph of **270 defensive techniques** organized across 7 tactical categories: Model, Harden, Detect, Isolate, Deceive, Evict, and Restore.  Built on OWL 2 ontology, it uses a shared Digital Artifact layer to bidirectionally map defensive countermeasures to ATT&CK offensive techniques.  Skills tagged with D3FEND identifiers let agents recommend specific countermeasures for detected threats.

### NIST AI RMF 1.0 + GenAI Profile (AI 600-1)
The AI Risk Management Framework defines 4 core functions — Govern, Map, Measure, Manage — with **72 subcategories** for trustworthy AI development.  The GenAI Profile (AI 600-1, July 2024) adds **12 risk categories** specific to generative AI, from confabulation and data privacy to prompt injection and supply chain risks.  Colorado's AI Act (effective February 2026) provides a **legal safe harbor** for organizations complying with NIST AI RMF, making these mappings directly relevant to regulatory compliance.

</details>

## Compatible platforms

**AI code assistants**
Claude Code (Anthropic) · GitHub Copilot (Microsoft) · Cursor · Windsurf · Cline · Aider · Continue · Roo Code · Amazon Q Developer · Tabnine · Sourcegraph Cody · JetBrains AI 

**CLI agents**
OpenAI Codex CLI · Gemini CLI (Google) 

**Autonomous agents**
Devin · Replit Agent · SWE-agent · OpenHands 

**Agent frameworks & SDKs**
LangChain · CrewAI · AutoGen · Semantic Kernel · Haystack · Vercel AI SDK · Any MCP-compatible agent 

All platforms that support the [agentskills.io](https://agentskills.io) standard can load these skills with zero configuration. 

## What people are saying

> *"A database of real, organized security skills that any AI agent can plug into and use. Not tutorials. Not blog posts."* 
> — **[Hasan Toor (@hasantoxr)](https://x.com/hasantoxr/status/2033193922349179249)**, AI/tech creator

> *"This is not a random collection of security scripts. It's a structured operational knowledge base designed for AI-driven security workflows."* 
> — **[fazal-sec](https://fazal-sec.medium.com/claude-skills-ai-powered-cybersecurity-the-complete-guide-to-building-intelligent-security-7bb7e9d14c8e)**,  Medium

## Featured in

| Where | Type | Link |
|---|---|---|
| **awesome-agent-skills** | Awesome List (1,000+ skills index) | [VoltAgent/awesome-agent-skills](https://github.com/VoltAgent/awesome-agent-skills) |
| **awesome-ai-security** | Awesome List (AI security tools) | [ottosulin/awesome-ai-security](https://github.com/ottosulin/awesome-ai-security) |
| **awesome-codex-cli** | Awesome List (Codex CLI resources) | [RoggeOhta/awesome-codex-cli](https://github.com/RoggeOhta/awesome-codex-cli) |
| **SkillsLLM** | Skills directory & marketplace | [skillsllm.com/skill/anthropic-cybersecurity-skills](https://skillsllm.com/skill/anthropic-cybersecurity-skills) |
| **Openflows** | Signal analysis & tracking | [openflows.org](https://openflows.org/currency/currents/anthropic-cybersecurity-skills/) |
| **NeverSight skills_feed** | Automated skills index | [NeverSight/skills_feed](https://github.com/NeverSight/skills_feed) |

## Star history

<a href="https://star-history.com/#mukul975/Anthropic-Cybersecurity-Skills&Date">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date&theme=dark" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date" width="100%" />
 </picture>
</a>

## Releases

| Version | Date | Highlights |
|---|---|---|
| [v1.0.0](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/releases/tag/v1.0.0) | March 11, 2026 | 734 skills · 26 domains · MITRE ATT&CK + NIST CSF 2.0 mapping · ATT&CK Navigator layer |

Skills have continued to grow on `main` since v1.0.0 — the library now contains **817 skills** with **6-framework mapping**  (MITRE ATLAS, D3FEND, NIST AI RMF, and the MITRE Fight Fraud Framework added post-release).  Check [Releases](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/releases) for the latest tagged version.

## Contributing

This project grows through community contributions. Here is how to get involved:

**Add a new skill** — Domains like Deception Technology (2 skills) and Compliance & Governance (5 skills) need the most help. Follow the template in [CONTRIBUTING.md](CONTRIBUTING.md) and submit a PR with the title `Add skill: your-skill-name`.

**Improve existing skills** — Add framework mappings, fix workflows, update tool references, or contribute scripts and templates.

**Report issues** — Found an inaccurate procedure or broken script? [Open an issue](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues).

Every PR is reviewed for technical accuracy and agentskills.io standard compliance within 48 hours.  Check [good first issues](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) for a starting point.

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/). By participating, you agree to uphold this code. 

## 🙏 Thanks to our contributors

This library is built by the community. Thank you to everyone who has contributed:

<p align="center">
<a href="https://github.com/mukul975" title="mukul975 — maintainer"><img src="https://github.com/mukul975.png?size=100" width="72" height="72" alt="@mukul975"></a>
<a href="https://github.com/juliosuas" title="juliosuas"><img src="https://github.com/juliosuas.png?size=100" width="72" height="72" alt="@juliosuas"></a>
<a href="https://github.com/andrewibrah" title="andrewibrah"><img src="https://github.com/andrewibrah.png?size=100" width="72" height="72" alt="@andrewibrah"></a>
<a href="https://github.com/Bortlesboat" title="Bortlesboat"><img src="https://github.com/Bortlesboat.png?size=100" width="72" height="72" alt="@Bortlesboat"></a>
<a href="https://github.com/DevRedious" title="DevRedious"><img src="https://github.com/DevRedious.png?size=100" width="72" height="72" alt="@DevRedious"></a>
<a href="https://github.com/ioxoi" title="ioxoi"><img src="https://github.com/ioxoi.png?size=100" width="72" height="72" alt="@ioxoi"></a>
<a href="https://github.com/shanujans" title="shanujans"><img src="https://github.com/shanujans.png?size=100" width="72" height="72" alt="@shanujans"></a>
<a href="https://github.com/nyxst4ck" title="nyxst4ck"><img src="https://github.com/nyxst4ck.png?size=100" width="72" height="72" alt="@nyxst4ck"></a>
</p>

<p align="center"><sub>Ordered by contribution count · see the full <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/graphs/contributors">contributor graph</a></sub></p>

## Community

💬 [Discussions](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/discussions) — Questions, ideas, and roadmap conversations
🐛 [Issues](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues) — Bug reports and feature requests
🔒 [Security Policy](SECURITY.md) — Responsible disclosure process (48-hour acknowledgment) 

## Citation

If you use this project in research or publications:

```bibtex
@software{anthropic_cybersecurity_skills,
  author       = {Jangra, Mahipal},
  title        = {Anthropic Cybersecurity Skills},
  year         = {2026},
  url          = {https://github.com/mukul975/Anthropic-Cybersecurity-Skills},
  license      = {Apache-2.0},
  note         = {817 structured cybersecurity skills for AI agents,
                  mapped to MITRE ATT\&CK, NIST CSF 2.0, MITRE ATLAS,
                  MITRE D3FEND, and NIST AI RMF}
}
```

## License

This project is licensed under the [Apache License 2.0](LICENSE). You are free to use, modify, and distribute these skills in both personal and commercial projects. 

---

<div align="center">

**If this project helps your security work, consider giving it a ⭐**

[⭐ Star](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers) · [🍴 Fork](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/fork) · [💬 Discuss](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/discussions) · [📝 Contribute](CONTRIBUTING.md)

Community project by [@mukul975](https://github.com/mukul975). Not affiliated with Anthropic PBC.

</div>
