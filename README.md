<p align="center">
  <img src="assets/banner.png" alt="Anthropic Cybersecurity Skills — 753 skills for AI agents" width="100%" />
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge" alt="License: Apache 2.0" /></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers"><img src="https://img.shields.io/github/stars/mukul975/Anthropic-Cybersecurity-Skills?style=for-the-badge&logo=github" alt="GitHub Stars" /></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/network/members"><img src="https://img.shields.io/github/forks/mukul975/Anthropic-Cybersecurity-Skills?style=for-the-badge&logo=github" alt="GitHub Forks" /></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/commits"><img src="https://img.shields.io/github/last-commit/mukul975/Anthropic-Cybersecurity-Skills?style=for-the-badge&logo=github" alt="Last Commit" /></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills"><img src="https://img.shields.io/badge/Skills-753-blueviolet?style=for-the-badge&logo=bookstack&logoColor=white" alt="753 Skills" /></a>
  <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge&logo=shield&logoColor=white" alt="MITRE ATT&CK Mapped" /></a>
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/graphs/contributors"><img src="https://img.shields.io/github/contributors/mukul975/Anthropic-Cybersecurity-Skills?style=for-the-badge&logo=github" alt="Contributors" /></a>
</p>

<p align="center">
  <b>The largest open-source collection of cybersecurity skills for AI agents.<br/>753 structured skills · MITRE ATT&CK mapped · NIST CSF 2.0 aligned · <a href="https://agentskills.io">agentskills.io</a> open standard</b>
</p>

<p align="center">
  <a href="https://mahipal.engineer/Anthropic-Cybersecurity-Skills/">🌐 Landing Page</a> · <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/releases/tag/v1.1.0">📦 v1.1.0 Release</a> · <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues">🐛 Report Bug</a> · <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues">💡 Request Feature</a>
</p>

---

Anthropic Cybersecurity Skills gives every AI agent — from Claude Code to GitHub Copilot to your custom LangChain pipeline — instant access to **753 production-grade cybersecurity skills** spanning 26 security domains. Each skill follows the [agentskills.io](https://agentskills.io) open standard: a YAML frontmatter header for lightning-fast discovery, a structured Markdown body for step-by-step execution, and reference files for deep technical context. The entire collection is mapped to **MITRE ATT&CK** (all 14 Enterprise tactics, 200+ techniques) and aligned to **NIST CSF 2.0** — giving AI agents the same structured knowledge that senior security practitioners carry in their heads. Install in one command and your agent immediately knows how to perform memory forensics, hunt for C2 beaconing, audit Kubernetes RBAC, reverse .NET malware, and hundreds more tasks.

## 📑 Table of contents

- [🚀 Quick start](#-quick-start--install-cybersecurity-skills-for-ai-agents)
- [🛡️ What's inside](#️-whats-inside--753-cybersecurity-skills-across-38-domains)
- [🤖 Compatible platforms](#-compatible-ai-agent-platforms)
- [📐 Skill structure](#-skill-structure-and-agentskillsio-format)
- [🗺️ MITRE ATT&CK coverage](#️-mitre-attck-and-nist-csf-20-coverage)
- [🧠 How AI agents use these skills](#-how-ai-agents-use-these-cybersecurity-skills)
- [📝 Example skills](#-example-cybersecurity-skills)
- [👥 Contributors](#-contributors)
- [🤝 Contributing](#-contributing-to-cybersecurity-ai-skills)
- [⭐ Star history](#-star-history)
- [🌐 Community](#-community)
- [📄 License](#-license)

---

## 🚀 Quick start — install cybersecurity skills for AI agents

Get up and running in under 30 seconds. Choose your preferred method:

### Option 1 · npx (recommended)

```bash
npx skills add mukul975/Anthropic-Cybersecurity-Skills
```

### Option 2 · Claude Code plugin marketplace

```
/plugin marketplace add mukul975/Anthropic-Cybersecurity-Skills
```

### Option 3 · Manual clone

```bash
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills
```

> **That's it.** Your AI agent can now discover and execute 753 cybersecurity skills on demand. No configuration, no API keys, no setup scripts.

---

## 🛡️ What's inside — 753 cybersecurity skills across 38 domains

Every skill is a self-contained directory with structured workflows, reference materials, helper scripts, and validation steps. Here are the top 16 domains:

| Domain | Skills | Example capabilities |
|:-------|:------:|:---------------------|
| ☁️ **Cloud Security** | **48** | AWS S3 bucket audit, Azure AD config review, GCP IAM assessment |
| 🌐 **Web Application Security** | **45** | HTTP request smuggling, XSS with Burp Suite, web cache poisoning |
| 🔌 **Network Security** | **41** | Wireshark traffic analysis, VLAN segmentation, Suricata IDS tuning |
| 🎯 **Penetration Testing** | **38** | Active Directory exploitation, OSCP-style methodology, pivoting |
| 🔴 **Red Teaming** | **35** | Cobalt Strike operations, LOTL techniques, evasion & persistence |
| 🔍 **DFIR** | **32** | Disk imaging, memory forensics with Volatility3, browser forensics |
| 🦠 **Malware Analysis** | **28** | Ghidra reverse engineering, YARA rules, .NET decompilation |
| 📡 **Threat Intelligence** | **26** | APT group analysis with MITRE Navigator, campaign attribution |
| ☸️ **Cloud Native / Kubernetes** | **24** | etcd security assessment, pod security policies, RBAC audit |
| 📋 **Compliance & Governance** | **22** | PCI DSS scoping, SOC 2 readiness, GDPR data mapping |
| 🔑 **IAM Security** | **20** | SAML SSO with Okta, PAM deployment, service account hardening |
| 🔐 **Cryptography** | **18** | TLS configuration audit, certificate lifecycle, key management |
| 🏰 **Zero Trust** | **16** | Microsegmentation, BeyondCorp implementation, continuous verification |
| 🏭 **OT / ICS Security** | **14** | SCADA monitoring, Modbus anomaly detection, Purdue model |
| 🔧 **DevSecOps** | **12** | Pipeline security gates, SAST/DAST integration, IaC scanning |
| 🕵️ **OSINT** | **15** | Domain reconnaissance, social engineering recon, dark web monitoring |
| ➕ **Additional domains (10+)** | **300+** | SOC operations, API security, endpoint security, phishing defense, ransomware defense, mobile security, deception technology, and more |
| | **753** | **Total skills across 38 domains** |

---

## 🤖 Compatible AI agent platforms

Skills follow the [agentskills.io](https://agentskills.io) open standard — **write once, use everywhere**. Any platform that reads `SKILL.md` files with YAML frontmatter works out of the box.

### AI code assistants

| Platform | Status | Install method |
|:---------|:------:|:---------------|
| **Claude Code** (Anthropic) | ✅ | `/plugin marketplace add mukul975/Anthropic-Cybersecurity-Skills` |
| **GitHub Copilot** (Microsoft) | ✅ | Place in `.github/skills` directory |
| **Cursor** | ✅ | `npx skills add` or manual clone |
| **Windsurf** | ✅ | `npx skills add` or manual clone |
| **Cline** | ✅ | `npx skills add` or manual clone |
| **Aider** | ✅ | `npx skills add` or manual clone |
| **Continue** | ✅ | `npx skills add` or manual clone |
| **Roo Code** | ✅ | `npx skills add` or manual clone |
| **Amazon Q Developer** | ✅ | `npx skills add` or manual clone |
| **Tabnine** | ✅ | `npx skills add` or manual clone |
| **Sourcegraph Cody** | ✅ | `npx skills add` or manual clone |
| **JetBrains AI** | ✅ | `npx skills add` or manual clone |

### CLI agents

| Platform | Status | Install method |
|:---------|:------:|:---------------|
| **OpenAI Codex CLI** | ✅ | `npx skills add` — reads from `~/.codex/skills` |
| **Gemini CLI** (Google) | ✅ | `npx skills add` or manual clone |

### Autonomous agents

| Platform | Status | Install method |
|:---------|:------:|:---------------|
| **Devin** | ✅ | Point to cloned skill directory |
| **Replit Agent** | ✅ | Import via repo URL |
| **SWE-agent** | ✅ | Mount skill directory |
| **OpenHands** | ✅ | Mount skill directory |

### Agent frameworks & SDKs

| Platform | Status | Install method |
|:---------|:------:|:---------------|
| **LangChain** | ✅ | Load `SKILL.md` files as tool descriptions |
| **CrewAI** | ✅ | Load as agent knowledge base |
| **AutoGen** | ✅ | Load as agent knowledge base |
| **Semantic Kernel** | ✅ | Load as plugins |
| **Haystack** | ✅ | Ingest via document store |
| **Vercel AI SDK** | ✅ | Load as tool definitions |
| **Any MCP-compatible agent** | ✅ | Via MCP tool integration |

---

## 📐 Skill structure and agentskills.io format

Every skill lives in its own directory under `skills/` and follows a consistent structure:

```
skills/performing-memory-forensics-with-volatility3/
├── SKILL.md              # Skill definition (YAML frontmatter + Markdown body)
│   ├── Frontmatter       #   → name, description, domain, subdomain, tags
│   ├── When to Use       #   → Trigger conditions for AI agents
│   ├── Prerequisites     #   → Required tools, access, environment
│   ├── Workflow           #   → Step-by-step execution guide
│   └── Verification      #   → How to confirm success
├── references/
│   ├── standards.md      # NIST, MITRE ATT&CK, CVE references
│   └── workflows.md      # Deep technical procedure reference
├── scripts/
│   └── process.py        # Practitioner helper scripts
└── assets/
    └── template.md       # Checklists, report templates
```

### YAML frontmatter (the discovery layer)

```yaml
---
name: performing-memory-forensics-with-volatility3
description: >-
  Analyze memory dumps to extract running processes, network connections,
  injected code, and malware artifacts using Volatility3 framework.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response, dfir]
version: "1.0"
author: mukul975
license: Apache-2.0
---
```

**Required fields:** `name` (kebab-case, 1–64 chars), `description` (keyword-rich for agent discovery), `domain`, `subdomain`, `tags`

**Optional fields:** `version`, `author`, `license`

---

## 🗺️ MITRE ATT&CK and NIST CSF 2.0 coverage

This collection provides **comprehensive coverage** of the two most widely adopted cybersecurity frameworks in the industry.

### MITRE ATT&CK Enterprise

All **14 Enterprise tactics** are covered, with skills mapped to **200+ individual techniques**:

| Tactic | Coverage | Example skills |
|:-------|:--------:|:---------------|
| Reconnaissance | ✅ | OSINT gathering, domain enumeration, social engineering recon |
| Resource Development | ✅ | Infrastructure profiling, certificate analysis |
| Initial Access | ✅ | Phishing analysis, exploit detection, supply chain review |
| Execution | ✅ | Script analysis, command-line forensics, scheduled task audit |
| Persistence | ✅ | Registry analysis, startup item review, implant detection |
| Privilege Escalation | ✅ | Token manipulation detection, UAC bypass analysis |
| Defense Evasion | ✅ | Process injection detection, obfuscation analysis |
| Credential Access | ✅ | Credential dumping detection, Kerberoasting defense |
| Discovery | ✅ | Network scanning detection, AD enumeration monitoring |
| Lateral Movement | ✅ | Pass-the-hash detection, RDP abuse monitoring |
| Collection | ✅ | Data staging detection, screen capture forensics |
| Command and Control | ✅ | C2 beaconing detection, DNS tunneling analysis |
| Exfiltration | ✅ | Data transfer monitoring, covert channel detection |
| Impact | ✅ | Ransomware response, data destruction forensics |

### NIST CSF 2.0 alignment

Every skill maps to one or more **NIST Cybersecurity Framework 2.0** functions:

- **Identify (ID)** — Asset management, risk assessment, governance skills
- **Protect (PR)** — Access control, awareness training, data security skills
- **Detect (DE)** — Anomaly detection, continuous monitoring, event analysis skills
- **Respond (RS)** — Incident response, mitigation, communication skills
- **Recover (RC)** — Recovery planning, improvement, communication skills

> An ATT&CK Navigator layer file is included in the v1.1.0 release for visual coverage mapping.

---

## 🧠 How AI agents use these cybersecurity skills

Skills use a **progressive disclosure pattern** that minimizes token usage while maximizing agent capability. Here's what happens when you ask your AI agent to "analyze this memory dump for signs of compromise":

### Stage 1 · Discovery (~30–50 tokens per skill)

The agent scans **only YAML frontmatter** across all 753 skills. Each scan costs ~30–50 tokens — the entire collection can be indexed for under 40K tokens. The agent matches your task against `name`, `description`, `subdomain`, and `tags` fields to find relevant skills.

```yaml
# Agent reads ONLY this:
name: performing-memory-forensics-with-volatility3
description: Analyze memory dumps to extract processes, network connections, and malware artifacts using Volatility3.
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response]
```

### Stage 2 · Full workflow load (~200–500 tokens)

Once a skill matches, the agent loads the **complete `SKILL.md` body** — trigger conditions, prerequisites, step-by-step workflow, and verification checks. This gives the agent a structured playbook to follow.

### Stage 3 · Deep reference access (on demand)

For complex tasks, the agent pulls in **supporting files** from `references/`, `scripts/`, and `assets/` — NIST standards mappings, detailed technical procedures, helper scripts, and report templates. These files are loaded only when the agent needs deeper context.

> **Result:** Irrelevant skills cost ~30 tokens. Relevant skills provide complete, structured, expert-level guidance. No wasted context window.

---

## 📝 Example cybersecurity skills

<details>
<summary><b>🔍 Memory forensics with Volatility3</b> — DFIR domain</summary>

````yaml
---
name: performing-memory-forensics-with-volatility3
description: >-
  Analyze memory dumps to extract running processes, network connections,
  injected code, and malware artifacts using the Volatility3 framework.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, memory-analysis, volatility3, incident-response, dfir]
version: "1.0"
author: mukul975
license: Apache-2.0
---

## When to Use

- Incident responder needs to analyze a memory dump from a compromised host
- Investigating potential malware infection or lateral movement
- Extracting indicators of compromise (IOCs) from volatile memory
- Identifying injected code, hidden processes, or rootkit activity
- Memory dump file (.raw, .mem, .dmp, .vmem) is available for analysis

## Prerequisites

- **Volatility3** installed (`pip install volatility3`)
- Memory dump file acquired from target system
- **Python 3.8+** runtime environment
- Symbol tables for target OS (auto-downloaded by Volatility3)
- Sufficient disk space for analysis output (~2x memory dump size)

## Workflow

### Step 1 — Identify the operating system profile

Run the banner and `windows.info` (or `linux.info` / `mac.info`) plugin to
auto-detect the OS version and confirm the dump is valid:

```bash
vol -f memory.raw windows.info
```

### Step 2 — List running processes

Extract the process tree to identify suspicious or unexpected processes:

```bash
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
vol -f memory.raw windows.psscan    # Finds hidden/unlinked processes
```

Look for: unusual parent-child relationships, processes with suspicious names,
processes running from temp directories, unsigned executables.

### Step 3 — Analyze network connections

Extract active and closed network connections:

```bash
vol -f memory.raw windows.netscan
vol -f memory.raw windows.netstat
```

Flag: connections to known-bad IPs, unusual ports (4444, 8443, 1337),
beaconing patterns, connections from non-browser processes.

### Step 4 — Detect code injection

Scan for injected code in process memory:

```bash
vol -f memory.raw windows.malfind
```

Review output for: PAGE_EXECUTE_READWRITE memory regions, MZ headers in
non-image regions, shellcode signatures, hollow process indicators.

### Step 5 — Extract artifacts

Dump suspicious processes, DLLs, and drivers for further analysis:

```bash
vol -f memory.raw windows.dumpfiles --pid <PID>
vol -f memory.raw windows.dlllist --pid <PID>
vol -f memory.raw windows.handles --pid <PID>
```

### Step 6 — Check persistence mechanisms

Examine registry hives and services loaded in memory:

```bash
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.svcscan
vol -f memory.raw windows.cmdline
```

## Verification

- [ ] OS profile correctly identified and dump validated
- [ ] Complete process tree exported and anomalies flagged
- [ ] Network connections reviewed and suspicious IPs documented
- [ ] Malfind output reviewed — injected code regions identified
- [ ] Suspicious binaries dumped for downstream malware analysis
- [ ] IOCs extracted (IPs, domains, file hashes, mutex names)
- [ ] Findings documented in incident report with timestamps
````

</details>

<details>
<summary><b>🦠 Reverse engineering .NET malware with dnSpy</b> — Malware Analysis domain</summary>

````yaml
---
name: analyzing-dotnet-malware-with-dnspy
description: >-
  Decompile, analyze, and extract IOCs from .NET-based malware samples
  using dnSpy for static analysis and behavioral understanding.
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, reverse-engineering, dotnet, dnspy, static-analysis]
version: "1.0"
author: mukul975
license: Apache-2.0
---

## When to Use

- Triaging a suspected .NET malware sample (.exe or .dll compiled with CLR)
- Extracting hardcoded C2 URLs, encryption keys, or configuration data
- Understanding malware behavior before dynamic analysis
- Analyzing obfuscated .NET payloads (ConfuserEx, SmartAssembly, etc.)
- Building detection signatures (YARA, Sigma) from decompiled source

## Prerequisites

- **dnSpy** (or dnSpyEx fork) installed on analysis workstation
- Isolated malware analysis environment (VM with snapshots)
- **PE analysis tool** (CFF Explorer, PE-bear, or pestudio) for initial triage
- **de4dot** for automated .NET deobfuscation
- Sample SHA256 hash documented before analysis begins
- Network monitoring tools (Wireshark/FakeNet-NG) for dynamic validation

## Workflow

### Step 1 — Initial triage and environment setup

Confirm the sample is a .NET assembly before opening in dnSpy:

```bash
# Check for CLR metadata
file sample.exe
# Look for .NET version string, mscoree.dll import
pestudio sample.exe
```

Take a VM snapshot. Disable network adapters. Document sample hash.

### Step 2 — Deobfuscate if protected

Many .NET malware families use obfuscation. Run de4dot first:

```bash
de4dot sample.exe -o sample_clean.exe
```

Check output log for identified obfuscator (ConfuserEx, Dotfuscator,
SmartAssembly, Babel, Eazfuscator). If de4dot fails, note the packer
for manual unpacking in dnSpy.

### Step 3 — Load and explore in dnSpy

Open the cleaned binary in dnSpy. Start with high-level reconnaissance:

1. **Assembly Explorer** — Review namespaces, classes, entry point
2. **Entry point** (`Main()` or module initializer) — Trace execution flow
3. **Resources** — Check for embedded payloads, encrypted configs
4. **String references** — Search for URLs, IP addresses, registry keys
5. **References** — Note any P/Invoke calls (Win32 API) indicating native interaction

### Step 4 — Identify C2 infrastructure and configuration

Search decompiled source for network indicators:

- Hardcoded URLs, IP addresses, domain names
- Base64-encoded strings (decode in CyberChef)
- XOR / AES decryption routines with embedded keys
- HTTP User-Agent strings, custom headers
- Registry keys or file paths used for persistence

Set breakpoints in dnSpy debugger at decryption functions to capture
plaintext config at runtime if static extraction fails.

### Step 5 — Map capabilities to MITRE ATT&CK

Document each observed capability:

- **Execution method** — Process injection, scheduled tasks, WMI
- **Persistence** — Registry Run keys, startup folder, services
- **Credential access** — Browser credential theft, keylogging
- **Exfiltration** — HTTP POST, DNS tunneling, cloud storage APIs
- **Evasion** — Anti-VM checks, sleep timers, sandbox detection

### Step 6 — Extract IOCs and build detections

Compile all indicators into a structured IOC list:

```
# Network IOCs
C2: https://evil-domain[.]com/gate.php
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0)
DNS: ns1.malware-c2[.]net

# Host IOCs
Mutex: Global\{GUID-HERE}
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svchost
File: %APPDATA%\svchost.exe (SHA256: abc123...)
```

Write YARA rule targeting unique strings or byte patterns.

## Verification

- [ ] Sample identified as .NET assembly and hash documented
- [ ] Deobfuscation attempted — obfuscator identified and handled
- [ ] Entry point traced — full execution flow mapped
- [ ] C2 infrastructure extracted (URLs, IPs, domains, ports)
- [ ] Encryption keys / decryption routines documented
- [ ] Capabilities mapped to MITRE ATT&CK techniques
- [ ] IOC list exported in structured format (STIX, OpenIOC, or CSV)
- [ ] YARA detection rule written and tested against sample
````

</details>

---

## 👥 Contributors

Thanks to these wonderful people for building the largest open-source cybersecurity skills collection:

<!-- ALL-CONTRIBUTORS-LIST:START -->
<a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mukul975/Anthropic-Cybersecurity-Skills" />
</a>
<!-- ALL-CONTRIBUTORS-LIST:END -->

Want to see your name here? Check out the [contributing guide](#-contributing-to-cybersecurity-ai-skills) below.

---

## 🤝 Contributing to cybersecurity AI skills

This project hit **3.5k stars in two weeks** — the community momentum is real. With **328 forks**, **9 open PRs**, and security professionals from around the world getting involved, now is the perfect time to contribute.

We welcome four types of contributions:

| Type | Description | Good for |
|:-----|:------------|:---------|
| 🆕 **New skills** | Add skills for uncovered techniques or domains | Security practitioners, pen testers, IR analysts |
| 📖 **Improve existing skills** | Enhance workflows, add edge cases, fix errors | Anyone who uses the skills and spots improvements |
| 🌍 **Translations & i18n** | Help make skills accessible to non-English speakers | Multilingual security professionals |
| 🐛 **Bug reports & feedback** | Report issues, suggest improvements, review PRs | Everyone — all experience levels welcome |

### How to get started

1. **Browse [open issues](https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues)** — look for `good first issue` and `help wanted` labels
2. **Read [`CONTRIBUTING.md`](CONTRIBUTING.md)** for the full skill template and submission guidelines
3. **Fork the repo**, create your skill directory under `skills/`, and submit a PR
4. **Title format:** `Add skill: your-skill-name-here`

> Every PR gets reviewed for technical accuracy and consistency with the agentskills.io standard. We aim to review within 48 hours.

---

## ⭐ Star history

[![Star History Chart](https://api.star-history.com/svg?repos=mukul975/Anthropic-Cybersecurity-Skills&type=Date)](https://star-history.com/#mukul975/Anthropic-Cybersecurity-Skills&Date)

---

## 🌐 Community

<p align="center">
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/stargazers">⭐ Star this repo</a> ·
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/fork">🍴 Fork it</a> ·
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/discussions">💬 Discuss</a> ·
  <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills/issues/new">📝 Open an issue</a>
</p>

If this project saves you time or makes your AI agent more capable, **give it a ⭐** — it helps others discover these skills and keeps the community growing.

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](LICENSE) file for details.

You are free to use, modify, and distribute these skills in both personal and commercial projects. Attribution is appreciated but not required.

---

<p align="center">
  <sub>
    <b>⚠️ Disclaimer:</b> This is an independent, community-created project. <b>Not affiliated with Anthropic PBC.</b><br/>
    "Anthropic" in the repository name refers to compatibility with the <a href="https://agentskills.io">agentskills.io</a> open standard,<br/>
    not official Anthropic endorsement or affiliation. All trademarks belong to their respective owners.
  </sub>
</p>
