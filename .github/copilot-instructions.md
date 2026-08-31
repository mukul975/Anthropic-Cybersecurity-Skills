# Copilot Instructions for Anthropic-Cybersecurity-Skills

**Anthropic-Cybersecurity-Skills** is the largest open-source cybersecurity skills library for AI agents, containing 817 production-grade skills mapped to 6 industry frameworks (MITRE ATT&CK, NIST CSF, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, MITRE F3). This document guides Copilot agents contributing new skills and framework mappings.

## Quick Facts

- **Type**: Open-source cybersecurity skills library + framework mapping hub
- **Skills**: 817 across 29 security domains
- **Frameworks**: 6 (MITRE ATT&CK v14, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, MITRE F3)
- **Format**: agentskills.io standard (YAML frontmatter + Markdown)
- **License**: Apache 2.0 (ethical use required)
- **Community**: Independent, community-created (not affiliated with Anthropic)

## Repository Structure

```
Anthropic-Cybersecurity-Skills/
├── skills/                    # 817 skill directories (kebab-case)
│   ├── abusing-dpapi-for-credential-access/
│   │   ├── SKILL.md          # Frontmatter + detailed instructions
│   │   ├── LICENSE
│   │   ├── scripts/
│   │   │   └── process.py    # Optional helper scripts
│   │   └── references/
│   │       ├── api-reference.md
│   │       ├── standards.md
│   │       └── workflows.md
│   └── ... (816 more)
├── mappings/                  # Framework coverage & alignment
│   ├── mitre-attack/
│   │   ├── attack-navigator-layer.json
│   │   └── coverage-summary.md
│   ├── nist-csf/
│   ├── owasp/
│   └── README.md
├── docs/                      # Additional documentation
├── index.json                 # Central skill registry (auto-generated)
├── CONTRIBUTING.md            # Contribution guide
├── SECURITY.md               # Ethical use & dual-use policies
└── CODE_OF_CONDUCT.md        # Community guidelines
```

## Build & Development

### Prerequisites

- **Git** (for cloning and version control)
- **Python 3.8+** (optional, for scripts/metadata generation)
- **jq** (optional, for JSON processing; useful for index.json queries)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
cd Anthropic-Cybersecurity-Skills

# No installation needed—skills are static Markdown files
# View a skill directly:
cat skills/abusing-dpapi-for-credential-access/SKILL.md

# Search for skills by keyword:
grep -r "credential-access" skills/*/SKILL.md | head -10

# Query the central index:
jq '.skills[] | select(.description | contains("Active Directory"))' index.json
```

### Generating/Updating index.json

When adding new skills, the index must be regenerated:

```bash
# If a script exists (check repository):
python3 tools/generate-index.py

# Otherwise, manually verify:
jq '.skills | length' index.json  # Should match skill directory count
```

## Architecture & Concepts

### Skill Structure

Each skill is a **self-contained directory** following the `agentskills.io` standard:

```
skills/skill-name/
├── SKILL.md              # The authoritative skill definition
├── LICENSE               # Apache 2.0 (usually)
├── scripts/
│   └── process.py        # Optional: helper scripts, agent implementations
└── references/
    ├── api-reference.md  # Technical API docs for the skill
    ├── standards.md      # CVE, NIST, MITRE refs
    └── workflows.md      # Deep technical procedures
```

### SKILL.md Format

Every skill follows this structure:

```markdown
---
name: skill-name-kebab-case
description: >-
  Clear, agent-discoverable description.
  Include keywords for search/filtering.
  This is what agents read to decide whether to use this skill.
domain: cybersecurity
subdomain: red-teaming  # e.g. digital-forensics, compliance-governance, etc.
tags:
  - tool-names (mimikatz, burp-suite, etc.)
  - frameworks (active-directory, cloud, kubernetes, etc.)
  - techniques (credential-access, privilege-escalation, etc.)
version: "1.0"
author: github-username
license: Apache-2.0
nist_csf:
  - DE.CM-01
  - PR.AC-01
mitre_attack:
  - T1555.004
  - T1078.002
atlas_techniques:
  - AML.T0047
d3fend_techniques:
  - D3-MA
  - D3-PSMD
nist_ai_rmf:
  - MEASURE-2.6
mitre_f3:
  - F1020.002
---

# Skill Title

> **Legal Notice:** This skill is for authorized [penetration testing/research/defense] only.
> Unauthorized use may violate computer fraud laws. Always operate within rules-of-engagement.

## Overview

Clear, concise explanation of what the skill does and why an agent needs it.
Include threat model context if applicable.

## When to Use

- Specific scenario 1
- Specific scenario 2
- Real-world contexts where this skill applies

## Prerequisites

- Required tools (with install commands if applicable)
- Required access/permissions
- Required knowledge/certifications
- System requirements

## Workflow

### Step 1: [Action]
Clear instructions with real commands.
```bash
tool-name --flag value
```

### Step 2: [Next Action]
Continue with detailed steps.

### Output Format

What success looks like:
```
Expected output or indicator
```

## Key Concepts

| Term | Definition |
|------|-----------|
| Concept1 | Explanation |
| Concept2 | Explanation |

## Tools & Systems

- **Tool A** — What it does, where to get it
- **Tool B** — What it does, where to get it

## Common Scenarios

### Scenario 1
When X, do Y.

### Scenario 2
When A, do B.

## References

- [MITRE ATT&CK: T1555.004](https://attack.mitre.org/techniques/T1555/004/)
- [NIST CSF: DE.CM-01](https://csrc.nist.gov/)
```

### Framework Mappings

Each skill can map to multiple frameworks. Key mappings:

| Framework | Scope | Example |
|-----------|-------|---------|
| **MITRE ATT&CK** | Adversarial tactics/techniques | T1555.004 (Credentials from Password Stores) |
| **NIST CSF 2.0** | Cybersecurity functions & categories | DE.CM (Detect - Monitor) |
| **MITRE ATLAS** | AI/ML system attacks | AML.T0047 |
| **MITRE D3FEND** | Defensive techniques | D3-MA |
| **NIST AI RMF** | AI risk management | MEASURE-2.6 (Measure function) |
| **MITRE F3** | Fraud-specific techniques | F1020.002 (Fake Website) |

### Subdomains (Choose One)

- **web-application-security** — OWASP, API, web app testing
- **network-security** — Network tools, protocols, monitoring
- **penetration-testing** — General penetration testing methodology
- **red-teaming** — Simulating advanced attackers (C2, evasion, etc.)
- **digital-forensics** — Incident response, forensic analysis, disk imaging
- **malware-analysis** — Static/dynamic malware analysis, reverse engineering
- **threat-intelligence** — Gathering, analyzing, sharing threat data
- **cloud-security** — AWS/Azure/GCP-specific security
- **container-security** — Docker, Kubernetes, container runtime
- **identity-access-management** — Active Directory, IAM, authentication
- **cryptography** — Encryption, hashing, key management
- **vulnerability-management** — Scanning, assessment, remediation
- **compliance-governance** — CMMC, HIPAA, SOC2, auditing
- **zero-trust-architecture** — Zero-trust implementation patterns
- **ot-ics-security** — Operational technology, ICS/SCADA
- **devsecops** — Secure software development, CI/CD security

## Conventions & Patterns

### Naming

- **Directory/file**: kebab-case, lowercase with hyphens (e.g., `abusing-dpapi-for-credential-access`)
- **Skill name**: Same as directory (in YAML frontmatter)
- **GitHub usernames**: Use lowercase GitHub username as author

### Description Quality

Descriptions should be **agent-discoverable** — concise, keyword-rich, action-oriented:

```yaml
# ✗ Vague
description: How to abuse DPAPI

# ✓ Clear and searchable
description: >-
  Extract DPAPI-protected secrets such as credentials and browser data
  offline and online using SharpDPAPI, Mimikatz, or impacket. Ideal
  for post-exploitation Windows credential harvesting and offline analysis.
```

### Tags Strategy

Use 3-5 tags for discoverability:

```yaml
tags:
  - tool-names           # mimikatz, sharpdpapi, burp-suite
  - attack-frameworks    # active-directory, kerberos, oauth
  - techniques           # credential-access, privilege-escalation, lateral-movement
  - platforms            # windows, linux, macos, cloud
  - use-cases            # post-exploitation, threat-intel, forensics
```

### Framework ID Format

IDs are **case-sensitive** and **exact**:

```yaml
mitre_attack:
  - T1055                   # Parent technique
  - T1055.001               # Sub-technique
nist_csf:
  - DE.CM-01                # NIST Cybersecurity Framework 2.0
atlas_techniques:
  - AML.T0047              # MITRE ATLAS for AI/ML
d3fend_techniques:
  - D3-MA                  # MITRE D3FEND defensive technique ID
nist_ai_rmf:
  - MEASURE-2.6                   # NIST AI Risk Management Framework
mitre_f3:
  - F1020.002               # MITRE Fight Fraud Framework technique ID
```

## Common Tasks

### Adding a New Skill

1. **Create skill directory** (kebab-case):
   ```bash
   mkdir -p skills/your-skill-name
   ```

2. **Create SKILL.md** with required frontmatter:
   ```bash
   cat > skills/your-skill-name/SKILL.md << 'EOF'
   ---
   name: your-skill-name
   description: >-
     Clear, discoverable description with keywords.
   domain: cybersecurity
   subdomain: red-teaming
   tags:
     - tool-name
     - technique
     - use-case
   version: "1.0"
   author: your-github-username
   license: Apache-2.0
   mitre_attack:
     - T1234.567
   nist_csf:
     - DE.CM-01
   atlas_techniques:
     - AML.T0047
   d3fend_techniques:
     - D3-MA
   nist_ai_rmf:
     - MEASURE-2.6
   mitre_f3:
     - F1020.002
   ---
   
   # Skill Title
   
   > **Legal Notice:** Authorized use only. [...]
   
   ## Overview
   
   Clear explanation...
   EOF
   ```

3. **Write detailed sections** in Markdown:
   - When to Use (specific scenarios)
   - Prerequisites (tools, permissions, access)
   - Workflow (numbered steps with real commands)
   - Key Concepts (table for terminology)
   - Tools & Systems
   - Common Scenarios
   - References (framework links)

4. **Add optional supporting files**:
   ```
   scripts/process.py         # Helper script or agent implementation
   references/standards.md    # CVE, NIST, MITRE links
   references/workflows.md    # Deep technical procedures
   ```

5. **Add LICENSE**:
   ```bash
   cp LICENSE skills/your-skill-name/LICENSE
   # Or use a specific open-source license file
   ```

6. **Regenerate index** (if automation exists):
   ```bash
   python3 tools/generate-index.py  # Updates index.json
   ```

7. **Submit PR**:
   ```bash
   git add skills/your-skill-name
   git commit -m "Add skill: your-skill-name"
   git push origin feature/add-skill-name
   # Create PR with title: "Add skill: your-skill-name"
   ```

### Updating Framework Mappings

If a skill maps to new frameworks or techniques change:

1. **Update SKILL.md frontmatter**:
   ```yaml
   mitre_attack:
     - T1555.004      # Add new technique IDs
   nist_csf:
     - DE.CM-01       # Add new control IDs
   ```

2. **Regenerate index** (if automation exists):
   ```bash
   python3 tools/generate-index.py
   ```

3. **Verify mapping coverage**:
   ```bash
   # Check if all referenced IDs are valid:
   grep -r "T1[0-9]" skills/*/SKILL.md | grep -v "http"
   ```

### Searching Skills

**By keyword**:
```bash
grep -r "active-directory" skills/*/SKILL.md
```

**By framework**:
```bash
grep -r "T1055" skills/*/SKILL.md  # MITRE ATT&CK technique
```

**By subdomain**:
```bash
grep "subdomain: red-teaming" skills/*/SKILL.md
```

**Using jq (if index.json exists)**:
```bash
# Find skills by keyword
jq '.skills[] | select(.tags[] | contains("credential-access"))' index.json

# Count skills by subdomain
jq '[.skills[] | .subdomain] | group_by(.) | map({subdomain: .[0], count: length})' index.json
```

## Platform & Framework Notes

### Windows-Specific Skills

- Often leverage PowerShell, Windows APIs, Active Directory
- Reference MITRE ATT&CK Windows tactics: T1021 (Lateral Movement), T1078 (Valid Accounts)
- Include prerequisite (SYSTEM/Administrator access, domain join, etc.)

### Linux/macOS Skills

- Use standard Unix tools (bash, Python, curl, etc.)
- Note platform availability differences
- Cloud/container skills often multi-platform

### Cloud Security Skills

- Specify cloud provider (AWS, Azure, GCP, multi-cloud)
- Reference cloud-specific tools (awscli, az, gcloud)
- Map to cloud-specific MITRE ATLAS techniques

### AI/ML Attack Skills

- Use MITRE ATLAS techniques (AML.T0047, AML.T0051, etc.)
- Include model/system type (LLM, transformer, computer vision, etc.)
- Note NIST AI RMF alignment (GOVERN, MAP, MEASURE, MANAGE)

## Gotchas & Known Issues

### Legal & Ethical

- **Dual-use policy**: Skills for red-teaming and exploitation require legal notice
  - Must include "authorized use only" disclaimer
  - Reference SECURITY.md for policy
- **No credentials**: Never embed API keys, tokens, or credentials
- **Attribution**: Cite original tool authors and researchers

### Framework Maintenance

- **MITRE ATT&CK updates**: v14 is current; check attack.mitre.org for latest
- **NIST CSF 2.0**: Rolled out Feb 2024; use subcategory IDs as in this repo (e.g., `DE.CM-01`, `PR.PS-01`)
- **Technique changes**: Techniques may deprecate; verify via attack.mitre.org

### Subdomain Assignment

- **Common mistake**: Using wrong subdomain (e.g., "red-teaming" for defensive skill)
  - red-teaming = offensive/attacker perspective
  - compliance-governance = defensive/compliance perspective
  - Choose the **primary** subdomain if skill spans multiple

### index.json Generation

- If index doesn't auto-regenerate, manually verify:
  ```bash
  # Count skills in index vs directories
  jq '.skills | length' index.json
  ls -d skills/*/ | wc -l
  # Should match (or index may be stale)
  ```

## Testing & Quality

### Skill Quality Checklist

Before submitting a PR:

- [ ] **Name**: Kebab-case, 1-64 chars, descriptive
- [ ] **Description**: Clear, includes keywords, discoverable by agents
- [ ] **Instructions**: Actionable with real commands and tool names
- [ ] **Subdomain**: Correctly assigned (red-teaming vs defensive)
- [ ] **Tags**: 3-5 relevant tags (tools, techniques, platforms)
- [ ] **Framework IDs**: Valid MITRE ATT&CK, NIST CSF, MITRE ATLAS IDs
- [ ] **Legal notice**: Included if skill is offensive/dual-use
- [ ] **References**: Links to official framework docs
- [ ] **Formatting**: Proper Markdown, no typos, code blocks highlighted

### Manual Verification

```bash
# Validate skill frontmatter and conventions (repo validator):
python3 tools/validate-skill.py skills/my-skill/
# Or validate all skills:
python3 tools/validate-skill.py --all

# Check for framework ID patterns:
grep -E "^  - (T1[0-9]{3,4}(\.[0-9]{3})?|DE\.[A-Z]{2}-[0-9]{2}|AML\.)" skills/*/SKILL.md

# Verify all referenced skills have directories:
jq -r '.skills[].name' index.json | while read skill; do
  [ -d "skills/$skill" ] || echo "Missing: $skill"
done
```

## Contributing Notes

- **No build required** — Skills are static files; git pull = ready to use
- **Skill dependencies**: Skills are independent; if skill A requires skill B, note it in the workflow
- **Tool versions**: Mention tool versions in prerequisites (e.g., "Burp Suite 2024.1+")
- **Testing**: Test commands on actual systems before submitting
- **Code of Conduct**: See CODE_OF_CONDUCT.md — be respectful, follow ethical use policy

## Resources & Links

- **agentskills.io Standard**: https://agentskills.io (format specification)
- **MITRE ATT&CK**: https://attack.mitre.org (techniques, tactics)
- **NIST Cybersecurity Framework**: https://csrc.nist.gov/projects/cybersecurity-framework (controls)
- **MITRE ATLAS**: https://atlas.mitre.org (AI/ML attacks)
- **MITRE D3FEND**: https://d3fend.mitre.org (defensive techniques)
- **NIST AI RMF**: https://airc.nist.gov/ (AI risk management)
- **Contributing Guide**: `CONTRIBUTING.md` in repo
- **Security Policy**: `SECURITY.md` — dual-use & ethical use
- **Code of Conduct**: `CODE_OF_CONDUCT.md`
- **Community Playground**: https://casky.ai (test skills in browser)

## Quick Reference

| Task | Command |
|------|---------|
| Add skill | `mkdir skills/name && cat > SKILL.md` |
| Search by technique | `grep -r "T1055" skills/` |
| Search by subdomain | `grep "subdomain: red-teaming" skills/*/SKILL.md` |
| Validate skill | `python3 tools/validate-skill.py skills/my-skill/` |
| Regenerate index | `python3 tools/generate-index.py` |
| View mapping coverage | Open `mappings/attack-navigator-layer.json` in ATT&CK Navigator |
