# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A community-maintained library of 817+ structured cybersecurity skills for AI agents, following the [agentskills.io](https://agentskills.io) standard. Skills are distributed as a Claude Code plugin (`cybersecurity-skills@claude-plugins-official`). **Not affiliated with Anthropic PBC.**

All skills cover authorized use only — red-team, pentesting, DFIR, detection, and defense in authorized contexts.

## Commands

```bash
# Validate a single skill before submitting a PR
python tools/validate-skill.py skills/your-skill-name/

# Validate all skills (mirrors what CI runs)
python tools/validate-skill.py --all
```

Requirements: Python 3.8+, stdlib only (no pip installs needed).

Run these from the **repository root** — `--all` resolves skills via a relative `skills/*/` glob and will report "No skill directories found" if invoked elsewhere.

## Skill anatomy

Every skill lives under `skills/<kebab-case-name>/` with this layout:

```
skills/your-skill-name/
├── SKILL.md              ← Required. YAML frontmatter + Markdown body.
├── references/
│   ├── standards.md      ← MITRE ATT&CK IDs, CVE refs, NIST links
│   └── workflows.md      ← Deep technical procedure
├── scripts/
│   └── agent.py          ← Working helper script (optional)
└── assets/
    └── template.md       ← Filled-in checklist/report template (optional)
```

Only `SKILL.md` is required. The other files are optional but recommended.

### Required SKILL.md frontmatter fields

```yaml
---
name: your-skill-name          # kebab-case, 1–64 chars, matches directory name
description: >-                # ≥50 chars, keyword-rich for agent discovery
  Clear description of what this skill does ...
domain: cybersecurity          # always "cybersecurity"
subdomain: red-teaming         # see canonical list below
tags: [tag1, tag2, tag3]       # list with ≥2 items
version: "1.0"
author: your-github-username
license: Apache-2.0
---
```

Optional framework-mapping fields in frontmatter: `nist_csf`, `atlas_techniques`, `d3fend_techniques`, `nist_ai_rmf`, `mitre_attack`, `mitre_f3`.

### Required Markdown body sections

```markdown
## When to Use
## Prerequisites
## Workflow      ← numbered steps with real commands
```

Common optional sections: `## Key Concepts`, `## Tools & Systems`, `## Common Scenarios`, `## Output Format`, `## Detection and OPSEC Notes`, `## Validation Criteria`.

### Canonical subdomains

Use the canonical form (not aliases) for new skills:

`web-application-security` · `network-security` · `penetration-testing` · `red-teaming` · `digital-forensics` · `malware-analysis` · `threat-intelligence` · `cloud-security` · `container-security` · `identity-access-management` · `cryptography` · `vulnerability-management` · `compliance-governance` · `zero-trust-architecture` · `ot-ics-security` · `devsecops` · `soc-operations` · `incident-response` · `endpoint-security` · `phishing-defense` · `api-security` · `mobile-security` · `ransomware-defense` · `threat-hunting` · `ai-security` · `supply-chain-security` · `deception-technology` · `hardware-firmware-security` · `purple-team`

The validator accepts aliases (e.g. `security-operations` for `soc-operations`) but warns. Run the validator to check.

## What CI manages automatically — do not edit by hand

- `index.json` — regenerated on every push to `main` that touches `skills/**`
- Skill count badges/numbers in `README.md`
- Version fields in `.claude-plugin/marketplace.json` and `.claude-plugin/plugin.json`

These are updated by the `update-index.yml` and `sync-marketplace-version.yml` workflows. Manually editing them will be overwritten.

## Adding a new skill

1. Create `skills/your-skill-name/SKILL.md` — directory name must match the `name` frontmatter field exactly.
2. Run `python tools/validate-skill.py skills/your-skill-name/` locally.
3. Submit a PR with title `Add skill: your-skill-name`.

CI checks: frontmatter validity (via `validate-skill.py --all`) and duplicate `name` detection across all skills.

## Key architectural constraints

- **`.bak` directories** under `skills/` are ignored by the validator and index generator — safe to use as stash space, but CI skips them entirely.
- **MITRE ATT&CK IDs** for a skill go in `references/standards.md`, not necessarily in the frontmatter `mitre_attack` list. The ATT&CK Navigator layer lives in the v1.0.0 release assets, not in `main`.
- **F3 technique IDs** use `F1XXX` format (not `TXXXX`); reused ATT&CK techniques keep their `TXXXX` IDs. Schema documented in `docs/mitre-f3-mapping.md`.
- The `tools/validate-skill.py` parser is the single source of truth for frontmatter validation — it is stdlib-only and is called directly by CI, so the validator and CI always agree.
