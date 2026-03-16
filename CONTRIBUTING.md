# Contributing to HRD-Security Skills

## How to add a new skill

1. Create a new directory: `skills/your-skill-name/`
2. Add a `SKILL.md` file with required YAML frontmatter:
   ```yaml
   ---
   name: your-skill-name
   description: >-
     Clear description of what this skill does and when
     an AI agent should activate it. Include keywords.
   domain: cybersecurity
   subdomain: [category]
   tags: [tag1, tag2, tag3]
   version: "1.0"
   author: your-github-username
   license: Apache-2.0
   ---
   ```
3. Write clear, step-by-step instructions in the Markdown body using these sections:
   - ## When to Use
   - ## Prerequisites
   - ## Workflow (numbered steps with real commands)
   - ## Key Concepts (table)
   - ## Tools & Systems
   - ## Common Scenarios
   - ## Output Format
4. (Optional) Add supporting files:
   - `references/standards.md` — Real standard numbers, CVE refs, NIST/MITRE links
   - `references/workflows.md` — Deep technical procedure
   - `scripts/process.py` — Real working helper script
   - `assets/template.md` — Real filled-in checklist/template
5. Submit a PR with title: `Add skill: your-skill-name`

## Skill quality checklist
- [ ] Name is lowercase with hyphens (kebab-case), 1–64 characters
- [ ] Description is clear and includes agent-discovery keywords
- [ ] Instructions are actionable with real commands and tool names
- [ ] Domain and subdomain are set correctly
- [ ] Tags include relevant tools, frameworks, and techniques

## Subdomains
Choose the most appropriate subdomain for your skill:
- web-application-security
- network-security
- penetration-testing
- red-teaming
- digital-forensics
- malware-analysis
- threat-intelligence
- cloud-security
- container-security
- identity-access-management
- cryptography
- vulnerability-management
- compliance-governance
- zero-trust-architecture
- ot-ics-security
- devsecops
- soc-operations
- incident-response
- phishing-defense
- ransomware-defense
- api-security
- mobile-security
- endpoint-security
- threat-hunting

## Code of Conduct
This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License
By contributing, you agree that your contributions will be licensed under Apache-2.0.
