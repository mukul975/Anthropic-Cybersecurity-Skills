# Tools

Utility scripts for maintaining the Anthropic-Cybersecurity-Skills repository.

## validate-skill.py

A Python 3 script that validates SKILL.md YAML frontmatter against the repository schema. **No external dependencies** — uses only the Python standard library.

### Usage

```bash
# Validate a single skill
python tools/validate-skill.py skills/analyzing-cobalt-strike-beacon-configuration/

# Validate all skills in the repository
python tools/validate-skill.py --all
```

### What It Checks

| Field         | Rule                                                                 |
|---------------|----------------------------------------------------------------------|
| `SKILL.md`    | Must exist in the skill directory                                    |
| Frontmatter   | Valid YAML between `---` markers                                     |
| `name`        | Required · kebab-case · 1–64 characters                             |
| `description` | Required · 20–500 characters                                        |
| `domain`      | Required · must be `cybersecurity`                                   |
| `subdomain`   | Required · must be one of the 24 allowed subdomains (see below)      |
| `tags`        | Required · list with at least 2 items                                |

### Allowed Subdomains

`web-application-security` · `network-security` · `penetration-testing` · `red-teaming` · `digital-forensics` · `malware-analysis` · `threat-intelligence` · `cloud-security` · `container-security` · `identity-access-management` · `cryptography` · `vulnerability-management` · `compliance-governance` · `zero-trust-architecture` · `ot-ics-security` · `devsecops` · `threat-hunting` · `soc-operations` · `incident-response` · `endpoint-security` · `phishing-defense` · `api-security` · `mobile-security` · `ransomware-defense`

### Exit Codes

| Code | Meaning               |
|------|-----------------------|
| `0`  | All skills passed     |
| `1`  | One or more failures  |
| `2`  | Usage / config error  |

### Output

The script prints colored `✔ PASS` / `✘ FAIL` lines per skill, followed by a summary count.

### CI Integration

```yaml
- name: Validate skill metadata
  run: python tools/validate-skill.py --all
```
