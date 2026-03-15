# API Reference: Web Application Vulnerability Triage

## SLA Remediation Timelines

| Severity | CVSS Range | SLA (Days) |
|----------|-----------|------------|
| Critical | 9.0-10.0 | 7 |
| High | 7.0-8.9 | 30 |
| Medium | 4.0-6.9 | 90 |
| Low | 0.1-3.9 | 180 |
| Info | 0.0 | 365 |

## Scanner JSON Formats

### OWASP ZAP
| Field | Description |
|-------|-------------|
| `alerts[].name` | Finding title |
| `alerts[].risk` | Severity (High, Medium, Low, Informational) |
| `alerts[].cweid` | CWE identifier |
| `alerts[].uri` | Affected URL |

### Burp Suite
| Field | Description |
|-------|-------------|
| `issues[].name` | Issue name |
| `issues[].severity` | high, medium, low, information |
| `issues[].url` | Affected endpoint |
| `issues[].parameter` | Vulnerable parameter |

### Nikto JSON
| Field | Description |
|-------|-------------|
| `vulnerabilities[].id` | Nikto ID |
| `vulnerabilities[].OSVDB` | OSVDB reference |
| `vulnerabilities[].url` | Affected path |

## Priority Scoring Formula

```
score = cvss * 10
  + 5 if parameter identified
  + 10 if injection-type vulnerability
  + 8 if authentication-related
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Ingest scanner output |
| `datetime` | stdlib | SLA deadline calculation |
| `collections` | stdlib | Severity distribution |

## References

- CVSS v3.1: https://www.first.org/cvss/specification-document
- OWASP Risk Rating: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
- CWE Database: https://cwe.mitre.org/
