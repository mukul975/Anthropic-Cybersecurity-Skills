# API Reference: Vulnerability Prioritization with CVSS Scoring

## CVSS v3.1 Base Metrics

| Metric | Values | Description |
|--------|--------|-------------|
| AV (Attack Vector) | N, A, L, P | Network, Adjacent, Local, Physical |
| AC (Attack Complexity) | L, H | Low, High |
| PR (Privileges Required) | N, L, H | None, Low, High |
| UI (User Interaction) | N, R | None, Required |
| S (Scope) | U, C | Unchanged, Changed |
| C (Confidentiality) | N, L, H | None, Low, High |
| I (Integrity) | N, L, H | None, Low, High |
| A (Availability) | N, L, H | None, Low, High |

## Severity Ratings

| Score Range | Rating |
|-------------|--------|
| 0.0 | None |
| 0.1-3.9 | Low |
| 4.0-6.9 | Medium |
| 7.0-8.9 | High |
| 9.0-10.0 | Critical |

## EPSS API (FIRST.org)

| Endpoint | Description |
|----------|-------------|
| `GET https://api.first.org/data/v1/epss?cve=CVE-XXXX` | Get EPSS score |
| Response: `data[].epss` | Exploit probability (0-1) |
| Response: `data[].percentile` | Percentile ranking |

## CISA KEV Catalog

| Field | Description |
|-------|-------------|
| URL | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| `vulnerabilities[].cveID` | CVE identifier |
| `vulnerabilities[].dateAdded` | Date added to KEV |
| `vulnerabilities[].dueDate` | Remediation deadline |

## Priority Scoring Formula

```
priority = cvss_score * 10
  + 30 if in CISA KEV
  + 20 if EPSS > 0.5
  + 10 if EPSS > 0.1
```

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Fetch EPSS and KEV data |
| `math` | stdlib | CVSS score rounding |
| `json` | stdlib | Report generation |

## References

- CVSS v3.1 Specification: https://www.first.org/cvss/specification-document
- EPSS Model: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov/
