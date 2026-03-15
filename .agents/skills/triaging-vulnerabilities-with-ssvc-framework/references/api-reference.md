# API Reference: Triaging Vulnerabilities with SSVC Framework

## SSVC Decision Outcomes

| Decision | Action | Timeline |
|----------|--------|----------|
| Act | Immediate remediation required | 24-48 hours |
| Attend | Urgent, prioritize in current cycle | 1-2 weeks |
| Track* | Monitor closely, schedule remediation | Next patch cycle |
| Track | Standard vulnerability management | Regular cadence |

## SSVC Decision Points

| Decision Point | Values | Description |
|----------------|--------|-------------|
| Exploitation | none, poc, active | Current exploitation activity |
| Technical Impact | partial, total | Scope of compromise if exploited |
| Automatability | no, yes | Can exploitation be automated? |
| Mission Prevalence | minimal, support, essential | Asset criticality to mission |

## Enrichment APIs

| API | Endpoint | Purpose |
|-----|----------|---------|
| CISA KEV | `known_exploited_vulnerabilities.json` | Active exploitation check |
| FIRST EPSS | `api.first.org/data/v1/epss?cve=` | Exploitation probability |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | CVSS scores, CWE |

## Decision Tree Key Paths

| Exploitation | Impact | Automatability | Prevalence | Decision |
|-------------|--------|----------------|------------|----------|
| Active | Total | any | any | Act |
| Active | Partial | Yes | any | Act |
| Active | Partial | No | Essential | Act |
| Active | Partial | No | Support | Attend |
| PoC | Total | Yes | any | Attend |
| PoC | Total | No | any | Track* |
| PoC | Partial | any | any | Track* |
| None | Total | any | any | Track* |
| None | Partial | any | any | Track |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | CISA KEV and EPSS API queries |
| `json` | stdlib | Report generation |
| `pathlib` | stdlib | Output directory management |

## References

- CISA SSVC Guide: https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc
- SEI SSVC Paper: https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=653459
- FIRST EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
