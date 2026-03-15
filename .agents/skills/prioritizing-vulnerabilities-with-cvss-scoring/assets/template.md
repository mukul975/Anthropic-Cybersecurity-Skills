# Vulnerability Prioritization Report Template

## Assessment Summary
| Field | Value |
|-------|-------|
| Report Date | [YYYY-MM-DD] |
| Assessment Period | [START] to [END] |
| Total CVEs Evaluated | [N] |
| Scoring Framework | CVSS v4.0 + EPSS + CISA KEV |

## Priority Distribution
| Priority | Count | % | SLA | Status |
|----------|-------|---|-----|--------|
| P1 - Emergency | [N] | [%] | 48 hours | [On Track/Overdue] |
| P2 - Critical | [N] | [%] | 7 days | [On Track/Overdue] |
| P3 - High | [N] | [%] | 14 days | [On Track/Overdue] |
| P4 - Medium | [N] | [%] | 30 days | [On Track/Overdue] |
| P5 - Low | [N] | [%] | 90 days | [On Track/Overdue] |

## Top 10 Prioritized Vulnerabilities
| Rank | CVE | CVSS | EPSS | KEV | Asset | Priority | SLA |
|------|-----|------|------|-----|-------|----------|-----|
| 1 | [CVE-ID] | [N.N] | [0.NN] | [Y/N] | [Asset] | P1 | 48h |

## Scoring Methodology
- **CVSS Base Score (25%)**: NVD v4.0/v3.1 base score
- **EPSS Score (25%)**: FIRST Exploit Prediction Scoring System
- **Asset Criticality (20%)**: CMDB tier rating (1-5)
- **CISA KEV Status (15%)**: Known exploited vulnerability indicator
- **Network Exposure (15%)**: Internet/DMZ/Internal exposure level

## Remediation Tracking
| Priority | Open | In Progress | Remediated | Overdue |
|----------|------|-------------|------------|---------|
| P1 | [N] | [N] | [N] | [N] |
| P2 | [N] | [N] | [N] | [N] |
