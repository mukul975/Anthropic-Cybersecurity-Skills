# KEV-Based CVE Prioritization Report Template

## Assessment Summary
| Field | Value |
|-------|-------|
| Report Date | [YYYY-MM-DD] |
| KEV Catalog Version | [Version] |
| Total CVEs Analyzed | [N] |
| KEV-Listed CVEs Found | [N] |
| Ransomware-Associated CVEs | [N] |

## Priority Distribution
| Priority | Count | % | SLA | KEV Count |
|----------|-------|---|-----|-----------|
| P1 - Emergency | [N] | [%] | 48 hours | [N] |
| P2 - Critical | [N] | [%] | 7 days | [N] |
| P3 - High | [N] | [%] | 14 days | [N] |
| P4 - Medium | [N] | [%] | 30 days | [N] |
| P5 - Low | [N] | [%] | 90 days | [N] |

## KEV-Listed Vulnerabilities in Environment
| CVE | Vendor | Product | CVSS | EPSS | Ransomware | Due Date | Status |
|-----|--------|---------|------|------|------------|----------|--------|
| [CVE-ID] | [Vendor] | [Product] | [N.N] | [0.NN] | [Y/N] | [Date] | [Open/Remediated] |

## Scoring Methodology
- **CISA KEV (30%)**: Confirmed active exploitation in the wild
- **EPSS Score (25%)**: Predicted 30-day exploitation probability
- **CVSS Base (20%)**: Intrinsic vulnerability severity
- **Asset Criticality (15%)**: Business impact tier (1-5)
- **Network Exposure (10%)**: Attack surface accessibility
