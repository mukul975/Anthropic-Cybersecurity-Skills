# API Reference: SOC 2 Type II Audit Preparation

## Trust Services Criteria (TSC) Categories

| Category | Series | Required | Focus |
|----------|--------|----------|-------|
| Security | CC1-CC9 | Mandatory | Protection against unauthorized access |
| Availability | A1 | Optional | System uptime and availability |
| Processing Integrity | PI1 | Optional | Accurate and complete processing |
| Confidentiality | C1 | Optional | Confidential data protection |
| Privacy | P1-P8 | Optional | Personal information handling |

## Common Criteria Series

| Series | Focus | Key Controls |
|--------|-------|-------------|
| CC6.1 | Logical access | MFA, SSO, RBAC implementation |
| CC6.3 | Access removal | Termination deprovisioning within 24h |
| CC6.6 | Access reviews | Quarterly user access certification |
| CC7.1 | Detection | SIEM monitoring, vulnerability scanning |
| CC7.2 | Incident response | IR plan, tabletop exercises |
| CC8.1 | Change management | Approval workflow, testing, rollback |

## Evidence Collection Frequencies

| Frequency | Expected Samples | Examples |
|-----------|-----------------|----------|
| Continuous | 1+ config proof | SSO MFA config, firewall rules |
| Per-event | Population sample | Change tickets, offboarding records |
| Weekly | 52 per year | Vulnerability scan reports |
| Monthly | 12 per year | Access review summaries |
| Quarterly | 4 per year | Access certification campaigns |
| Annual | 1 per year | Penetration test, risk assessment |

## GRC Platforms

| Platform | Purpose |
|----------|---------|
| Vanta | Automated SOC 2 evidence collection |
| Drata | Continuous compliance monitoring |
| Secureframe | SOC 2 readiness and evidence management |
| AuditBoard | Enterprise GRC and audit management |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Control matrix and report generation |
| `datetime` | stdlib | Audit period and evidence date tracking |
| `collections` | stdlib | Criteria coverage aggregation |

## References

- AICPA TSC 2017: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
- COSO 2013 Framework: https://www.coso.org/guidance-on-ic
- Secureframe SOC 2 Guide: https://secureframe.com/hub/soc-2/trust-services-criteria
- Vanta SOC 2: https://www.vanta.com/collection/soc-2
