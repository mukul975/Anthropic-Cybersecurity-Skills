# Asset Criticality Scoring for Vulnerability Prioritization — API Reference

## Criticality Scoring Factors

| Factor | Weight | Description |
|--------|--------|-------------|
| Data Sensitivity | 0.25 | Classification of data stored/processed |
| Business Function | 0.20 | Revenue/operational importance |
| Regulatory Scope | 0.15 | Compliance frameworks in scope |
| Network Exposure | 0.20 | Internet-facing vs air-gapped |
| Recoverability | 0.10 | Recovery time and capability |
| User Count | 0.10 | Number of users impacted |

## Data Sensitivity Levels

| Level | Score | Examples |
|-------|-------|---------|
| Public | 1 | Marketing website, public docs |
| Internal | 2 | Internal wiki, employee tools |
| Confidential | 3 | Financial reports, source code |
| PII | 4 | Customer names, emails, addresses |
| PCI/PHI | 5 | Credit card data, health records |

## Criticality Tiers

| Tier | Score Range | Name | Remediation SLA (Critical) |
|------|------------|------|---------------------------|
| 1 | >= 4.0 | Crown Jewel | 24 hours |
| 2 | 3.0 - 3.9 | Business Critical | 48 hours |
| 3 | 2.0 - 2.9 | Important | 7 days |
| 4 | 1.5 - 1.9 | Standard | 14 days |
| 5 | < 1.5 | Low Impact | 30 days |

## Risk-Adjusted Priority Formula

```
adjusted_priority = min(CVSS_score * tier_multiplier, 10.0)
Tier multipliers: {1: 1.5, 2: 1.3, 3: 1.0, 4: 0.8, 5: 0.5}
```

## CSV Inventory Format

```csv
hostname,data_classification,business_function,regulatory_scope,network_exposure,recoverability,user_count
db-prod-01,pci,revenue-generating,pci-dss,dmz,manual-recovery,50000
web-staging,internal,staging,none,vpn-accessible,auto-recovery,10
```

## Integration Points

| System | Purpose |
|--------|---------|
| CMDB (ServiceNow, Qualys) | Asset metadata source |
| Vulnerability Scanner | CVSS scores for risk adjustment |
| Ticketing (Jira, ServiceNow) | SLA-driven remediation tracking |
| SIEM | Alert priority enrichment |

## External References

- [NIST SP 800-30 Risk Assessment](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CISA Stakeholder-Specific Vulnerability Categorization](https://www.cisa.gov/ssvc)
