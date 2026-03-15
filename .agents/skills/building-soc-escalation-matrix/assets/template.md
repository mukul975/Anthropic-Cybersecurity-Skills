# SOC Escalation Matrix Template

## Priority Definitions

| Priority | Response SLA | Resolution SLA | Assigned Tier | Mgmt Notification |
|---|---|---|---|---|
| P1 - Critical | 15 min | 4 hours | Tier 3 | 30 min |
| P2 - High | 30 min | 8 hours | Tier 2 | 2 hours |
| P3 - Medium | 4 hours | 24 hours | Tier 1 | As needed |
| P4 - Low | 8 hours | 72 hours | Tier 1 | Weekly |

## Escalation Contacts

| Role | Name | Phone | Email | Availability |
|---|---|---|---|---|
| Tier 1 Lead | | | | 24/7 |
| Tier 2 Lead | | | | 24/7 |
| Tier 3 Lead | | | | On-call |
| SOC Manager | | | | Business hours + on-call |
| CISO | | | | On-call for P1 |

## Auto-Escalation Rules

| Trigger | Priority | Action |
|---|---|---|
| Ransomware detected | P1 | Tier 3 + CISO |
| Domain admin compromise | P1 | Tier 3 + CISO |
| Active data exfiltration | P1 | Tier 3 + CISO |
| Executive account anomaly | P2 | Tier 2 + SOC Manager |
| SLA breach | +1 Tier | Notify SOC Manager |
