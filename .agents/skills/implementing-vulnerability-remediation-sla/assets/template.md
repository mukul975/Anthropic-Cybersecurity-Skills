# Vulnerability Remediation SLA Policy Template

## 1. Purpose
This policy defines mandatory timeframes for remediating identified vulnerabilities based on severity and asset criticality.

## 2. SLA Matrix
| Severity | Tier 1 | Tier 2 | Tier 3 |
|----------|--------|--------|--------|
| Critical | 48h | 72h | 7 days |
| High | 7 days | 14 days | 30 days |
| Medium | 30 days | 45 days | 60 days |
| Low | 90 days | 90 days | 90 days |

## 3. Escalation Procedure
| Threshold | Action | Notification |
|-----------|--------|-------------|
| 75% elapsed | Warning | Asset Owner |
| SLA breach | Escalation L1 | Manager + Security |
| Breach + 7d | Escalation L2 | Director |
| Breach + 30d | Risk Acceptance | CISO |

## 4. Exception Process
- Requestor: [Asset owner name]
- Justification: [Reason for exception]
- Compensating Controls: [Mitigations in place]
- New Deadline: [Extended date]
- Approved By: [Security leadership]

## 5. Monthly Compliance Report
| Metric | This Month | Last Month | Trend |
|--------|-----------|------------|-------|
| Compliance Rate | [%] | [%] | [arrow] |
| MTTR (Critical) | [N days] | [N days] | [arrow] |
| Open Breaches | [N] | [N] | [arrow] |
