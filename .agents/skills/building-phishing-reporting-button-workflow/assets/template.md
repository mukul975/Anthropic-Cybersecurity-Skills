# Phishing Reporting Button Workflow Template

## Reporting Button Configuration
| Setting | Value | Status |
|---|---|---|
| Button type | Microsoft built-in Report | |
| Reporting mailbox | phishing-reports@company.com | |
| Also send to Microsoft | Yes | |
| Supported platforms | Desktop, Web, Mobile | |

## Triage Automation Rules
| Classification | Criteria | Auto-Action |
|---|---|---|
| Confirmed Phishing | Score >= 50 | Retract + Block sender |
| Suspicious | Score 25-49 | Escalate to SOC analyst |
| Spam | Score 10-24 | Move to junk for all |
| Simulation | Matches sim subject | Credit reporter |
| Clean | Score < 10 | Return to inbox |

## Reporting Metrics Dashboard
| Metric | Target | Current |
|---|---|---|
| Report volume (monthly) | | |
| Mean time to triage | < 10 min | |
| Confirmed phishing caught | | |
| User report rate (sim) | > 70% | |
| False positive rate | < 30% | |
| Top reporter recognition | Monthly | |
