# Standards & References: Building Phishing Reporting Button Workflow

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1204**: User Execution
- **D3-RERE**: User Reporting (MITRE D3FEND)

## Industry Standards
- **NIST SP 800-61 Rev.2**: Computer Security Incident Handling Guide
- **CIS Controls v8 Control 14**: Security Awareness and Skills Training
- **ISO 27001 A.6.3**: Information Security Awareness, Education and Training

## Reporting Platform Comparison
| Platform | Type | Integration | Auto-Triage |
|---|---|---|---|
| Microsoft Report Button | Built-in | M365 native | Via Sentinel/API |
| Cofense Reporter + Triage | Third-party | M365, Google | Yes (Cofense Triage) |
| KnowBe4 PAB | Third-party | M365, Google | Yes (KMSAT) |
| Proofpoint CLEAR | Third-party | M365, Google | Yes (built-in) |
| Hoxhunt | Third-party | M365, Google | Yes (AI-powered) |

## Key Metrics
- **Report Rate**: Percentage of phishing simulations reported (target: >70%)
- **Mean Time to Triage**: Time from report to classification (target: <10 min)
- **False Positive Rate**: Legitimate emails reported as phishing
- **Threat Catch Rate**: Real threats first detected by user reports
- **Reporter Accuracy**: Percentage of reports that are actual threats
