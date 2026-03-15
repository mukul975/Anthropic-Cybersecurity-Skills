# Email Sandboxing Configuration Template (Proofpoint TAP)

## Deployment Info
- **Product**: Proofpoint Email Protection + TAP
- **Deployment Date**: [YYYY-MM-DD]
- **MX Records Updated**: Yes/No
- **SIEM Integration**: [Splunk / Sentinel / QRadar]

## Attachment Sandbox Policy
| File Type | Action | Sandbox Env | Timeout |
|---|---|---|---|
| .exe, .dll, .scr | Detonate + Block | Win10, Win11 | 120s |
| .doc(m), .xls(m), .ppt(m) | Detonate (dynamic delivery) | Win10 + Office | 90s |
| .pdf | Detonate | Win10 + Reader | 60s |
| .zip, .rar, .7z | Extract + Detonate contents | All | 120s |
| .iso, .img | Detonate | Win10 | 120s |
| .js, .vbs, .ps1, .bat | Block (no detonation) | N/A | N/A |

## URL Defense Policy
| Setting | Value |
|---|---|
| URL rewriting | All inbound email |
| Time-of-click analysis | Enabled |
| Block malicious URLs | Yes |
| Suspicious URL interstitial | Enabled |
| Allowed domains bypass | [list internal domains] |

## Monitoring Checklist
- [ ] Daily: Review TAP Dashboard threat digest
- [ ] Daily: Check quarantine for false positives
- [ ] Weekly: Review VAP list
- [ ] Weekly: Analyze threat trends
- [ ] Monthly: Generate executive threat report
- [ ] Quarterly: Policy tuning review
