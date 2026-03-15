# Email Gateway Spearphishing Detection Configuration Template

## Gateway Information
- **Product**: [Microsoft Defender for O365 / Proofpoint / Mimecast / Barracuda]
- **Version**: []
- **Configuration Date**: [YYYY-MM-DD]
- **Configured By**: []

## VIP Protection List
| Name | Title | Email | Risk Level |
|---|---|---|---|
| | CEO | | Critical |
| | CFO | | Critical |
| | CTO | | Critical |
| | VP Finance | | High |
| | HR Director | | High |

## Impersonation Detection Rules
| Rule | Trigger | Action | Severity |
|---|---|---|---|
| VIP display name match | External email with VIP name | Quarantine + Alert | Critical |
| Lookalike domain | Levenshtein distance <= 2 | Quarantine | High |
| First-time sender to VIP | No prior communication | Tag warning | Medium |
| Reply-to mismatch | Reply-to differs from From | Tag + Log | Medium |

## URL Protection Settings
| Setting | Value |
|---|---|
| URL rewriting enabled | Yes |
| Time-of-click verification | Yes |
| Block new domains (< days) | 30 |
| Follow redirects | Yes (max 5 hops) |
| Detonate suspicious URLs | Yes |

## Attachment Protection Settings
| Setting | Value |
|---|---|
| Sandbox detonation | Enabled |
| Dynamic delivery | Enabled |
| Block macros from external | Yes |
| Block executable types | .exe, .scr, .bat, .cmd, .ps1, .vbs, .js |

## Alert Configuration
| Event | Alert Method | Recipients |
|---|---|---|
| VIP impersonation detected | Email + SIEM | SOC team |
| Credential harvest URL blocked | SIEM | SOC team |
| Malicious attachment blocked | Email + SIEM | SOC team |
| DMARC failure from partner domain | Email | Email admin |

## Quarterly Review Checklist
- [ ] Update VIP protection list
- [ ] Review false positive rates
- [ ] Analyze user-reported phishing misses
- [ ] Update domain allow/block lists
- [ ] Test detection with simulated phishing
- [ ] Review and update custom rules
- [ ] Verify SIEM integration working
