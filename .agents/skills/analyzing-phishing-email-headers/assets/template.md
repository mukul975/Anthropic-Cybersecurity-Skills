# Phishing Email Header Analysis Report Template

## Report Information
- **Analyst**: [Name]
- **Date**: [YYYY-MM-DD]
- **Case ID**: [CASE-XXXX]
- **Classification**: [Phishing / Spear-phishing / BEC / Legitimate]

## Email Summary
| Field | Value |
|---|---|
| From | |
| To | |
| Subject | |
| Date Received | |
| Message-ID | |

## Authentication Results
| Check | Result | Domain | Notes |
|---|---|---|---|
| SPF | pass/fail/none | | |
| DKIM | pass/fail/none | | |
| DMARC | pass/fail/none | | |

## Sender Analysis
| Field | Value | Match From? |
|---|---|---|
| From (header) | | N/A |
| Return-Path (envelope) | | Yes/No |
| Reply-To | | Yes/No |
| X-Originating-IP | | |
| X-Mailer | | |

## Routing Analysis
| Hop | Server From | Server By | IP | Location | Time |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

## Indicators of Compromise (IOCs)
### IP Addresses
| IP | Source | Reputation | Location |
|---|---|---|---|
| | | | |

### Domains
| Domain | Source | Age | Reputation |
|---|---|---|---|
| | | | |

### URLs
| URL | Context | Status |
|---|---|---|
| | | |

## Phishing Indicators Found
| # | Category | Description | Severity |
|---|---|---|---|
| 1 | | | |
| 2 | | | |
| 3 | | | |

## Risk Assessment
- **Risk Score**: [0-100]
- **Risk Level**: [CLEAN / LOW / MEDIUM / HIGH / CRITICAL]
- **Confidence**: [Low / Medium / High]

## Recommended Actions
- [ ] Block sender domain at email gateway
- [ ] Add originating IP to blocklist
- [ ] Submit IOCs to threat intelligence platform
- [ ] Notify affected users
- [ ] Check for similar messages in mail logs
- [ ] Update email filtering rules
- [ ] Report to anti-phishing databases (PhishTank, APWG)

## Evidence Chain
| Item | Hash (SHA-256) | Description |
|---|---|---|
| Original .eml | | Raw email file |
| Headers export | | Extracted headers |
| Screenshots | | Visual evidence |

## Notes
[Additional observations, context, or analysis notes]
