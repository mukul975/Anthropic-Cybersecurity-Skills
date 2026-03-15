# URL Analysis Report Template

## Analysis Information
- **Analyst**: [Name]
- **Date**: [YYYY-MM-DD]
- **Case ID**: [CASE-XXXX]
- **Source**: [User report / Email gateway / SIEM alert]

## URL Details
| Field | Value |
|---|---|
| Original URL | |
| Defanged URL | hxxps://... |
| Final URL (after redirects) | |
| URLScan UUID | |
| Scan visibility | private/public |

## Page Analysis
| Field | Value |
|---|---|
| Page Title | |
| HTTP Status | |
| Server | |
| Domain | |
| IP Address | |
| ASN | |
| Country | |
| Login Form Detected | Yes/No |

## TLS Certificate
| Field | Value |
|---|---|
| Issuer | |
| Subject | |
| Valid From | |
| Valid To | |
| Certificate Age | |

## Redirect Chain
| # | URL | Status |
|---|---|---|
| 1 (original) | | |
| 2 | | |
| 3 (final) | | |

## Threat Intelligence Cross-Reference
| Source | Result | Score |
|---|---|---|
| URLScan Verdict | | |
| VirusTotal | /XX engines | |
| PhishTank | | |
| Google Safe Browsing | | |
| AbuseIPDB | | |

## IOCs Extracted
### Domains
| Domain | Role | Reputation |
|---|---|---|
| | | |

### IP Addresses
| IP | ASN | Country | Reputation |
|---|---|---|---|
| | | | |

### File Hashes
| Hash (SHA-256) | Type | Size |
|---|---|---|
| | | |

## Classification
- [ ] Phishing - Credential Harvesting
- [ ] Phishing - Malware Delivery
- [ ] Scam / Fraud
- [ ] Benign
- [ ] Inconclusive

## Recommended Actions
- [ ] Block domain at proxy/firewall
- [ ] Block IP at firewall
- [ ] Add to email gateway blocklist
- [ ] Submit to PhishTank / APWG
- [ ] Notify affected users
- [ ] Request domain takedown

## Notes
[Additional analysis observations]
