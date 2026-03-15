# Standards & References: Performing DMARC Policy Enforcement Rollout

## Core Protocol Standards
- **RFC 7489**: Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- **RFC 7208**: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email
- **RFC 6376**: DomainKeys Identified Mail (DKIM) Signatures
- **RFC 8616**: Email Authentication for Internationalized Mail
- **RFC 8601**: Message Header Field for Indicating Message Authentication Status

## Regulatory Requirements (2025)
- **Google Bulk Sender Requirements**: DMARC required for senders of 5,000+ messages/day to Gmail
- **Yahoo Sender Requirements**: DMARC authentication required for bulk senders
- **PCI DSS 4.0 Requirement 5.3**: Anti-phishing mechanisms including email authentication
- **NIST SP 800-177 Rev.1**: Trustworthy Email guidance

## DMARC Policy Progression
| Phase | Duration | Record | pct | Monitoring |
|---|---|---|---|---|
| Discovery | 2-4 weeks | p=none | N/A | Daily report review |
| Soft enforce | 4-6 weeks | p=quarantine | 10->100 | Twice-weekly review |
| Hard enforce | 4-6 weeks | p=reject | 10->100 | Weekly review |
| Maintenance | Ongoing | p=reject | 100 | Monthly review |

## SPF Lookup Limit
- Maximum 10 DNS lookups per SPF evaluation (RFC 7208 Section 4.6.4)
- Each `include:`, `a:`, `mx:`, `redirect=`, and `exists:` counts as one lookup
- Exceeding 10 lookups causes SPF permerror (treated as fail by some receivers)
- Use SPF flattening tools to stay within limit

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1586.002**: Compromise Accounts: Email Accounts
- **T1656**: Impersonation
