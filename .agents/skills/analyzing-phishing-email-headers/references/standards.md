# Standards & References: Analyzing Phishing Email Headers

## RFC Standards
- **RFC 5321 (SMTP)**: Simple Mail Transfer Protocol - defines how email is transmitted and the structure of Received headers
- **RFC 5322 (Internet Message Format)**: Defines the syntax of email header fields including From, To, Date, Message-ID
- **RFC 7208 (SPF)**: Sender Policy Framework - mechanism for validating email sender IP against domain policy
- **RFC 6376 (DKIM)**: DomainKeys Identified Mail - cryptographic authentication of email messages
- **RFC 7489 (DMARC)**: Domain-based Message Authentication, Reporting and Conformance
- **RFC 8601 (Authentication-Results)**: Message Header Field for Indicating Message Authentication Status

## NIST Guidelines
- **NIST SP 800-177 Rev.1**: Trustworthy Email - comprehensive guide to email security including header authentication
- **NIST SP 800-45 Ver.2**: Guidelines on Electronic Mail Security

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1566.003**: Phishing: Spearphishing via Service
- **T1534**: Internal Spearphishing

## Industry Standards
- **M3AAWG Best Practices**: Messaging, Malware and Mobile Anti-Abuse Working Group email authentication recommendations
- **DMARC.org**: Industry consortium for DMARC deployment guidance
- **Anti-Phishing Working Group (APWG)**: Phishing Activity Trends Reports

## Key Header Fields Reference

| Header Field | RFC | Purpose |
|---|---|---|
| Received | RFC 5321 | Records each SMTP hop |
| From | RFC 5322 | Display sender address |
| Return-Path | RFC 5321 | Envelope sender (bounce address) |
| Authentication-Results | RFC 8601 | SPF/DKIM/DMARC results |
| DKIM-Signature | RFC 6376 | Cryptographic signature |
| Message-ID | RFC 5322 | Unique message identifier |
| X-Originating-IP | Non-standard | Sender's IP (provider-specific) |
| X-Mailer | Non-standard | Email client identification |

## Compliance Frameworks
- **PCI DSS 4.0**: Requirement 5 - Protect All Systems and Networks from Malicious Software
- **ISO 27001:2022**: A.8.23 - Web filtering; A.5.14 - Information transfer
- **SOC 2**: CC6.1 - Logical and Physical Access Controls
