# Standards & References: DMARC, DKIM, and SPF Email Security

## RFC Standards
- **RFC 7208 (SPF)**: Sender Policy Framework - authorizing sending hosts via DNS
- **RFC 6376 (DKIM)**: DomainKeys Identified Mail Signatures
- **RFC 7489 (DMARC)**: Domain-based Message Authentication, Reporting and Conformance
- **RFC 8301**: Cryptographic Algorithm and Key Usage Update to DKIM (mandates RSA 2048-bit minimum)
- **RFC 8616**: Email Authentication for Internationalized Mail
- **RFC 8617 (ARC)**: Authenticated Received Chain - preserving authentication through forwarding
- **RFC 7960**: Interoperability Issues between DMARC and Indirect Email Flows
- **RFC 6591**: Authentication Failure Reporting Using ARF
- **RFC 8601**: Authentication-Results header field

## NIST Guidelines
- **NIST SP 800-177 Rev.1**: Trustworthy Email - comprehensive email security deployment guide
  - Section 4.3: Sender Policy Framework
  - Section 4.4: DKIM
  - Section 4.5: DMARC
- **NIST SP 800-45 Ver.2**: Guidelines on Electronic Mail Security

## Government Mandates
- **BOD 18-01 (CISA/DHS)**: Binding Operational Directive requiring all federal agencies to implement DMARC p=reject
- **UK NCSC Mail Check**: Mandates DMARC for government domains
- **Australian ASD Essential Eight**: DMARC listed as a mitigation strategy

## MITRE ATT&CK
- **T1566**: Phishing (all sub-techniques)
- **T1586.002**: Compromise Accounts: Email Accounts
- **T1585.002**: Establish Accounts: Email Accounts

## Industry Best Practices
- **M3AAWG DMARC Training Series**: Messaging Anti-Abuse Working Group deployment guide
- **DMARC.org Implementation Guide**: Step-by-step deployment methodology
- **Google Email Authentication Requirements (2024)**: Bulk senders must have SPF, DKIM, and DMARC

## SPF Syntax Reference

| Mechanism | Description | Example |
|---|---|---|
| `ip4:` | IPv4 address/range | `ip4:192.168.1.0/24` |
| `ip6:` | IPv6 address/range | `ip6:2001:db8::/32` |
| `include:` | Include domain SPF | `include:_spf.google.com` |
| `a` | Domain A record IPs | `a:mail.example.com` |
| `mx` | Domain MX record IPs | `mx` |
| `redirect=` | Use another domain's SPF | `redirect=_spf.example.com` |
| `-all` | Hard fail | Reject unauthorized |
| `~all` | Soft fail | Mark but deliver |
| `?all` | Neutral | No assertion |

## DMARC Tag Reference

| Tag | Required | Description | Values |
|---|---|---|---|
| `v` | Yes | Version | `DMARC1` |
| `p` | Yes | Policy | `none`, `quarantine`, `reject` |
| `rua` | No | Aggregate report URI | `mailto:reports@example.com` |
| `ruf` | No | Forensic report URI | `mailto:forensic@example.com` |
| `pct` | No | Percentage of messages | `0-100` (default 100) |
| `sp` | No | Subdomain policy | `none`, `quarantine`, `reject` |
| `adkim` | No | DKIM alignment | `r` (relaxed), `s` (strict) |
| `aspf` | No | SPF alignment | `r` (relaxed), `s` (strict) |
| `fo` | No | Failure reporting | `0`, `1`, `d`, `s` |
