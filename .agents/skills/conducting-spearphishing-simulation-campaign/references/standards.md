# Standards and Framework References

## MITRE ATT&CK - Initial Access (TA0001)

| Technique ID | Name | Sub-technique |
|-------------|------|---------------|
| T1566.001 | Spearphishing Attachment | Malicious files delivered via email |
| T1566.002 | Spearphishing Link | URLs in emails directing to malicious content |
| T1566.003 | Spearphishing via Service | Phishing through third-party services |
| T1598.001 | Phishing for Information: Spearphishing Service | Info gathering via services |
| T1598.002 | Phishing for Information: Spearphishing Attachment | Credential harvesting attachments |
| T1598.003 | Phishing for Information: Spearphishing Link | Credential harvesting links |

## MITRE ATT&CK - Execution (TA0002)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1204.001 | User Execution: Malicious Link | User clicks phishing link |
| T1204.002 | User Execution: Malicious File | User opens malicious attachment |

## MITRE ATT&CK - Resource Development (TA0042)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1583.001 | Acquire Infrastructure: Domains | Register phishing domains |
| T1583.006 | Acquire Infrastructure: Web Services | Use web services for phishing |
| T1585.001 | Establish Accounts: Social Media | Create fake social media profiles |
| T1585.002 | Establish Accounts: Email Accounts | Create email accounts for sending |
| T1608.001 | Stage Capabilities: Upload Malware | Host payloads for download |
| T1608.005 | Stage Capabilities: Link Target | Prepare phishing URLs |

## PTES - Social Engineering

### Pre-text Creation
- Research-based pretext development
- Authority, urgency, and scarcity principles
- Robert Cialdini's principles of influence
- Corporate communication mimicry

### Attack Vectors
- Email-based spearphishing
- Voice phishing (vishing) support calls
- SMS phishing (smishing)
- Social media-based pretexting

## NIST SP 800-177 - Trustworthy Email

### Email Authentication Protocols
- SPF (Sender Policy Framework)
- DKIM (DomainKeys Identified Mail)
- DMARC (Domain-based Message Authentication)

### Email Security Controls
- Email gateway filtering
- URL rewriting and sandboxing
- Attachment analysis
- Domain reputation scoring

## CIS Controls v8

### Control 14: Security Awareness and Skills Training
- 14.1: Establish and Maintain a Security Awareness Program
- 14.2: Train Workforce Members to Recognize Social Engineering Attacks
- 14.3: Train Workforce Members on Authentication Best Practices

## Email Security Bypass Techniques Reference

| Technique | Bypasses | Risk Level |
|-----------|----------|------------|
| HTML Smuggling | Email attachment scanning | High |
| Domain Age/Reputation | New domain blocking | Medium |
| Legitimate Service Abuse | Domain reputation filters | High |
| SPF/DKIM/DMARC Alignment | Email authentication checks | Medium |
| File Format Alternatives | Attachment type blocking | Medium |
| QR Code Phishing | URL analysis engines | High |
