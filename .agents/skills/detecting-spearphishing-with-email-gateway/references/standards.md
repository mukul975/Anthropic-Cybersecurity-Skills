# Standards & References: Detecting Spearphishing with Email Gateway

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1566.003**: Phishing: Spearphishing via Service
- **T1598.002**: Phishing for Information: Spearphishing Attachment
- **T1598.003**: Phishing for Information: Spearphishing Link
- **T1534**: Internal Spearphishing

## NIST Guidelines
- **NIST SP 800-177 Rev.1**: Trustworthy Email
- **NIST SP 800-53 Rev.5**: SI-8 Spam Protection, SI-3 Malicious Code Protection
- **NIST CSF**: PR.AT (Awareness & Training), DE.CM (Security Continuous Monitoring)

## CIS Controls v8
- **CIS Control 9**: Email and Web Browser Protections
  - 9.1: Ensure only approved browsers and email clients are used
  - 9.2: Use DNS filtering services
  - 9.3: Maintain and enforce network-based URL filters
  - 9.6: Block unnecessary file types
  - 9.7: Deploy and maintain email server anti-malware protections

## Email Gateway Feature Matrix

| Feature | Microsoft Defender | Proofpoint | Mimecast | Barracuda |
|---|---|---|---|---|
| Impersonation detection | Anti-phishing policy | Impostor Classifier | Brand Exploit Protect | Impersonation Protection |
| URL detonation | Safe Links | URL Defense | URL Protect | Link Protection |
| Attachment sandbox | Safe Attachments | Targeted Attack Protection | Attachment Protect | Advanced Threat Protection |
| DMARC enforcement | Built-in | Built-in | DMARC Analyzer | Built-in |
| AI/ML detection | Yes (multiple models) | NexusAI | Yes | Yes |
| User reporting | Report Message add-in | PhishAlarm | Built-in | Phishline |
| SIEM integration | Microsoft Sentinel | Splunk, QRadar | Splunk, Sentinel | Various |
| Auto-remediation (ZAP) | Yes | CLEAR | Yes | Yes |

## Detection Indicators for Spearphishing

| Indicator | Weight | Description |
|---|---|---|
| Display name spoofing VIP | High | From name matches protected user but different email |
| Lookalike domain | High | Domain differs by 1-2 characters from legitimate |
| First-time sender to VIP | Medium | No prior communication history |
| Urgency keywords | Medium | "urgent", "immediately", "wire transfer", "confidential" |
| Reply-to mismatch | High | Reply-to differs from From address |
| External sender with internal branding | High | Email mimics internal templates |
| Newly registered domain | High | Sending domain < 30 days old |
| Authentication failure | High | SPF/DKIM/DMARC fail |
