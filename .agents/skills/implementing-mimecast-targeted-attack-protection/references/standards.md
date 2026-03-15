# Standards & References: Implementing Mimecast Targeted Attack Protection

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1534**: Internal Spearphishing
- **T1598**: Phishing for Information
- **T1656**: Impersonation
- **T1204.001**: User Execution: Malicious Link
- **T1204.002**: User Execution: Malicious File

## Mimecast TTP Components
| Component | Version | Key Feature |
|---|---|---|
| URL Protect | Current | Pre-delivery hold (Nov 2025 default) |
| Attachment Protect | Current | Safe File + Dynamic sandbox |
| Impersonation Protect | Current | Hit 1 (VIP) / Hit 3 (Default) |
| Internal Email Protect | Current | Journal-based internal scanning |

## Compliance Alignment
- **CIS Controls v8 Control 9.2**: Use DNS filtering services
- **CIS Controls v8 Control 9.6**: Block unnecessary file types
- **NIST SP 800-177**: Trustworthy Email
- **SOC 2 CC6.1**: Logical and physical access controls
- **ISO 27001 A.8.23**: Web filtering

## Impersonation Protection Indicators
| Indicator | Description | Weight |
|---|---|---|
| Display name match | External sender uses internal VIP display name | High |
| Domain similarity | Sender domain visually similar to internal domain | High |
| Reply-to mismatch | Reply-to differs from From address | Medium |
| Newly observed | First-time sender to recipient | Medium |
| Header anomaly | Unusual mail routing or missing authentication | Medium |

## Integration Points
- Microsoft 365 via connector and journaling
- Google Workspace via gateway routing
- SIEM via syslog or API (Splunk, QRadar, Sentinel)
- SOAR platforms via Mimecast API
- Directory sync via Active Directory / Azure AD
