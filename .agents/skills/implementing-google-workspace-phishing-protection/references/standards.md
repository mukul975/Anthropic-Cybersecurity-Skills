# Standards & References: Google Workspace Phishing Protection

## Google Workspace Security Settings Path
- Admin Console > Apps > Google Workspace > Gmail > Safety
- Admin Console > Security > Gmail Enhanced Safe Browsing
- Admin Console > Apps > Google Workspace > Gmail > Authenticate email

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1656**: Impersonation
- **T1586.002**: Compromise Accounts: Email Accounts

## Key Protection Settings
| Setting | Location | Default | Recommended |
|---|---|---|---|
| Domain spoofing protection | Safety | Off | On - Quarantine |
| Employee name spoofing | Safety | Off | On - Warning |
| Pre-delivery scanning | Safety | On | On (enhanced) |
| Attachment protection | Safety | Partial | Full - all options |
| Enhanced Safe Browsing | Security | Off | On |
| Gmail Security Sandbox | Safety | Off | On (Enterprise) |

## Google Workspace License Requirements
| Feature | Business Starter | Business Standard | Enterprise |
|---|---|---|---|
| Basic phishing protection | Yes | Yes | Yes |
| Enhanced pre-delivery scanning | Yes | Yes | Yes |
| Gmail Security Sandbox | No | No | Yes |
| Security Investigation Tool | No | Partial | Yes |
| Advanced Protection Program | Yes | Yes | Yes |
