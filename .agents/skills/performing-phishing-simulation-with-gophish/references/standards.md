# Standards & References: Phishing Simulation with GoPhish

## Legal & Compliance Framework
- **Computer Fraud and Abuse Act (CFAA)**: Ensure written authorization before conducting simulations
- **GDPR (EU)**: Data protection requirements for handling employee email addresses and click data
- **CCPA (California)**: Employee data privacy considerations
- **Company Acceptable Use Policy**: Must align simulation with organizational policies

## Industry Standards
- **NIST SP 800-50**: Building an Information Technology Security Awareness and Training Program
- **NIST SP 800-16**: Information Technology Security Training Requirements
- **SANS Security Awareness Maturity Model**: Five levels from non-existent to metrics framework
- **ISO 27001:2022**: A.6.3 - Information security awareness, education and training

## MITRE ATT&CK References
- **T1566.001**: Phishing: Spearphishing Attachment
- **T1566.002**: Phishing: Spearphishing Link
- **T1598**: Phishing for Information
- **T1204.001**: User Execution: Malicious Link
- **T1204.002**: User Execution: Malicious File

## GoPhish Technical Reference

### API Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `/api/campaigns/` | GET | List all campaigns |
| `/api/campaigns/` | POST | Create new campaign |
| `/api/campaigns/{id}` | GET | Get campaign details |
| `/api/campaigns/{id}/results` | GET | Get campaign results |
| `/api/campaigns/{id}/summary` | GET | Get campaign summary |
| `/api/templates/` | GET/POST | Manage email templates |
| `/api/pages/` | GET/POST | Manage landing pages |
| `/api/smtp/` | GET/POST | Manage sending profiles |
| `/api/groups/` | GET/POST | Manage user groups |
| `/api/import/email` | POST | Import email template |
| `/api/import/site` | POST | Import/clone website |

### Campaign Event Types
| Event | Description |
|---|---|
| Email Sent | Email delivered to target |
| Email Opened | Tracking pixel loaded |
| Clicked Link | User clicked phishing URL |
| Submitted Data | User entered credentials |
| Email Reported | User reported via plugin |

## Phishing Simulation Best Practices
1. **Always obtain written authorization** from executive management
2. **Coordinate with IT/security teams** to whitelist simulation infrastructure
3. **Start with easier-to-identify phishing** and increase difficulty gradually
4. **Never punish employees** for failing - focus on education
5. **Provide immediate training** after user interaction
6. **Run campaigns regularly** (monthly/quarterly) for sustained awareness
7. **Vary scenarios** across campaign types (credential harvesting, attachment, link)
8. **Respect opt-outs** where legally required
9. **Protect campaign data** - treat click/submit data as sensitive
10. **Report metrics anonymously** when possible at department level
