# QR Code Phishing Detection Template

## Quishing Detection Rules
| Rule | Condition | Action | Status |
|---|---|---|---|
| QR in image | QR code detected in embedded image | Extract URL + analyze | |
| QR in PDF | QR code detected in PDF attachment | Extract URL + analyze | |
| ASCII QR | Text-rendered QR code pattern | Decode + analyze | |
| Image-only email | Email with image but minimal text | Flag for review | |
| MFA QR theme | QR + MFA/authentication language | High priority alert | |

## Common Quishing Themes to Monitor
- [ ] MFA enrollment requiring QR code scan
- [ ] Document signing via QR code
- [ ] Voicemail access via QR code
- [ ] Package delivery confirmation QR
- [ ] IT security update with QR authentication
- [ ] Shared document access via QR

## Mobile Protection Controls
- [ ] Mobile threat defense deployed with QR scanning
- [ ] MDM policy warns before opening QR URLs
- [ ] Corporate VPN required for QR destinations
- [ ] User training on safe QR scanning completed

## Incident Response for Quishing
| Step | Action | Responsible |
|---|---|---|
| 1 | Decode QR and extract URL | SOC Analyst |
| 2 | Check if URL is active phishing page | SOC Analyst |
| 3 | Search for same email across all mailboxes | Email Admin |
| 4 | Retract email from all recipients | Email Admin |
| 5 | Block URL at web proxy/firewall | Network Security |
| 6 | Check if any user scanned and submitted credentials | SOC Lead |
| 7 | Force password reset for affected users | IAM Team |
