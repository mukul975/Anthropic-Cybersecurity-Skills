# Google Workspace Phishing Protection Configuration Template

## Safety Settings Checklist
- [ ] Domain spoofing protection enabled
- [ ] Employee name spoofing protection enabled
- [ ] Enhanced pre-delivery scanning enabled
- [ ] Encrypted attachment protection enabled
- [ ] Script attachment protection enabled
- [ ] Anomalous attachment type protection enabled
- [ ] Enhanced Safe Browsing enabled
- [ ] Security Sandbox enabled (Enterprise)

## Advanced Protection Program Enrollment
| User | Role | APP Enrolled | FIDO2 Key |
|---|---|---|---|
| | Super Admin | | |
| | CEO | | |
| | CFO | | |
| | VP Finance | | |

## Authentication Configuration
| Protocol | Status | Record |
|---|---|---|
| SPF | | v=spf1 include:_spf.google.com -all |
| DKIM | | google._domainkey.{domain} |
| DMARC | | v=DMARC1; p=reject; rua=... |
