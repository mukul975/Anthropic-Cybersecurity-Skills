# Standards & References: Detecting Business Email Compromise

## FBI IC3 BEC Classification
- **Type 1**: CEO Fraud / Executive Impersonation
- **Type 2**: Account Compromise (compromised employee email)
- **Type 3**: False Invoice / Vendor Email Compromise
- **Type 4**: Attorney Impersonation
- **Type 5**: Data Theft (W-2/PII requests)

## MITRE ATT&CK References
- **T1566.001/002**: Phishing (initial access for BEC)
- **T1534**: Internal Spearphishing
- **T1114.003**: Email Collection: Email Forwarding Rule
- **T1098.002**: Account Manipulation: Additional Email Delegate Access
- **T1586.002**: Compromise Accounts: Email Accounts

## NIST / Regulatory
- **NIST SP 800-177 Rev.1**: Trustworthy Email
- **FinCEN Advisory FIN-2019-A005**: Advisory on BEC targeting businesses
- **FBI IC3 Annual Report**: BEC statistics and trends ($2.9B losses in 2023)

## Detection Rule Categories
| Rule | Description | Priority |
|---|---|---|
| VIP impersonation | External email with internal VIP display name | Critical |
| Payment language | Wire transfer/payment keywords + urgency | High |
| Reply-to mismatch | Reply-to domain differs from From | High |
| First-time sender | No prior communication with recipient | Medium |
| Forwarding rule | New auto-forward rule to external address | Critical |
| Gift card request | Request for gift card purchase | High |
| Vendor change | Payment detail change notification | High |
