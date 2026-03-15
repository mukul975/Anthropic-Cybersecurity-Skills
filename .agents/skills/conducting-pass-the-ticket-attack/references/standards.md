# Standards and Framework References

## MITRE ATT&CK

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | Lateral Movement |
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access |
| T1558 | Steal or Forge Kerberos Tickets | Credential Access |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement |

## Kerberos Ticket Types

| Ticket | Purpose | Lifetime | Encryption |
|--------|---------|----------|-----------|
| TGT (Ticket Granting Ticket) | Authenticates to KDC for TGS requests | 10 hours default | krbtgt NTLM hash |
| TGS (Ticket Granting Service) | Authenticates to specific service | 10 hours default | Service account hash |

## Detection - Windows Event IDs

| Event ID | Description | PtT Indicator |
|----------|-------------|---------------|
| 4768 | TGT Request | Unusual source IP for known user |
| 4769 | TGS Request | Service access from unexpected host |
| 4770 | TGT Renewal | Renewal from different IP than original |
| 4771 | Kerberos Pre-Auth Failed | May indicate ticket reuse attempts |

## NIST SP 800-171
- 3.5.1: Identify system users, processes acting on behalf of users
- 3.5.2: Authenticate identities before allowing access
- 3.1.1: Limit system access to authorized users

## CIS Controls
- Control 6: Access Control Management
- Control 8: Audit Log Management - Monitor Kerberos authentication events
