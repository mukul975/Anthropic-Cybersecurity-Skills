# Standards and Framework References

## MITRE ATT&CK - Credential Access (TA0006)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | Request TGS tickets for SPN accounts and crack offline |
| T1558 | Steal or Forge Kerberos Tickets | Parent technique for Kerberos attacks |

## MITRE ATT&CK - Discovery (TA0007)

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1087.002 | Account Discovery: Domain Account | Enumerate domain accounts with SPNs |
| T1069.002 | Permission Groups Discovery: Domain Groups | Identify group membership of SPN accounts |

## Kerberos Authentication Protocol

### Normal TGS Request Flow
1. Client presents TGT to KDC (Domain Controller)
2. KDC validates TGT and issues TGS ticket
3. TGS ticket is encrypted with target service account's long-term key (NTLM hash)
4. Client presents TGS to target service
5. Service decrypts ticket and validates PAC

### Kerberoasting Exploitation
1. Any domain user can request TGS for any SPN
2. TGS is encrypted with the service account password hash
3. RC4 encryption (etype 23) uses NTLM hash directly
4. AES encryption (etype 17/18) is slower to crack but still possible
5. Cracking happens offline - no failed logon events generated

## Encryption Types

| Etype | Algorithm | Hashcat Mode | Crack Difficulty |
|-------|-----------|-------------|-----------------|
| 23 | RC4-HMAC (NTLM) | 13100 | Easiest |
| 17 | AES128-CTS-HMAC-SHA1 | 19700 | Hard |
| 18 | AES256-CTS-HMAC-SHA1 | 19800 | Hardest |

## NIST SP 800-63B - Authentication Guidelines
- Recommends minimum 8-character passwords
- Service accounts should use 25+ character passwords
- Managed Service Accounts (MSA/gMSA) automatically rotate passwords

## CIS Benchmark - Kerberos Configuration
- Ensure 'Network security: Configure encryption types allowed for Kerberos' excludes RC4
- Monitor Event ID 4769 for anomalous service ticket requests
- Implement AES-only encryption for service accounts
- Use Group Managed Service Accounts where possible

## Detection References

| Event ID | Description | Relevance |
|----------|-------------|-----------|
| 4769 | Kerberos Service Ticket Operation | TGS request with etype |
| 4770 | Kerberos Service Ticket Renewed | Ticket renewal |
| 4768 | Kerberos Authentication Ticket (TGT) | Initial authentication |

### Sigma Rule Reference
```yaml
title: Kerberoasting Activity
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName: '*$'
  filter:
    ServiceName: 'krbtgt'
  condition: selection and not filter
```
