# Standards and References: Kerberoasting with Impacket

## MITRE ATT&CK Techniques

### Primary Technique
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting
  - Tactic: Credential Access (TA0006)
  - Platforms: Windows
  - Data Sources: Active Directory (Credential Request), Logon Session (Logon Session Metadata)
  - Detection: MITRE DET0157

### Related Techniques
- **T1558** - Steal or Forge Kerberos Tickets (parent)
- **T1558.004** - AS-REP Roasting
- **T1558.001** - Golden Ticket
- **T1558.002** - Silver Ticket
- **T1087.002** - Account Discovery: Domain Account
- **T1110.002** - Brute Force: Password Cracking

### APT Groups Known to Use Kerberoasting
- **APT29** (Cozy Bear / MITRE G0016)
- **FIN7** (MITRE G0046)
- **Wizard Spider** (MITRE G0102)
- **HAFNIUM** (MITRE G0125)
- **Sandworm Team** (MITRE G0034)

## NIST References

- **NIST SP 800-53 Rev. 5** - IA-5: Authenticator Management (strong service account passwords)
- **NIST SP 800-53 Rev. 5** - AC-6: Least Privilege (service account permissions)
- **NIST SP 800-63B** - Digital Identity Guidelines (password complexity)
- **NIST SP 800-171** - 3.5.7: Store and transmit only cryptographically-protected passwords

## Windows Security Events

| Event ID | Description | Relevance |
|---|---|---|
| 4769 | A Kerberos service ticket was requested | Primary detection (check Encryption Type) |
| 4768 | A Kerberos authentication ticket (TGT) was requested | Correlate with source of TGS requests |
| 4770 | A Kerberos service ticket was renewed | Renewal of Kerberoasted tickets |
| 4771 | Kerberos pre-authentication failed | Related: AS-REP Roasting detection |

## Kerberos Encryption Types

| Etype Value | Algorithm | Crackable | Hashcat Mode |
|---|---|---|---|
| 0x17 (23) | RC4-HMAC | Fast cracking | 13100 |
| 0x11 (17) | AES128-CTS-HMAC-SHA1-96 | Slower cracking | 19600 |
| 0x12 (18) | AES256-CTS-HMAC-SHA1-96 | Slowest cracking | 19700 |

## CIS Benchmarks
- **CIS Microsoft Windows Server 2022** - 2.3.6.4: Network security: Configure encryption types for Kerberos
- **CIS Active Directory** - Service account management requirements
- **CIS Controls v8** - Control 5.4: Restrict Administrator Privileges to Dedicated Accounts
