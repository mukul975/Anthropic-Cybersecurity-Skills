# Pass-the-Ticket Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| impacket | `pip install impacket` | Kerberos ticket manipulation (ticketer.py, getST.py) |
| ldap3 | `pip install ldap3` | AD LDAP queries for SPN and account enumeration |
| pySigma | `pip install pySigma` | Sigma rule parsing and conversion |

## Key Windows Event IDs

| Event ID | Description | Relevance |
|----------|-------------|-----------|
| 4768 | Kerberos TGT request | Golden ticket detection (RC4 = 0x17) |
| 4769 | Kerberos service ticket request | Silver ticket / Kerberoasting |
| 4770 | Kerberos service ticket renewed | Ticket reuse indicator |
| 4771 | Kerberos pre-auth failed | Password spray detection |
| 4624 | Successful logon | Correlate with ticket usage |

## Encryption Type Constants

| Value | Algorithm | Concern |
|-------|-----------|---------|
| 0x17 | RC4-HMAC | Downgrade attack indicator |
| 0x12 | AES-256 | Expected modern encryption |
| 0x11 | AES-128 | Acceptable encryption |

## MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Use Alternate Authentication Material: Pass the Ticket | T1550.003 |
| Steal or Forge Kerberos Tickets: Golden Ticket | T1558.001 |
| Steal or Forge Kerberos Tickets: Silver Ticket | T1558.002 |

## External References

- [impacket ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- [Microsoft Kerberos Event Logging](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [ADSecurity.org Kerberos Attacks](https://adsecurity.org/?p=1515)
