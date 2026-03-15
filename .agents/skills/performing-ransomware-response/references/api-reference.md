# API Reference: Ransomware Response

## Ransomware Identification Services

| Service | URL | Purpose |
|---------|-----|---------|
| ID Ransomware | https://id-ransomware.malwarehunterteam.com/ | Upload ransom note or sample for identification |
| NoMoreRansom | https://www.nomoreransom.org/en/decryption-tools.html | Free decryption tools |
| CISA StopRansomware | https://www.cisa.gov/stopransomware | Federal guidance and resources |

## OFAC Sanctions Screening

| Resource | URL | Purpose |
|----------|-----|---------|
| OFAC SDN List | https://sanctionssearch.ofac.treas.gov/ | Check if ransomware group is sanctioned |
| OFAC Advisory | https://home.treasury.gov/policy-issues/financial-sanctions | Ransomware payment guidance |

## Key Containment Commands

| Action | Command | Description |
|--------|---------|-------------|
| Block SMB | `netsh advfirewall firewall add rule name="Block SMB" dir=in action=block protocol=TCP localport=445` | Block lateral movement |
| Block RDP | `netsh advfirewall firewall add rule name="Block RDP" dir=in action=block protocol=TCP localport=3389` | Block RDP |
| Disable account | `Disable-ADAccount -Identity <username>` | Disable compromised AD account |

## Recovery Validation

| Check | Command | Description |
|-------|---------|-------------|
| Backup integrity | `veeamcli verify` | Verify backup is not encrypted |
| Password reset | `Set-ADAccountPassword` | Reset all domain passwords |
| DC health | `dcdiag /v` | Validate rebuilt domain controller |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `requests` | >=2.28 | Query ransomware identification APIs |
| `hashlib` | stdlib | Hash encrypted file samples |
| `json` | stdlib | Incident tracking and reporting |

## References

- CISA Ransomware Guide: https://www.cisa.gov/stopransomware/ransomware-guide
- NIST SP 1800-26: https://www.nccoe.nist.gov/data-integrity-recovering-ransomware
- NoMoreRansom: https://www.nomoreransom.org/
- Veeam recovery: https://www.veeam.com/ransomware-recovery.html
