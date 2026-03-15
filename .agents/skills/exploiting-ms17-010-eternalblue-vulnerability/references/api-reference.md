# API Reference: MS17-010 (EternalBlue) Detection

## CVE-2017-0144 — EternalBlue

### Affected Systems
- Windows XP, Vista, 7, 8, 8.1, 10 (pre-patch)
- Windows Server 2003, 2008, 2008 R2, 2012, 2016 (pre-patch)

### Protocol: SMBv1 (Port 445)

## Nmap NSE Script

### Check for MS17-010
```bash
nmap -p 445 --script smb-vuln-ms17-010 <target>
```

### Output (Vulnerable)
```
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers
|     Risk factor: HIGH  CVSSv2: 9.3
```

## SMB Protocol Basics

### Negotiate Protocol Request
| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | NetBIOS Session header |
| 4 | 4 | SMB magic (0xFF534D42) |
| 8 | 1 | Command (0x72 = Negotiate) |
| 9 | 4 | Status |
| 13 | 1 | Flags |

### SMB Versions
| Version | Protocol | Notes |
|---------|----------|-------|
| SMBv1 | NT LM 0.12 | Vulnerable to EternalBlue |
| SMBv2 | SMB 2.002 | Not vulnerable |
| SMBv3 | SMB 3.0 | Not vulnerable |

## Python Socket Check

### SMBv1 Connection Test
```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect((target, 445))
sock.send(SMB_NEGOTIATE_PACKET)
response = sock.recv(4096)
```

## Metasploit Module (Authorized Testing)

### Scanner
```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <target>
run
```

### Detection Events

| Source | Indicator |
|--------|-----------|
| Windows Event 7036 | Service state change |
| Sysmon Event 3 | Network connection to 445 |
| IDS | Signature for EternalBlue SMB exploit |

## Remediation
1. Apply MS17-010 patch (KB4012598 / KB4013389)
2. Disable SMBv1: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`
3. Block port 445 at network perimeter
4. Enable Windows Firewall rules for SMB

## Suricata Detection Rule
```
alert tcp any any -> $HOME_NET 445 (msg:"ET EXPLOIT EternalBlue Attempt";
  flow:established,to_server; content:"|ff|SMB|73|";
  content:"|08 00|"; within:2; distance:54; sid:2024217;)
```
