# Internal Network Penetration Test — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| ldap3 | `pip install ldap3` | LDAP queries for AD enumeration |
| impacket | `pip install impacket` | SMB relay, credential dumping, lateral movement tools |
| python-nmap | `pip install python-nmap` | Python wrapper for nmap scanning |

## Key Tools & Commands

| Tool | Command | Purpose |
|------|---------|---------|
| nmap | `nmap -sV -sC --top-ports 1000 <target>` | Service version and script scan |
| Responder | `responder -I eth0 -A` | LLMNR/NBT-NS poisoning (analyze mode) |
| CrackMapExec | `cme smb <target> --gen-relay-list` | Find hosts with SMB signing disabled |
| BloodHound | `bloodhound-python -d domain -u user -p pass` | AD attack path mapping |
| ntlmrelayx | `ntlmrelayx.py -t <target> -smb2support` | NTLM relay attack |

## Common Internal Vulnerabilities

| Vulnerability | Impact | CVSS |
|--------------|--------|------|
| SMB signing disabled | NTLM relay attacks | 7.5 |
| LLMNR/NBT-NS enabled | Credential capture | 7.0 |
| Default credentials | Unauthorized access | 9.0 |
| Unpatched EternalBlue (MS17-010) | Remote code execution | 9.8 |
| Kerberoasting-eligible SPNs | Offline password cracking | 7.5 |

## Windows Event IDs for Detection

| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon attempt (brute force indicator) |
| 4648 | Logon with explicit credentials |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos service ticket request |

## External References

- [nmap Reference Guide](https://nmap.org/book/man.html)
- [ldap3 Documentation](https://ldap3.readthedocs.io/)
- [impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [PTES Technical Guidelines](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)
