# API Reference: Privilege Escalation Assessment

## Linux Enumeration Commands

| Command | Description |
|---------|-------------|
| `id && whoami` | Current user and group memberships |
| `uname -a` | Kernel version for exploit matching |
| `sudo -l` | Sudo permissions for current user |
| `find / -perm -4000 -type f 2>/dev/null` | SUID binaries |
| `find / -perm -2000 -type f 2>/dev/null` | SGID binaries |
| `getcap -r / 2>/dev/null` | Binaries with Linux capabilities |
| `cat /etc/crontab` | System cron jobs |
| `ps aux \| grep root` | Processes running as root |

## Windows Enumeration Commands

| Command | Description |
|---------|-------------|
| `whoami /priv` | User privileges (SeImpersonate, SeDebug) |
| `systeminfo` | OS version and hotfix level |
| `wmic service get name,pathname,startmode` | Unquoted service paths |
| `reg query HKLM\...\Installer /v AlwaysInstallElevated` | MSI escalation |
| `cmdkey /list` | Stored Windows credentials |

## MITRE ATT&CK Techniques

| Technique | ID | Description |
|-----------|----|-------------|
| Sudo Abuse | T1548.003 | Exploiting sudo misconfiguration |
| SUID/SGID Abuse | T1548.001 | Abusing setuid/setgid binaries |
| Scheduled Task | T1053.003 | Cron job manipulation |
| Kernel Exploit | T1068 | Exploiting kernel vulnerabilities |
| Token Impersonation | T1134.001 | Windows token manipulation |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute system enumeration commands |
| `pathlib` | stdlib | File system permission checks |
| `os` | stdlib | Access and write permission verification |

## References

- GTFOBins: https://gtfobins.github.io/
- LOLBAS: https://lolbas-project.github.io/
- linPEAS: https://github.com/carlospolop/PEASS-ng
- Linux Exploit Suggester: https://github.com/mzet-/linux-exploit-suggester
