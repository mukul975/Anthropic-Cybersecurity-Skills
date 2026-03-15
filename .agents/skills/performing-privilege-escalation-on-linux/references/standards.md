# Standards and Framework References

## MITRE ATT&CK - Privilege Escalation (TA0004)
| Technique ID | Name | Description |
|-------------|------|-------------|
| T1548.001 | Setuid and Setgid | Exploit SUID/SGID binaries |
| T1548.003 | Sudo and Sudo Caching | Abuse sudo misconfigurations |
| T1068 | Exploitation for Privilege Escalation | Kernel/service exploits |
| T1574.006 | Dynamic Linker Hijacking | LD_PRELOAD/LD_LIBRARY_PATH abuse |
| T1053.003 | Cron | Abuse scheduled tasks |
| T1543.002 | Systemd Service | Writable service manipulation |

## Common Kernel CVEs
| CVE | Name | Kernel Range | CVSS |
|-----|------|-------------|------|
| CVE-2016-5195 | Dirty Cow | < 4.8.3 | 7.8 |
| CVE-2021-4034 | PwnKit (pkexec) | Polkit < 0.120 | 7.8 |
| CVE-2022-0847 | Dirty Pipe | 5.8 - 5.16.10 | 7.8 |
| CVE-2021-3156 | Baron Samedit (sudo) | sudo < 1.9.5p2 | 7.8 |
| CVE-2023-2640 | GameOver(lay) | Ubuntu kernels | 7.8 |
| CVE-2023-0386 | OverlayFS | 5.11 - 6.2 | 7.8 |

## CIS Benchmark - Linux
- Ensure permissions on /etc/crontab are configured (600 root:root)
- Ensure SUID/SGID files are reviewed regularly
- Ensure sudo is configured to use a pseudo-TTY
- Ensure no world-writable files exist in system paths
