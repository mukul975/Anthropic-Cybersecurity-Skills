# API Reference — Performing Privilege Escalation on Linux

## Libraries Used
- **subprocess**: Execute system enumeration commands (sudo, find, getcap, crontab)
- **os**: Check file writability with os.access()
- **pathlib**: File system navigation
- **re**: Pattern matching for cron script paths

## CLI Interface
```
python agent.py sysinfo
python agent.py sudo
python agent.py suid
python agent.py writable
python agent.py cron
python agent.py caps
python agent.py full
```

## Core Functions

### `enumerate_system_info()` — Kernel, user, architecture info
### `check_sudo_permissions()` — Sudo privilege analysis
Checks `sudo -l` output against 30+ GTFOBins-exploitable binaries.
Detects NOPASSWD entries and full sudo access.

### `find_suid_binaries()` — SUID/SGID binary enumeration
Identifies binaries with SUID bit set. Cross-references GTFOBins database.

### `check_writable_files()` — Sensitive writable file detection
Checks: /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab, /root, cron dirs.

### `check_cron_jobs()` — Cron job privilege escalation vectors
Identifies writable scripts called from cron jobs (CRITICAL finding).

### `check_capabilities()` — Linux capability enumeration
Flags: cap_setuid, cap_setgid, cap_sys_admin, cap_dac_override, cap_net_raw.

### `full_enumeration()` — Combined analysis

## GTFOBins SUID Exploitable Binaries (subset)
vim, find, bash, python, perl, nmap, env, tar, docker, strace, gdb, pkexec

## Dangerous Sudo Patterns
| Pattern | Severity | Vector |
|---------|----------|--------|
| (ALL) NOPASSWD: /usr/bin/vim | CRITICAL | Shell escape |
| (ALL : ALL) ALL | CRITICAL | Full root access |
| NOPASSWD: /usr/bin/find | CRITICAL | -exec escalation |

## Dependencies
No external packages — Python standard library only.
System: find, getcap, sudo, crontab
