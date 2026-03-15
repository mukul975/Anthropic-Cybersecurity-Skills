# API Reference: Linux Forensic Artifact Analysis Tools

## Key Artifact Locations

| Artifact | Path | Description |
|----------|------|-------------|
| Auth logs | `/var/log/auth.log` (Debian) `/var/log/secure` (RHEL) | Authentication events |
| Login history | `/var/log/wtmp` | Successful logins (binary, use `last`) |
| Failed logins | `/var/log/btmp` | Failed logins (binary, use `lastb`) |
| Bash history | `~/.bash_history` | Command history per user |
| SSH keys | `~/.ssh/authorized_keys` | Authorized public keys |
| Crontab | `/etc/crontab`, `/var/spool/cron/crontabs/` | Scheduled tasks |
| Systemd services | `/etc/systemd/system/` | Service definitions |
| LD_PRELOAD | `/etc/ld.so.preload` | Shared library preloading |
| SUID binaries | `find / -perm -4000` | Setuid executables |

## last / lastb - Login History

### Syntax
```bash
last -f /var/log/wtmp              # Successful logins
lastb -f /var/log/btmp             # Failed logins
last -i -f /var/log/wtmp           # Show IP addresses
last -s 2024-01-15 -t 2024-01-20  # Date range filter
```

### Output Format
```
user     pts/0   192.168.1.50  Mon Jan 15 09:00  still logged in
```

## chkrootkit - Rootkit Scanner

### Syntax
```bash
chkrootkit                    # Full scan
chkrootkit -r /mnt/evidence   # Scan mounted evidence
chkrootkit -q                 # Quiet (infected only)
```

## rkhunter - Rootkit Hunter

### Syntax
```bash
rkhunter --check                    # Full system check
rkhunter --check --rootdir /mnt/ev  # Check evidence root
rkhunter --list tests               # List available tests
rkhunter --propupd                  # Update file properties DB
```

### Check Categories
| Check | Description |
|-------|-------------|
| `rootkits` | Known rootkit signatures |
| `trojans` | Trojanized system binaries |
| `properties` | File permission anomalies |
| `filesystem` | Hidden files and directories |

## auditd Log Parsing

### ausearch Syntax
```bash
ausearch -m execve -ts recent         # Recent command execution
ausearch -m USER_AUTH -ts today        # Authentication events
ausearch -k suspicious_activity       # Custom audit rule key
ausearch -ua 0 -ts today              # Root user actions
```

### aureport Syntax
```bash
aureport --auth                       # Authentication summary
aureport --login                      # Login summary
aureport --file                       # File access summary
aureport --summary                    # Overall summary
```

## osquery - SQL-based System Queries

### Syntax
```bash
osqueryi "SELECT * FROM users WHERE uid = 0"
osqueryi "SELECT * FROM crontab"
osqueryi "SELECT * FROM authorized_keys"
osqueryi "SELECT * FROM suid_bin"
osqueryi "SELECT * FROM process_open_sockets"
```

### Key Tables
| Table | Content |
|-------|---------|
| `users` | User account information |
| `crontab` | Cron job entries |
| `authorized_keys` | SSH authorized keys |
| `suid_bin` | SUID binaries |
| `process_open_sockets` | Network connections by process |
| `shell_history` | Command history entries |

## Plaso / log2timeline - Super Timeline

### Syntax
```bash
log2timeline.py /cases/timeline.plaso /mnt/evidence
psort.py -o l2tcsv /cases/timeline.plaso > timeline.csv
psort.py -o l2tcsv /cases/timeline.plaso "date > '2024-01-15'"
```

## AIDE - File Integrity

### Syntax
```bash
aide --init                    # Initialize database
aide --check                   # Check for changes
aide --compare                 # Compare databases
```
