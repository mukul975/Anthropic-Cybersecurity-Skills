# API Reference: Analyzing Linux Audit Logs for Intrusion

## Audit Log Location
```
/var/log/audit/audit.log
```

## ausearch CLI
```bash
# Search by key
ausearch -k file_access

# Search by message type
ausearch -m EXECVE

# Failed events only
ausearch --success no

# By user
ausearch -ua 1000

# CSV output for Python processing
ausearch --format csv > audit_events.csv

# By time range
ausearch --start today --end now
ausearch --start 01/15/2025 00:00:00 --end 01/16/2025 00:00:00
```

## aureport CLI
```bash
# Summary report
aureport --summary

# Authentication report
aureport -au

# Failed events
aureport --failed

# Executable report
aureport -x

# File access report
aureport -f

# Anomaly report
aureport --anomaly
```

## Audit Rules (auditctl)
```bash
# Monitor sensitive files
auditctl -w /etc/passwd -p rwxa -k passwd_access
auditctl -w /etc/shadow -p rwxa -k shadow_access
auditctl -w /etc/sudoers -p rwxa -k sudoers_access

# Monitor privilege escalation
auditctl -a always,exit -F arch=b64 -S execve -F euid=0 -F uid!=0 -k priv_esc

# Monitor module loading
auditctl -a always,exit -F arch=b64 -S init_module -S finit_module -k modules

# Monitor network connections
auditctl -a always,exit -F arch=b64 -S connect -k network_connect
```

## Audit Log Fields
| Field | Description |
|-------|------------|
| type | Event type (SYSCALL, PATH, EXECVE, USER_CMD) |
| msg | audit(timestamp:event_id) |
| syscall | System call number |
| uid/euid | User ID / Effective UID |
| comm | Command name |
| exe | Executable path |
| key | Audit rule key |
| success | yes/no |
| name | File path (in PATH records) |

## Suspicious Syscalls
| Syscall | Concern |
|---------|---------|
| execve | Program execution |
| ptrace | Process debugging/injection |
| init_module | Kernel rootkit loading |
| connect | Outbound connection |
| setuid | Privilege change |
| open_by_handle_at | Container escape |
