# Workflows - Linux Log Forensics
## Workflow 1: Authentication Investigation
```
Collect /var/log/auth.log and rotated copies
    |
Parse for successful and failed SSH logins
    |
Identify brute force sources (>10 failures per IP)
    |
Trace sudo command execution by user
    |
Detect account creation/modification events
    |
Correlate with wtmp/btmp login records
```
## Workflow 2: Full System Timeline
```
Collect all logs from /var/log/
    |
Export systemd journal (journalctl --output=json)
    |
Parse audit.log for security events
    |
Merge into unified timeline
    |
Identify unauthorized access and persistence
```
