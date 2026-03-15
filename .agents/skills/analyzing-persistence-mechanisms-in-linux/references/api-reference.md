# Linux Persistence Mechanisms Detection API Reference

## Crontab Inspection Commands

```bash
# List current user crontab
crontab -l

# List crontab for a specific user (requires root)
crontab -l -u username

# List all system cron jobs
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
cat /etc/crontab

# Find recently modified cron files
find /var/spool/cron/ /etc/cron* -mtime -7 -type f 2>/dev/null
```

## Systemd Unit Audit Commands

```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# List all active timers
systemctl list-timers --all

# Show service details
systemctl cat suspicious.service

# Find non-package-managed unit files
find /etc/systemd/system/ -name '*.service' -exec sh -c \
  'dpkg -S "$1" 2>/dev/null || echo "UNMANAGED: $1"' _ {} \;

# Check for user-level systemd units
find /home -path '*/.config/systemd/user/*.service' 2>/dev/null
```

## LD_PRELOAD Detection

```bash
# Check ld.so.preload file
cat /etc/ld.so.preload 2>/dev/null

# Check environment for LD_PRELOAD
env | grep LD_PRELOAD
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD

# Check running processes for injected libraries
for pid in /proc/[0-9]*; do
  grep -l LD_PRELOAD "$pid/environ" 2>/dev/null && echo "PID: $(basename $pid)"
done
```

## Auditd Rules for Persistence Monitoring

```bash
# Monitor crontab modifications
-w /etc/crontab -p wa -k cron_modification
-w /etc/cron.d/ -p wa -k cron_modification
-w /var/spool/cron/ -p wa -k cron_modification

# Monitor systemd unit changes
-w /etc/systemd/system/ -p wa -k systemd_modification

# Monitor ld.so.preload
-w /etc/ld.so.preload -p wa -k ld_preload_modification

# Monitor shell profiles
-w /etc/profile -p wa -k profile_modification
-w /etc/profile.d/ -p wa -k profile_modification

# Monitor authorized_keys
-w /root/.ssh/authorized_keys -p wa -k ssh_key_modification

# Search audit logs for persistence events
ausearch -k cron_modification --start today
ausearch -k systemd_modification -i
```

## SSH Authorized Keys Audit

```bash
# Find all authorized_keys files
find / -name authorized_keys -type f 2>/dev/null

# Check for command restrictions in keys
grep 'command=' /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```

## MITRE ATT&CK Techniques

| Technique | ID | Persistence Vector |
|-----------|----|--------------------|
| Scheduled Task/Job: Cron | T1053.003 | Crontab entries |
| Create/Modify System Process: Systemd | T1543.002 | Systemd units |
| Hijack Execution Flow: LD_PRELOAD | T1574.006 | Shared library injection |
| Event Triggered Execution: Unix Shell | T1546.004 | .bashrc/.profile |
| Account Manipulation: SSH Keys | T1098.004 | authorized_keys |
