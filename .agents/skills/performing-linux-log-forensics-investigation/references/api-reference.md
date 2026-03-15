# API Reference — Performing Linux Log Forensics Investigation

## Libraries Used
- **re**: Pattern matching for log entries (IPs, users, timestamps, suspicious commands)
- **gzip**: Read compressed log files (.gz)
- **pathlib**: File system operations
- **collections.Counter**: Aggregate brute force IPs, command tags

## CLI Interface
```
python agent.py auth --file /var/log/auth.log
python agent.py syslog --file /var/log/syslog
python agent.py history --file /home/user/.bash_history
python agent.py timeline --files /var/log/auth.log /var/log/syslog /var/log/kern.log
```

## Core Functions

### `analyze_auth_log(log_file)` — Authentication log analysis
Detects: failed logins, successful logins, sudo commands, SSH events.
Identifies brute force suspects (>=5 failed attempts from same IP).

### `analyze_syslog(log_file)` — System log anomaly detection
Flags: errors/critical messages, kernel anomalies (segfault, OOM, panic), cron jobs.

### `analyze_command_history(history_file)` — Suspicious command detection
12 patterns: remote code execution (curl|sh), reverse shells, base64 decode,
crontab modification, firewall flush, history clearing, destructive commands.

### `timeline_analysis(log_files)` — Multi-source timeline reconstruction
Merges events from multiple log files sorted by timestamp.
Supports syslog format (Mon DD HH:MM:SS) and ISO 8601.

## Suspicious Command Tags
| Tag | Pattern |
|-----|---------|
| REMOTE_CODE_EXECUTION | curl/wget piped to sh/bash |
| BASH_REVERSE_SHELL | /dev/tcp/ usage |
| NETCAT_LISTENER | nc -e/-l/-p |
| HISTORY_CLEAR | history -c |
| DESTRUCTIVE_COMMAND | rm -rf / |

## Dependencies
No external packages — Python standard library only.
