# API Reference: Privileged Session Monitoring

## SSH Auth Log Parsing
```bash
# Location
/var/log/auth.log       # Debian/Ubuntu
/var/log/secure          # RHEL/CentOS

# Extract SSH sessions
grep "sshd.*Accepted" /var/log/auth.log
grep "sshd.*Failed" /var/log/auth.log

# Count by source IP
grep "sshd.*Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

## Windows RDP Event IDs
| Event ID | Log | Description |
|----------|-----|------------|
| 4624 (Type 10) | Security | Successful RDP logon |
| 4625 (Type 10) | Security | Failed RDP logon |
| 1149 | TerminalServices-RemoteConnectionManager | RDP connection established |
| 21 | TerminalServices-LocalSessionManager | Session logon succeeded |
| 24 | TerminalServices-LocalSessionManager | Session disconnected |
| 25 | TerminalServices-LocalSessionManager | Session reconnected |

## PowerShell RDP Query
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} |
  Where-Object {$_.Properties[8].Value -eq 10} |
  Select-Object TimeCreated,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}}
```

## CyberArk PSM REST API
```bash
# Get active sessions
curl -H "Authorization: $CYBERARK_TOKEN" \
  "https://pvwa.example.com/PasswordVault/api/LiveSessions"

# Get session recordings
curl -H "Authorization: $CYBERARK_TOKEN" \
  "https://pvwa.example.com/PasswordVault/api/Recordings?Limit=100"
```

## Session Policy Fields
| Policy | Default | Description |
|--------|---------|------------|
| max_duration_hours | 8 | Maximum session length |
| max_idle_minutes | 30 | Auto-disconnect on idle |
| require_mfa | true | MFA required for access |
| record_session | true | Full session recording |
| allowed_hours | 06:00-22:00 | Permitted access window |

## Restricted Commands (Alert Triggers)
| Pattern | Risk |
|---------|------|
| `rm -rf /` | Destructive deletion |
| `dd if=` | Disk overwrite |
| `chmod 777` | Excessive permissions |
| `iptables -F` | Firewall rule flush |
| `passwd root` | Root password change |
