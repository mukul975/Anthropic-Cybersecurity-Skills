# Fail2ban Port Scan Detection API Reference

## fail2ban-client CLI

```bash
# Service status
fail2ban-client status

# Jail status
fail2ban-client status sshd

# Ban IP manually
fail2ban-client set sshd banip 192.168.1.100

# Unban IP
fail2ban-client set sshd unbanip 192.168.1.100

# Reload configuration
fail2ban-client reload

# Get ban time for jail
fail2ban-client get sshd bantime

# Set ban time
fail2ban-client set sshd bantime 7200
```

## Jail Configuration (/etc/fail2ban/jail.local)

```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[portscan]
enabled = true
filter = portscan
logpath = /var/log/syslog
maxretry = 3
findtime = 300
bantime = 86400
action = iptables-allports[name=portscan]
```

## Custom Filter (/etc/fail2ban/filter.d/portscan.conf)

```ini
[Definition]
failregex = UFW BLOCK .* SRC=<HOST>
            iptables .* SRC=<HOST> .* DPT=
ignoreregex =
```

## Ban Actions

| Action | Description |
|--------|-------------|
| `iptables-multiport` | Ban specific ports via iptables |
| `iptables-allports` | Ban all ports via iptables |
| `nftables-multiport` | Ban via nftables |
| `firewallcmd-rich-rules` | Ban via firewalld |
| `sendmail-whois` | Email notification with WHOIS |
| `abuseipdb` | Report to AbuseIPDB |

## Log Parsing Patterns

```bash
# Fail2ban log - count bans per IP
grep "Ban " /var/log/fail2ban.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn

# Auth.log - failed SSH logins
grep "Failed password" /var/log/auth.log | grep -oP 'from \K\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn

# Syslog - blocked connections (UFW)
grep "UFW BLOCK" /var/log/syslog | grep -oP 'SRC=\K\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn
```

## Escalating Ban Times (recidive jail)

```ini
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800   # 1 week for repeat offenders
findtime = 86400
maxretry = 3
```
