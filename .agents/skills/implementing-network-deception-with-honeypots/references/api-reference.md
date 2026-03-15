# Network Deception with Honeypots Reference

## OpenCanary Installation

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev python3-pip python3-virtualenv libssl-dev libpcap-dev
virtualenv canary-env && source canary-env/bin/activate
pip install opencanary

# Docker
docker pull thinkst/opencanary
docker run -d --network host -v /path/to/config:/etc/opencanaryd thinkst/opencanary
```

## OpenCanary CLI

```bash
# Generate default config
opencanaryd --copyconfig

# Start daemon
opencanaryd --start

# Stop daemon
opencanaryd --stop

# Check status
opencanaryd --status

# Run in foreground (debug)
opencanaryd --dev
```

## Configuration File (`/etc/opencanaryd/opencanary.conf`)

```json
{
    "device.node_id": "honeypot-dmz-01",
    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.4.41 (Ubuntu)",
    "http.skin": "nasLogin",
    "smb.enabled": true,
    "smb.filelist": [{"name": "passwords.xlsx", "type": "xlsx"}],
    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    "mysql.enabled": true,
    "mysql.port": 3306,
    "rdp.enabled": true,
    "rdp.port": 3389
}
```

## Available Service Modules

| Service | Config Key | Default Port | Interaction Level |
|---------|-----------|-------------|-------------------|
| SSH | ssh.enabled | 22 | Medium |
| HTTP | http.enabled | 80 | Low-Medium |
| FTP | ftp.enabled | 21 | Low |
| SMB | smb.enabled | 445 | Low |
| MySQL | mysql.enabled | 3306 | Low |
| RDP | rdp.enabled | 3389 | Low |
| Telnet | telnet.enabled | 23 | Low |
| SNMP | snmp.enabled | 161 | Low |
| Git | git.enabled | 9418 | Low |
| Redis | redis.enabled | 6379 | Low |
| VNC | vnc.enabled | 5000 | Low |

## Log Format (JSON, one per line)

```json
{
    "dst_host": "10.0.0.50",
    "dst_port": 22,
    "src_host": "10.0.0.100",
    "src_port": 45321,
    "logtype": 3001,
    "node_id": "honeypot-dmz-01",
    "utc_time": "2025-03-01 14:30:00.123456",
    "logdata": {"USERNAME": "admin", "PASSWORD": "password123"}
}
```

## Log Type Codes

| Code | Service | Event |
|------|---------|-------|
| 1001 | FTP | Login attempt |
| 2001 | HTTP | Login attempt |
| 3001 | SSH | Login attempt |
| 5001 | SMB | File open |
| 6001 | Telnet | Login attempt |
| 7001 | MySQL | Login attempt |
| 8001 | RDP | Login attempt |

## Cowrie SSH Honeypot

```bash
# Docker deployment
docker run -d -p 22:2222 cowrie/cowrie

# Session replay
bin/playlog log/tty/20250301-143000-abc123.log
```

## Syslog Forwarding

```json
{
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "handlers": {
                "syslog": {
                    "class": "logging.handlers.SysLogHandler",
                    "address": ["siem.example.com", 514]
                }
            }
        }
    }
}
```
