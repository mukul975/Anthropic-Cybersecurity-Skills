# Havoc C2 Infrastructure Configuration Template

## Engagement Details

| Field | Value |
|---|---|
| Engagement ID | RT-YYYY-XXX |
| Client | [Organization] |
| Operators | [Names] |
| Start Date | YYYY-MM-DD |
| End Date | YYYY-MM-DD |
| Kill Date | YYYY-MM-DD |

## Infrastructure Inventory

### Teamserver

| Field | Value |
|---|---|
| Provider | [AWS/DigitalOcean/Linode] |
| IP Address | X.X.X.X |
| OS | Ubuntu 22.04 LTS |
| Port | 40056 |
| Havoc Version | 0.7 |
| Access | SSH Key: [key name] |

### Redirector(s)

| Name | Provider | IP | Domain | SSL Cert | Status |
|---|---|---|---|---|---|
| Redirector-1 | [Provider] | X.X.X.X | c2.domain.com | Let's Encrypt | Active |
| Redirector-2 | [Provider] | X.X.X.X | cdn.domain2.com | Let's Encrypt | Standby |

### Domains

| Domain | Purpose | Registered | Aged | Categorized | SSL |
|---|---|---|---|---|---|
| c2.domain.com | Primary C2 | YYYY-MM-DD | Yes (45 days) | Business | Yes |
| cdn.domain2.com | Backup C2 | YYYY-MM-DD | Yes (60 days) | Technology | Yes |
| phish.domain3.com | Phishing | YYYY-MM-DD | Yes (30 days) | Uncategorized | Yes |

## Havoc Profile Configuration

```yaml
Teamserver:
  Host: "0.0.0.0"
  Port: 40056

Operators:
  - Username: operator1
    Password: [REDACTED]
  - Username: operator2
    Password: [REDACTED]

Listeners:
  - Name: "Primary HTTPS"
    Type: HTTPS
    Host: c2.domain.com
    Port: 443
    URIs: ["/api/v2/auth", "/api/v2/status", "/content/images/gallery"]
    User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    Jitter: 30%

  - Name: "SMB Pivot"
    Type: SMB
    PipeName: "\\ntsvcs"

Demon:
  Sleep: 10
  Jitter: 30
  Spawn64: "C:\\Windows\\System32\\notepad.exe"
  Spawn32: "C:\\Windows\\SysWOW64\\notepad.exe"
```

## Payload Inventory

| Payload | Format | Listener | Arch | Hash (SHA256) | Delivery |
|---|---|---|---|---|---|
| stage1.bin | Shellcode | Primary HTTPS | x64 | [hash] | Custom loader |
| beacon.dll | DLL | Primary HTTPS | x64 | [hash] | DLL sideloading |
| pivot.exe | Service EXE | SMB Pivot | x64 | [hash] | Lateral movement |

## OPSEC Checklist

### Pre-Engagement
- [ ] Domains registered 30+ days before engagement start
- [ ] Domains categorized in Bluecoat, Fortiguard, Palo Alto
- [ ] SSL certificates obtained from trusted CA (not self-signed)
- [ ] Teamserver hardened (SSH keys only, fail2ban, UFW)
- [ ] Redirector filtering non-C2 traffic to legitimate site
- [ ] Malleable profile customized (URIs, headers, user-agent)
- [ ] Payloads tested against target AV/EDR in isolated lab
- [ ] Kill date configured on all payloads
- [ ] Operator logs enabled and encrypted at rest

### During Engagement
- [ ] Beacon sleep/jitter appropriate for operation phase
- [ ] No default Havoc indicators in network traffic
- [ ] Post-exploitation tools loaded in-memory only
- [ ] Named pipes and service names randomized
- [ ] Token manipulation used instead of credential replay where possible

### Post-Engagement
- [ ] All Demon sessions terminated
- [ ] All persistence mechanisms removed from target
- [ ] All payloads removed from target systems
- [ ] Teamserver logs archived and encrypted
- [ ] VPS instances destroyed
- [ ] Domains released or parked
- [ ] IOC list provided to client

## Emergency Procedures

| Scenario | Action |
|---|---|
| Burned domain | Switch to backup redirector |
| Detected implant | Sleep beacon to 24h, assess exposure |
| Teamserver compromise | Kill all sessions, rotate infrastructure |
| Client emergency stop | Execute `killall` on all active Demons |
| Legal escalation | Contact [Legal Contact] at [phone] |

## Operator Communication

| Channel | Purpose |
|---|---|
| Signal Group | Real-time coordination |
| Encrypted Email | Reports and documentation |
| Havoc Chat | In-tool session coordination |
| Emergency Phone | [Phone number] for critical issues |
