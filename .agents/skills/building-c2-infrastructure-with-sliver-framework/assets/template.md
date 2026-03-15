# Sliver C2 Infrastructure Configuration Template

## Engagement Information

| Field | Value |
|-------|-------|
| Engagement Name | |
| Client | |
| Start Date | |
| End Date | |
| Authorization Document | |

## Team Server Configuration

| Parameter | Value |
|-----------|-------|
| Server IP | |
| Server OS | Ubuntu 22.04 LTS |
| Sliver Version | |
| Firewall Rules Applied | Yes / No |
| SSH Key-Only Auth | Yes / No |

## Listener Configuration

| Listener Type | Port | Domain/Host | Certificate | Status |
|--------------|------|-------------|-------------|--------|
| HTTPS | 443 | | Let's Encrypt / Custom | |
| mTLS | 8888 | | Auto-generated | |
| DNS | 53 | | N/A | |
| WireGuard | 51820 | | Auto-generated | |

## Redirector Configuration

| Redirector ID | IP Address | Cloud Provider | Proxy Software | Team Server Dest |
|--------------|------------|----------------|----------------|------------------|
| REDIR-01 | | | NGINX | |
| REDIR-02 | | | Apache | |

## Operator Access

| Operator Name | Config File | Role | Access Granted |
|--------------|-------------|------|----------------|
| | | Lead | |
| | | Operator | |

## Domain Configuration

| Domain | Registrar | Category | Purpose |
|--------|-----------|----------|---------|
| | | Uncategorized | HTTPS C2 |
| | | Uncategorized | DNS C2 |

## Implant Inventory

| Implant Name | Type | OS | Arch | Protocol | Callback Interval | Jitter |
|-------------|------|-----|------|----------|-------------------|--------|
| | Beacon | Windows | amd64 | HTTPS | 60s | 30% |
| | Session | Linux | amd64 | mTLS | N/A | N/A |

## OPSEC Checklist

- [ ] Team server IP not directly exposed to target network
- [ ] All C2 traffic routed through redirectors
- [ ] SSL certificates use categorized/aged domains
- [ ] DNS C2 domain registered with privacy protection
- [ ] Beacon intervals randomized with jitter
- [ ] Implant names do not reveal engagement details
- [ ] Operator configs distributed via secure channel
- [ ] Kill date configured on all implants
