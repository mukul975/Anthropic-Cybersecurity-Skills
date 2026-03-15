# Cloudflare Access Zero Trust - Deployment Checklist

## Project Information
| Field | Value |
|-------|-------|
| Organization | TechStartup Inc |
| Cloudflare Account | CF-XXXXXXX |
| Team Name | techstartup |
| Plan | Zero Trust Teams (50 seats) |
| Start Date | 2026-01-25 |

## Identity Provider Configuration
- [x] Primary IdP: Google Workspace (OIDC)
- [x] MFA enforced at IdP level
- [ ] Secondary IdP for contractors: GitHub OAuth
- [x] Email domain restriction: @techstartup.com

## Tunnel Deployment

| Tunnel Name | Server | Network | Routes | Status |
|-------------|--------|---------|--------|--------|
| prod-tunnel | prod-bastion (10.1.0.5) | Production VPC | wiki, grafana, api | Healthy |
| staging-tunnel | staging-bastion (10.2.0.5) | Staging VPC | staging-* | Healthy |

## Access Applications

| Application | Type | Domain | Session | Policies | Status |
|-------------|------|--------|---------|----------|--------|
| Internal Wiki | self_hosted | wiki.techstartup.com | 8h | 2 (Allow Eng, Deny All) | Active |
| Grafana | self_hosted | grafana.techstartup.com | 8h | 2 (Allow SRE, Deny All) | Active |
| Internal API | self_hosted | api.techstartup.com | 4h | 3 (Allow Backend, Service Token, Deny All) | Active |
| Staging Apps | self_hosted | staging.techstartup.com | 4h | 2 (Allow Eng, Deny All) | Active |
| SSH Jump | ssh | ssh.techstartup.com | 2h | 1 (Allow SRE) | Active |

## Device Posture Rules
- [x] Disk encryption: Required (Windows BitLocker, macOS FileVault)
- [x] OS version: Windows >= 10.0.19045, macOS >= 14.0
- [x] Firewall: Enabled
- [ ] CrowdStrike integration: Pending deployment

## WARP Enrollment

| Platform | Enrolled | Total | Coverage |
|----------|----------|-------|----------|
| macOS | 32 | 35 | 91.4% |
| Windows | 12 | 13 | 92.3% |
| Linux | 2 | 2 | 100% |
| Total | 46 | 50 | 92.0% |

## Sign-Off

| Role | Name | Date | Approved |
|------|------|------|----------|
| CTO | _________________ | __________ | [ ] |
| Security Lead | _________________ | __________ | [ ] |
