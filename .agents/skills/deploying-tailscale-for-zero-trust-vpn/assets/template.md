# Tailscale Deployment Planning Template

## Network Architecture

- **Organization**: _______________
- **Tailnet Name**: _______________
- **Identity Provider**: _______________
- **Key Expiry Policy**: _______________
- **Self-hosted (Headscale)**: [ ] Yes [ ] No

## User Groups

| Group Name | Description | Members Count | Access Level |
|---|---|---|---|
| group:engineering | Development team | ___ | Development, Staging |
| group:sre | SRE/DevOps team | ___ | All environments |
| group:security | Security team | ___ | Monitoring, Audit |
| group:management | Leadership | ___ | Dashboards only |

## Infrastructure Tags

| Tag | Description | Owner Group | Environment |
|---|---|---|---|
| tag:production | Production servers | group:sre | Production |
| tag:staging | Staging servers | group:engineering | Staging |
| tag:development | Dev servers | group:engineering | Development |
| tag:database | Database servers | group:sre | All |
| tag:monitoring | Monitoring stack | group:sre | All |

## Subnet Routes

| CIDR | Description | Router Node | Auto-Approved |
|---|---|---|---|
| 10.0.0.0/16 | Corporate network | ___ | [ ] Yes |
| 192.168.0.0/24 | Lab network | ___ | [ ] Yes |

## Exit Nodes

| Hostname | Location | Purpose | Auto-Approved |
|---|---|---|---|
| ___ | ___ | Internet routing | [ ] Yes |
| ___ | ___ | Geo-specific access | [ ] Yes |

## Security Checklist

- [ ] Identity provider configured with MFA
- [ ] Key expiry enabled (recommended: 90 days)
- [ ] ACLs configured with deny-all default
- [ ] Network Lock enabled
- [ ] SSH access requires re-authentication for privileged users
- [ ] Audit logging enabled
- [ ] Subnet routes approved only for authorized nodes
- [ ] Exit nodes approved only for authorized nodes
- [ ] Untagged node policy defined
- [ ] Ephemeral keys used for CI/CD and temporary workloads

## Rollout Plan

### Phase 1: Infrastructure
- [ ] Deploy to servers and critical infrastructure
- [ ] Configure subnet routers
- [ ] Set up exit nodes
- [ ] Test ACL enforcement

### Phase 2: User Onboarding
- [ ] Pilot group deployment
- [ ] Full organization rollout
- [ ] VPN migration (decommission legacy VPN)
- [ ] User training and documentation

### Phase 3: Hardening
- [ ] Enable Network Lock
- [ ] Enable Tailscale SSH with session recording
- [ ] Configure auto-approvers
- [ ] Set up monitoring and alerting
