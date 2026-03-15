# HashiCorp Boundary Deployment Template

## Deployment Information
- **Organization**: _______________
- **Deployment Type**: [ ] Self-hosted [ ] HCP Boundary
- **Identity Provider**: _______________
- **Vault Integration**: [ ] Yes [ ] No

## Scope Hierarchy

| Scope Type | Name | Description | Owner |
|---|---|---|---|
| Organization | ___ | ___ | ___ |
| Project | ___ | ___ | ___ |
| Project | ___ | ___ | ___ |

## Targets Inventory

| Target Name | Type | Port | Hosts | Session Max | Recording | Credentials |
|---|---|---|---|---|---|---|
| ___ | ssh | 22 | ___ | 3600s | [ ] Yes | injected |
| ___ | tcp | 5432 | ___ | 1800s | [ ] Yes | brokered |
| ___ | tcp | 443 | ___ | 3600s | [ ] Yes | none |

## Role Assignments

| Role | Scope | Grants | Groups |
|---|---|---|---|
| ___ | ___ | ___ | ___ |

## Security Checklist

- [ ] OIDC authentication configured with MFA-enabled IdP
- [ ] Managed groups auto-assign roles from IdP claims
- [ ] Vault credential brokering enabled for database targets
- [ ] SSH certificate injection via Vault SSH engine
- [ ] Session recording enabled for privileged access
- [ ] Session duration limits configured per target
- [ ] KMS configured with Vault Transit (not static AEAD)
- [ ] Workers deployed in each network zone
- [ ] Audit logging enabled on controllers and workers
- [ ] Break-glass recovery KMS configured and secured
