# JIT Access Provisioning Policy Template

## Resource Classification
| Resource Type | Risk Level | Max Duration | Auto-Approve | Approvals Required |
|---------------|------------|--------------|--------------|-------------------|
| Read-only access | Low | 1 hour | Yes | 0 |
| Standard application | Medium | 4 hours | No | 1 (manager) |
| Production server | High | 4 hours | No | 2 (manager + security) |
| Database admin | Critical | 2 hours | No | 2 (DBA lead + security) |
| Domain admin | Critical | 1 hour | No | 2 (security + CISO) |
| Cloud admin | Critical | 2 hours | No | 2 (cloud team + security) |

## Approval Workflow Matrix
| Risk Level | Standard Request | Emergency Request |
|------------|-----------------|-------------------|
| Low | Auto-approve | Auto-approve |
| Medium | 1 approval | Auto-approve + post-review |
| High | 2 approvals | Immediate grant + post-review |
| Critical | 2 approvals + MFA | Immediate grant + incident review |

## Request Form Fields
- Requester name and ID
- Target resource/system
- Access level requested
- Duration requested (within policy maximum)
- Business justification
- Related ticket/incident number
- Emergency flag (yes/no)

## SLA Targets
| Metric | Target |
|--------|--------|
| Mean time to access (low risk) | < 1 minute |
| Mean time to access (medium risk) | < 15 minutes |
| Mean time to access (high risk) | < 30 minutes |
| Emergency access grant | < 2 minutes |
| Access revocation at expiry | Immediate (< 1 minute) |
| Post-emergency review | Within 24 hours |

## Monitoring Alerts
- [ ] Emergency access granted
- [ ] Access duration extended
- [ ] Approved access not used within 30 minutes
- [ ] Unusual access patterns detected
- [ ] Approval SLA breached
- [ ] Revocation failure
