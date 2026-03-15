# RBAC Hardening Assessment Template

## Cluster Information
| Field | Value |
|-------|-------|
| Cluster Name | |
| Kubernetes Version | |
| Assessment Date | |

## RBAC Audit Results
| Metric | Count |
|--------|-------|
| ClusterRoleBindings | |
| cluster-admin bindings | |
| Wildcard permissions | |
| Default SA bindings | |

## Hardening Checklist
- [ ] Removed unnecessary cluster-admin bindings
- [ ] All workloads use dedicated service accounts
- [ ] automountServiceAccountToken disabled on default SAs
- [ ] OIDC integration configured
- [ ] RBAC monitoring and alerting active
- [ ] Quarterly review process established

## Sign-Off
| Role | Name | Date |
|------|------|------|
| Security Engineer | | |
| Platform Lead | | |
