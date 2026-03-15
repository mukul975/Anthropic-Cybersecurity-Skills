# OPA Gatekeeper Policy Deployment Checklist

## Policy Rollout Plan

### Pre-Deployment
- [ ] Policy reviewed and approved by security team
- [ ] Rego logic tested with `opa test`
- [ ] ConstraintTemplate syntax validated
- [ ] Exempt namespaces identified

### Deployment Steps
1. [ ] Deploy ConstraintTemplate to cluster
2. [ ] Verify CRD created: `kubectl get crd`
3. [ ] Deploy Constraint in `dryrun` mode
4. [ ] Wait 24 hours for audit results
5. [ ] Review violations and remediate/exempt
6. [ ] Switch to `warn` mode
7. [ ] Wait 7 days, monitor for issues
8. [ ] Switch to `deny` mode

### Post-Deployment
- [ ] Verify enforcement is active
- [ ] Test with known-bad resource (should be denied)
- [ ] Update documentation
- [ ] Alert engineering teams

## Policy Registry

| Policy Name | Kind | Mode | Namespaces | Owner |
|-------------|------|------|------------|-------|
| block-privileged | K8sBlockPrivileged | deny | all except kube-system | Security |
| require-labels | K8sRequiredLabels | deny | all | Platform |
| allowed-repos | K8sAllowedRepos | deny | production, staging | Security |
| block-latest | K8sBlockLatestTag | warn | production | DevOps |
| require-limits | K8sRequireLimits | deny | production | SRE |

## Exemption Request Form

| Field | Value |
|-------|-------|
| Constraint Name | |
| Resource | |
| Namespace | |
| Reason | |
| Duration | |
| Compensating Control | |
| Approved By | |
| Expiry Date | |
