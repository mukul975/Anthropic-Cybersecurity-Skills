# Workflows - RBAC Hardening

## Hardening Workflow
1. Audit all existing ClusterRoleBindings and RoleBindings
2. Identify overprivileged accounts (cluster-admin sprawl)
3. Create namespace-scoped Roles with minimum required permissions
4. Migrate workloads to dedicated service accounts
5. Disable automountServiceAccountToken on default service accounts
6. Integrate OIDC for user authentication
7. Deploy RBAC monitoring and alerting
8. Schedule quarterly RBAC reviews

## Continuous Compliance
- Weekly: automated RBAC audit with rbac-lookup
- Monthly: review new RoleBindings created in past 30 days
- Quarterly: full access review with stakeholder sign-off
- Annually: penetration test RBAC boundaries
