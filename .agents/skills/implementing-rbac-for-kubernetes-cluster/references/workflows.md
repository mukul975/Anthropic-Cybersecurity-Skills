# Kubernetes RBAC Workflows

## Workflow 1: New Team Onboarding
1. Create dedicated namespace for the team
2. Create ResourceQuota and LimitRange for the namespace
3. Create NetworkPolicy to isolate namespace traffic
4. Design Roles based on team member personas (admin, developer, viewer)
5. Create RoleBindings mapped to OIDC groups
6. Create dedicated service accounts for CI/CD
7. Test access with `kubectl auth can-i` for each persona
8. Document namespace ownership and contact

## Workflow 2: RBAC Audit
1. List all ClusterRoleBindings: `kubectl get clusterrolebindings -o wide`
2. Identify bindings to cluster-admin role
3. Review each cluster-admin binding for necessity
4. Check for wildcard permissions in custom roles
5. Verify service accounts have minimum permissions
6. Test pod escape scenarios (exec, privileged containers)
7. Generate compliance report with findings

## Workflow 3: Privilege Escalation Prevention
1. Restrict who can create/modify Roles and RoleBindings
2. Prevent escalate verb usage (only cluster-admin should have it)
3. Block bind verb for non-admin users
4. Prevent impersonate verb usage
5. Use admission controllers (OPA Gatekeeper) for policy enforcement
6. Monitor audit logs for RBAC modification attempts

## Workflow 4: Service Account Hardening
1. List all service accounts: `kubectl get sa --all-namespaces`
2. Identify service accounts with ClusterRole bindings
3. Remove unnecessary ClusterRoleBindings
4. Set automountServiceAccountToken: false in namespace default SA
5. Create per-application service accounts with minimum roles
6. Use projected service account tokens with short expiry
