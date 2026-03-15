# Standards Reference - RBAC Auditing

## CIS Kubernetes Benchmark v1.8 - Section 5.1

- 5.1.1: Ensure cluster-admin role is only used where required
- 5.1.2: Minimize access to secrets
- 5.1.3: Minimize wildcard use in Roles and ClusterRoles
- 5.1.4: Minimize access to create pods
- 5.1.5: Ensure default service accounts are not actively used
- 5.1.6: Ensure Service Account Tokens are not mounted when not needed
- 5.1.7: Avoid use of system:masters group
- 5.1.8: Limit use of the Bind, Impersonate and Escalate permissions

## NIST SP 800-53 AC Controls
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-6: Least Privilege
- AC-6(1): Authorize Access to Security Functions
- AC-6(5): Privileged Accounts

## Dangerous RBAC Combinations

| Verbs | Resources | Risk Level |
|-------|-----------|-----------|
| * | * | CRITICAL - cluster-admin equivalent |
| create | pods | HIGH - can deploy privileged pods |
| create | pods/exec | HIGH - can exec into any pod |
| get, list | secrets | HIGH - can read all secrets |
| create | clusterrolebindings | CRITICAL - privilege escalation |
| impersonate | users, groups, serviceaccounts | CRITICAL - identity theft |
| escalate | roles, clusterroles | CRITICAL - RBAC escalation |
| bind | roles, clusterroles | HIGH - can create bindings |
| create | deployments | MEDIUM - can deploy workloads |
| delete | pods, nodes | HIGH - denial of service |
