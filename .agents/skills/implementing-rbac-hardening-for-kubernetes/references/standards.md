# Standards - RBAC Hardening for Kubernetes

## CIS Kubernetes Benchmark v1.9
- 5.1.1: Ensure cluster-admin role is only used where required
- 5.1.2: Minimize access to secrets
- 5.1.3: Minimize wildcard use in Roles and ClusterRoles
- 5.1.4: Minimize access to create pods
- 5.1.5: Ensure default service accounts are not actively used
- 5.1.6: Ensure Service Account Tokens are only mounted where necessary

## NIST SP 800-190
- Section 3.4: Orchestrator security -- access control hardening
- Section 4.4: Countermeasures for orchestrator vulnerabilities

## MITRE ATT&CK
- T1078.004: Valid Accounts: Cloud Accounts -- compromised service accounts
- T1098: Account Manipulation -- RBAC escalation
- T1069: Permission Groups Discovery -- enumerating RBAC bindings
