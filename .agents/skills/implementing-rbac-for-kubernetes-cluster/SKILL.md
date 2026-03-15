---
name: implementing-rbac-for-kubernetes-cluster
description: Configure Kubernetes Role-Based Access Control (RBAC) to enforce least-privilege access to cluster resources. This skill covers Role/ClusterRole design, RoleBinding configuration, service account secu
domain: cybersecurity
subdomain: identity-access-management
tags: [iam, identity, access-control, authorization, rbac, kubernetes, k8s]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing RBAC for Kubernetes Cluster

## Overview
Configure Kubernetes Role-Based Access Control (RBAC) to enforce least-privilege access to cluster resources. This skill covers Role/ClusterRole design, RoleBinding configuration, service account security, namespace isolation, and audit logging for multi-tenant Kubernetes environments.

## Objectives
- Design RBAC role hierarchy for multi-tenant clusters
- Create granular Roles and ClusterRoles for different personas
- Configure RoleBindings and ClusterRoleBindings with least privilege
- Secure service accounts and limit their default permissions
- Integrate RBAC with external identity providers (OIDC)
- Audit and monitor RBAC usage with Kubernetes audit logs

## Key Concepts

### RBAC API Objects
1. **Role**: Namespace-scoped permissions (pods, services, deployments within a namespace)
2. **ClusterRole**: Cluster-wide permissions (nodes, namespaces, PVs, CRDs)
3. **RoleBinding**: Grants Role to users/groups/serviceAccounts in a namespace
4. **ClusterRoleBinding**: Grants ClusterRole cluster-wide

### Kubernetes RBAC Verbs
- `get`, `list`, `watch`: Read-only operations
- `create`, `update`, `patch`: Write operations
- `delete`, `deletecollection`: Destructive operations
- `impersonate`: Assume identity of another user
- `escalate`: Modify RBAC roles (highly privileged)
- `bind`: Create RoleBindings (highly privileged)

### Persona-Based Access Model
- **Cluster Admin**: Full cluster management (limit to 2-3 people)
- **Namespace Admin**: Full control within assigned namespace
- **Developer**: Deploy and manage workloads in assigned namespace
- **Viewer**: Read-only access to namespace resources
- **CI/CD Service Account**: Deploy workloads, manage configmaps/secrets

## Implementation Steps

### Step 1: Disable Default Permissive Settings
1. Ensure `--authorization-mode=RBAC` is enabled on API server
2. Remove default cluster-admin bindings from non-admin users
3. Disable auto-mounting of service account tokens in pods
4. Restrict access to default service account in each namespace

### Step 2: Create Custom Roles
```yaml
# Developer Role - namespace scoped
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app-team
  name: developer
rules:
- apiGroups: ["", "apps", "batch"]
  resources: ["pods", "deployments", "services", "configmaps", "jobs"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]  # read secrets but limit create/update
- apiGroups: [""]
  resources: ["pods/log", "pods/exec"]
  verbs: ["get", "create"]
```

### Step 3: Bind Roles to Users/Groups
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: developer-binding
  namespace: app-team
subjects:
- kind: Group
  name: "dev-team"
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: developer
  apiGroup: rbac.authorization.k8s.io
```

### Step 4: Secure Service Accounts
- Create dedicated service accounts per application
- Disable automountServiceAccountToken for pods that don't need API access
- Use projected service account tokens with audience and expiry
- Bind minimum required permissions to each service account

### Step 5: OIDC Integration
1. Configure API server with OIDC flags (issuer-url, client-id, username-claim, groups-claim)
2. Map OIDC groups to Kubernetes groups in RoleBindings
3. Use short-lived tokens from OIDC provider
4. Configure kubectl with OIDC authentication plugin

### Step 6: Audit and Monitoring
- Enable Kubernetes audit logging (audit-policy.yaml)
- Log all RBAC-related events (role creation, binding changes)
- Alert on ClusterRoleBinding creation/modification
- Monitor for privilege escalation attempts
- Regular review of who has cluster-admin access

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Access Control | AC-3 | RBAC enforcement |
| Least Privilege | AC-6 | Minimum necessary Kubernetes permissions |
| Account Management | AC-2 | Service account lifecycle |
| Audit | AU-3 | Kubernetes audit logging |
| Separation of Duties | AC-5 | Namespace isolation |

## Common Pitfalls
- Granting cluster-admin to CI/CD pipelines
- Using wildcard (*) verbs or resources in ClusterRoles
- Not restricting pods/exec which allows container shell access
- Leaving default service account with broad permissions
- Not auditing who can create RoleBindings (privilege escalation vector)

## Verification
- [ ] All users authenticate via OIDC (no static tokens/certs)
- [ ] No unnecessary ClusterRoleBindings to cluster-admin
- [ ] Developers limited to their assigned namespaces
- [ ] Service accounts use least-privilege roles
- [ ] automountServiceAccountToken disabled by default
- [ ] Audit logging captures RBAC changes
- [ ] `kubectl auth can-i` validates expected permissions per persona
