---
name: auditing-kubernetes-rbac-permissions
description: Kubernetes Role-Based Access Control (RBAC) auditing systematically reviews roles, cluster roles, bindings, and service account permissions to identify overly permissive access, privilege escalation p
domain: cybersecurity
subdomain: container-security
tags: [containers, kubernetes, security, RBAC, access-control]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Auditing Kubernetes RBAC Permissions

## Overview

Kubernetes Role-Based Access Control (RBAC) auditing systematically reviews roles, cluster roles, bindings, and service account permissions to identify overly permissive access, privilege escalation paths, and violations of least-privilege principles. Tools like rbac-tool, KubiScan, and rakkess automate discovery of dangerous permission combinations.

## Prerequisites

- Kubernetes cluster with RBAC enabled (default since 1.6)
- kubectl with cluster-admin access for full audit
- rbac-tool, rakkess, or KubiScan installed

## Core Concepts

### RBAC Components

| Resource | Scope | Purpose |
|----------|-------|---------|
| Role | Namespace | Grants permissions within a namespace |
| ClusterRole | Cluster | Grants permissions cluster-wide |
| RoleBinding | Namespace | Binds Role/ClusterRole to subjects in namespace |
| ClusterRoleBinding | Cluster | Binds ClusterRole to subjects cluster-wide |

### Dangerous Permission Combinations

| Permission | Risk | Impact |
|-----------|------|--------|
| `*` on `*` resources | Critical | Equivalent to cluster-admin |
| create pods | High | Can deploy privileged pods |
| create pods/exec | High | Can exec into any pod |
| get secrets | High | Can read all secrets |
| create clusterrolebindings | Critical | Can escalate to cluster-admin |
| impersonate users | Critical | Can act as any user |
| escalate on roles | Critical | Can grant permissions beyond own |
| bind on roles | High | Can create new role bindings |

## Implementation Steps

### Step 1: Enumerate All RBAC Resources

```bash
# List all ClusterRoles
kubectl get clusterroles -o name | wc -l
kubectl get clusterroles --no-headers | grep -v "system:"

# List all ClusterRoleBindings
kubectl get clusterrolebindings -o wide

# List all Roles per namespace
kubectl get roles -A

# List all RoleBindings per namespace
kubectl get rolebindings -A -o wide

# Export all RBAC for offline analysis
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o yaml > rbac-export.yaml
```

### Step 2: Identify Wildcard Permissions

```bash
# Find ClusterRoles with wildcard verbs on all resources
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.verbs | index("*")) and
    (.resources | index("*"))
  ) |
  .metadata.name'

# Find roles that can create pods
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.verbs | index("create") or index("*")) and
    (.resources | index("pods") or index("*"))
  ) |
  .metadata.name'

# Find roles that can read secrets
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.verbs | index("get") or index("list") or index("*")) and
    (.resources | index("secrets") or index("*"))
  ) |
  .metadata.name'
```

### Step 3: Check Service Account Permissions

```bash
# List all service accounts
kubectl get serviceaccounts -A

# Check permissions for default service accounts
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== $ns/default ==="
  kubectl auth can-i --list --as=system:serviceaccount:$ns:default 2>/dev/null | grep -v "no"
done

# Check for service accounts with cluster-admin
kubectl get clusterrolebindings -o json | jq -r '
  .items[] |
  select(.roleRef.name == "cluster-admin") |
  {binding: .metadata.name, subjects: [.subjects[]? | {kind, name, namespace}]}'
```

### Step 4: Use rbac-tool for Automated Analysis

```bash
# Install rbac-tool
kubectl krew install rbac-tool

# Visualize RBAC
kubectl rbac-tool viz --outformat dot | dot -Tpng > rbac-graph.png

# Find who can perform specific actions
kubectl rbac-tool who-can get secrets -A
kubectl rbac-tool who-can create pods -A
kubectl rbac-tool who-can '*' '*'

# Analyze all permissions
kubectl rbac-tool analysis

# Generate RBAC policy report
kubectl rbac-tool auditgen > rbac-audit.yaml
```

### Step 5: Check for Privilege Escalation Paths

```bash
# Check if any role can escalate privileges
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.verbs | index("escalate") or index("bind") or index("impersonate")) and
    (.resources | index("clusterroles") or index("roles") or index("clusterrolebindings") or index("rolebindings") or index("users") or index("groups") or index("serviceaccounts"))
  ) |
  .metadata.name'

# Check for impersonation permissions
kubectl get clusterroles -o json | jq -r '
  .items[] |
  select(.rules[]? |
    (.verbs | index("impersonate"))
  ) |
  {name: .metadata.name, rules: .rules}'
```

### Step 6: Audit with KubiScan

```bash
# Install KubiScan
pip install kubiscan

# Find risky roles
kubiscan --risky-roles

# Find risky ClusterRoles
kubiscan --risky-clusterroles

# Find risky subjects
kubiscan --risky-subjects

# Find pods with risky service accounts
kubiscan --risky-pods

# Full report
kubiscan --all
```

## Validation Commands

```bash
# Verify specific permission
kubectl auth can-i create pods --as=system:serviceaccount:default:myapp

# Check all permissions for a user
kubectl auth can-i --list --as=developer@example.com

# Validate RBAC with kubescape
kubescape scan framework nsa --controls-config rbac-controls.json

# Test least privilege
kubectl auth can-i delete nodes --as=system:serviceaccount:app:web-server
# Expected: no
```

## References

- [Kubernetes RBAC Documentation](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [rbac-tool GitHub](https://github.com/alcideio/rbac-tool)
- [KubiScan - Risky Permissions Scanner](https://github.com/cyberark/KubiScan)
- [CIS Kubernetes Benchmark - Section 5.1](https://www.cisecurity.org/benchmark/kubernetes)
