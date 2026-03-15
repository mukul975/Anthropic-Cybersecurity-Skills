---
name: auditing-kubernetes-cluster-rbac
description: >
  Auditing Kubernetes cluster RBAC configurations to identify overly permissive roles,
  wildcard permissions, dangerous ClusterRoleBindings, service account abuse, and
  privilege escalation paths using kubectl, rbac-tool, KubiScan, and Kubeaudit.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, kubernetes, rbac, access-control, eks, gke, aks]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Auditing Kubernetes Cluster RBAC

## When to Use

- When performing security assessments of Kubernetes clusters (EKS, GKE, AKS, or self-managed)
- When validating that RBAC policies enforce least privilege for users and service accounts
- When investigating potential lateral movement or privilege escalation within a Kubernetes cluster
- When compliance audits require documentation of access controls and permissions
- When onboarding new teams to a shared cluster and defining appropriate RBAC policies

**Do not use** for network policy auditing (use Cilium or Calico network policy tools), for container image scanning (use Trivy or Grype), or for runtime security monitoring (use Falco or Sysdig Secure).

## Prerequisites

- kubectl configured with cluster-admin or equivalent read permissions to the target cluster
- rbac-tool installed (`kubectl krew install rbac-tool` or binary from GitHub)
- KubiScan installed (`pip install kubiscan`)
- Kubeaudit installed (`brew install kubeaudit` or from GitHub releases)
- Access to the cluster's audit logs for correlating RBAC findings with actual API access

## Workflow

### Step 1: Enumerate ClusterRoles and Roles with Dangerous Permissions

Identify roles with wildcard permissions, secret access, pod exec, or escalation capabilities.

```bash
# List all ClusterRoles with wildcard verb access
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        verbs = rule.get('verbs', [])
        resources = rule.get('resources', [])
        if '*' in verbs or '*' in resources:
            print(f'ClusterRole: {name}')
            print(f'  Verbs: {verbs}')
            print(f'  Resources: {resources}')
            print(f'  API Groups: {rule.get(\"apiGroups\", [])}')
            print()
"

# Find roles that can read secrets
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])
        if ('secrets' in resources or '*' in resources) and ('get' in verbs or 'list' in verbs or '*' in verbs):
            if not name.startswith('system:'):
                print(f'ClusterRole: {name} -> can access secrets (verbs: {verbs})')
"

# Find roles with pod/exec permissions (container escape risk)
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        resources = rule.get('resources', [])
        if 'pods/exec' in resources or 'pods/*' in resources:
            print(f'ClusterRole: {name} -> has pods/exec access')
"
```

### Step 2: Audit ClusterRoleBindings and RoleBindings

Review bindings to identify who has elevated access and detect overly broad group assignments.

```bash
# List all ClusterRoleBindings with the subjects
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    name = binding['metadata']['name']
    role = binding['roleRef']['name']
    subjects = binding.get('subjects', [])
    for subject in subjects:
        kind = subject.get('kind', '')
        subj_name = subject.get('name', '')
        ns = subject.get('namespace', 'cluster-wide')
        print(f'{name} -> Role: {role} | {kind}: {subj_name} ({ns})')
" | sort

# Find bindings to cluster-admin
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    if binding['roleRef']['name'] == 'cluster-admin':
        print(f\"Binding: {binding['metadata']['name']}\")
        for subject in binding.get('subjects', []):
            print(f\"  {subject.get('kind')}: {subject.get('name')} (ns: {subject.get('namespace', 'N/A')})\")
"

# Find bindings granting access to all authenticated users
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    for subject in binding.get('subjects', []):
        if subject.get('name') in ['system:authenticated', 'system:unauthenticated']:
            print(f\"WARNING: {binding['metadata']['name']} grants {binding['roleRef']['name']} to {subject['name']}\")
"
```

### Step 3: Scan with rbac-tool for Comprehensive Analysis

Use rbac-tool for automated RBAC analysis including who-can queries and policy generation.

```bash
# Who can get secrets across all namespaces
kubectl rbac-tool who-can get secrets

# Who can create pods (potential for container escape)
kubectl rbac-tool who-can create pods

# Who can exec into pods
kubectl rbac-tool who-can create pods/exec

# Who can escalate privileges (bind/escalate verbs)
kubectl rbac-tool who-can bind clusterroles
kubectl rbac-tool who-can escalate clusterroles

# Generate RBAC policy report
kubectl rbac-tool analysis

# Visualize RBAC relationships
kubectl rbac-tool viz --outformat dot > rbac-graph.dot
dot -Tpng rbac-graph.dot -o rbac-graph.png
```

### Step 4: Run KubiScan for Risky Permissions Detection

Use KubiScan to automatically identify risky service accounts, pods, and RBAC configurations.

```bash
# Run KubiScan to find risky roles
python3 -m kubiscan -rroles   # List risky Roles
python3 -m kubiscan -rcr      # List risky ClusterRoles
python3 -m kubiscan -rrb      # List risky RoleBindings
python3 -m kubiscan -rcrb     # List risky ClusterRoleBindings

# Find risky service accounts
python3 -m kubiscan -rs       # Risky service accounts

# Find pods running with risky service accounts
python3 -m kubiscan -rp       # Risky pods

# Check for privilege escalation paths
python3 -m kubiscan -pe       # Privilege escalation vectors

# Generate full report
python3 -m kubiscan -a        # All checks
```

### Step 5: Audit Service Account Token Mounting and Usage

Check for unnecessary service account token mounts that could enable lateral movement from compromised pods.

```bash
# Find pods with automounted service account tokens
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pod in data['items']:
    name = pod['metadata']['name']
    ns = pod['metadata']['namespace']
    sa = pod['spec'].get('serviceAccountName', 'default')
    automount = pod['spec'].get('automountServiceAccountToken', True)
    if automount and sa != 'default':
        print(f'{ns}/{name} -> SA: {sa} (token auto-mounted)')
"

# Find service accounts with non-default token secrets
kubectl get serviceaccounts --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for sa in data['items']:
    name = sa['metadata']['name']
    ns = sa['metadata']['namespace']
    secrets = sa.get('secrets', [])
    if name != 'default' and len(secrets) > 0:
        print(f'{ns}/{name}: {len(secrets)} secret(s) bound')
"

# Check for pods running as privileged or with host access
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pod in data['items']:
    name = pod['metadata']['name']
    ns = pod['metadata']['namespace']
    for container in pod['spec'].get('containers', []):
        sc = container.get('securityContext', {})
        if sc.get('privileged', False) or sc.get('runAsUser', 1) == 0:
            print(f'RISK: {ns}/{name}/{container[\"name\"]} - privileged={sc.get(\"privileged\",False)} runAsRoot={sc.get(\"runAsUser\",\"not set\")==0}')
"
```

### Step 6: Run Kubeaudit for RBAC and Security Policy Validation

Execute Kubeaudit for comprehensive security checks including RBAC-related findings.

```bash
# Run all kubeaudit checks
kubeaudit all --kubeconfig ~/.kube/config

# Run specific RBAC-related checks
kubeaudit privesc    # Check for allowPrivilegeEscalation
kubeaudit rootfs     # Check for readOnlyRootFilesystem
kubeaudit nonroot    # Check for runAsNonRoot
kubeaudit capabilities  # Check for dangerous capabilities

# Output as JSON for processing
kubeaudit all --kubeconfig ~/.kube/config -f json > kubeaudit-results.json
```

## Key Concepts

| Term | Definition |
|------|------------|
| RBAC | Role-Based Access Control in Kubernetes, a method for regulating access to cluster resources based on the roles of individual users or service accounts |
| ClusterRole | Cluster-wide role definition that specifies permissions (verbs on resources) applicable across all namespaces |
| ClusterRoleBinding | Associates a ClusterRole with subjects (users, groups, service accounts) at the cluster scope |
| Service Account | Identity associated with pods for authenticating to the Kubernetes API server, automatically mounted unless disabled |
| automountServiceAccountToken | Pod spec field controlling whether the service account token is automatically mounted into the pod filesystem |
| Privilege Escalation | RBAC verbs (bind, escalate, impersonate) that allow a user to grant themselves or others elevated permissions |

## Tools & Systems

- **kubectl**: Primary CLI for querying Kubernetes RBAC resources (roles, bindings, service accounts)
- **rbac-tool**: kubectl plugin for RBAC analysis including who-can queries, visualization, and policy generation
- **KubiScan**: Python tool for scanning Kubernetes RBAC for risky permissions and privilege escalation paths
- **Kubeaudit**: Security auditing tool that checks pods and workloads for security anti-patterns including RBAC issues
- **rakkess**: kubectl plugin showing access matrix for the current user across all resource types

## Common Scenarios

### Scenario: Auditing an EKS Cluster Shared by Multiple Development Teams

**Context**: A shared EKS cluster serves four development teams. RBAC was configured during initial setup but has not been reviewed in 12 months. Teams report being able to access other teams' namespaces.

**Approach**:
1. List all ClusterRoleBindings to identify bindings granting broad access to authenticated users
2. Run `kubectl rbac-tool who-can get secrets` to find subjects that can read secrets across namespaces
3. Discover that a ClusterRoleBinding grants `edit` to `system:authenticated`, giving all users write access cluster-wide
4. Run KubiScan to identify service accounts with risky permissions and pods running with elevated service accounts
5. Replace the ClusterRoleBinding with namespace-scoped RoleBindings for each team
6. Disable automountServiceAccountToken for workloads that do not need API access
7. Create a NetworkPolicy to isolate namespace traffic between teams

**Pitfalls**: Removing ClusterRoleBindings can break CI/CD pipelines and operators that rely on cluster-wide access. Always audit which workloads use the bindings before removing them. EKS maps IAM roles to Kubernetes groups via aws-auth ConfigMap, so RBAC changes must be coordinated with IAM role mappings.

## Output Format

```
Kubernetes RBAC Audit Report
===============================
Cluster: production-eks (EKS 1.28)
Audit Date: 2026-02-23
Namespaces: 12

RBAC INVENTORY:
  ClusterRoles: 48 (18 custom, 30 system)
  ClusterRoleBindings: 32 (12 custom, 20 system)
  Roles (namespaced): 24
  RoleBindings (namespaced): 36
  Service Accounts: 67

CRITICAL FINDINGS:
[RBAC-001] ClusterRoleBinding Grants edit to system:authenticated
  Binding: authenticated-edit
  Effect: ALL authenticated users have edit access across ALL namespaces
  Risk: Any user can modify resources in any namespace
  Remediation: Replace with namespace-scoped RoleBindings per team

[RBAC-002] Custom ClusterRole with Wildcard Permissions
  ClusterRole: developer-admin
  Rules: verbs=["*"], resources=["*"], apiGroups=["*"]
  Bindings: 4 users via developer-admin-binding
  Risk: Equivalent to cluster-admin without the name
  Remediation: Scope to specific resources and verbs needed

SUMMARY:
  Principals with cluster-admin: 6 (recommended: <= 3)
  Roles with wildcard permissions: 4
  Service accounts with secret access: 12
  Pods with auto-mounted tokens: 45 / 67
  Privileged containers: 8
```
