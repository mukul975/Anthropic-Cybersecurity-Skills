# API Reference: Auditing Kubernetes Cluster RBAC

## kubernetes (Python Client)

### Configuration

```python
from kubernetes import client, config

config.load_kube_config()  # From ~/.kube/config
# or
config.load_incluster_config()  # Inside a pod
```

### List ClusterRoles

```python
rbac = client.RbacAuthorizationV1Api()
roles = rbac.list_cluster_role()
for role in roles.items:
    print(role.metadata.name)
    for rule in role.rules or []:
        print(f"  verbs={rule.verbs} resources={rule.resources}")
```

### List ClusterRoleBindings

```python
bindings = rbac.list_cluster_role_binding()
for b in bindings.items:
    print(b.metadata.name, "->", b.role_ref.name)
    for s in b.subjects or []:
        print(f"  {s.kind}: {s.name}")
```

### List Pods (Security Context)

```python
v1 = client.CoreV1Api()
pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    for c in pod.spec.containers:
        sc = c.security_context
        if sc and sc.privileged:
            print(f"PRIVILEGED: {pod.metadata.namespace}/{pod.metadata.name}")
```

## Key RBAC Resources

| Resource | API | Description |
|----------|-----|-------------|
| ClusterRole | `rbac.list_cluster_role()` | Cluster-wide permission definitions |
| ClusterRoleBinding | `rbac.list_cluster_role_binding()` | Binds roles to subjects cluster-wide |
| Role | `rbac.list_namespaced_role(ns)` | Namespace-scoped permissions |
| RoleBinding | `rbac.list_namespaced_role_binding(ns)` | Namespace-scoped binding |
| ServiceAccount | `v1.list_service_account_for_all_namespaces()` | Pod identities |

## Dangerous RBAC Patterns to Detect

| Pattern | Risk |
|---------|------|
| `verbs: ["*"], resources: ["*"]` | Equivalent to cluster-admin |
| `resources: ["secrets"], verbs: ["get"]` | Can read all secrets |
| `resources: ["pods/exec"]` | Can exec into containers |
| `subjects: system:authenticated` | All users get this role |
| `automountServiceAccountToken: true` | Token available in pod |

### References

- kubernetes Python client: https://pypi.org/project/kubernetes/
- K8s RBAC docs: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- KubiScan: https://github.com/cyberark/KubiScan
