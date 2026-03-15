# API Reference: Kubernetes RBAC Audit

## Python Kubernetes Client
```python
from kubernetes import client, config
config.load_kube_config()
rbac = client.RbacAuthorizationV1Api()
core = client.CoreV1Api()
```

## RBAC API Calls
| Method | Description |
|--------|-------------|
| `rbac.list_cluster_role()` | List all ClusterRoles |
| `rbac.list_cluster_role_binding()` | List all ClusterRoleBindings |
| `rbac.list_namespaced_role(ns)` | List Roles in namespace |
| `rbac.list_namespaced_role_binding(ns)` | List RoleBindings in namespace |

## ClusterRole Rule Structure
```python
role.rules[0].verbs       # ["get", "list", "watch"]
role.rules[0].resources   # ["pods", "secrets"]
role.rules[0].api_groups  # ["", "apps"]
```

## Dangerous RBAC Permissions
| Permission | Risk |
|------------|------|
| `* / *` (all verbs, resources) | Full cluster admin |
| `create` on `pods/exec` | Remote code execution |
| `get` on `secrets` | Credential theft |
| `bind` on `clusterroles` | Privilege escalation |
| `impersonate` on users | Identity spoofing |
| `escalate` on roles | Self-privilege escalation |

## Subject Types
| Kind | Description |
|------|-------------|
| User | Human user identity |
| Group | User group (e.g., system:authenticated) |
| ServiceAccount | Pod identity |

## Risky Groups
| Group | Risk |
|-------|------|
| `system:unauthenticated` | Anonymous access |
| `system:authenticated` | Any authenticated user |
| `system:masters` | Full cluster admin |

## kubectl RBAC Commands
```bash
kubectl auth can-i --list
kubectl get clusterrolebindings -o json
kubectl auth can-i create pods --as=system:serviceaccount:default:default
```
