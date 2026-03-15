# API Reference: Securing Kubernetes on Cloud

## kubernetes Python Client

### Installation
```bash
pip install kubernetes
```

### Configuration
```python
from kubernetes import client, config
config.load_kube_config(context="my-cluster")
```

### Core API (v1)
```python
v1 = client.CoreV1Api()
```
| Method | Description |
|--------|-------------|
| `list_namespace()` | List all namespaces with labels |
| `list_pod_for_all_namespaces()` | List all pods across namespaces |
| `read_namespaced_service_account()` | Get service account details |
| `create_namespace()` | Create namespace with PSA labels |

### RBAC API
```python
rbac = client.RbacAuthorizationV1Api()
```
| Method | Description |
|--------|-------------|
| `list_cluster_role_binding()` | List all ClusterRoleBindings |
| `list_cluster_role()` | List all ClusterRoles |
| `list_namespaced_role_binding()` | List RoleBindings in a namespace |
| `list_namespaced_role()` | List Roles in a namespace |

### Networking API
```python
net = client.NetworkingV1Api()
```
| Method | Description |
|--------|-------------|
| `list_namespaced_network_policy()` | List network policies in a namespace |
| `create_namespaced_network_policy()` | Create a network policy |

### Pod Security Context Fields
| Field | Description |
|-------|-------------|
| `privileged` | Run container in privileged mode |
| `run_as_user` | UID to run the container as |
| `run_as_non_root` | Require non-root UID |
| `read_only_root_filesystem` | Mount root filesystem as read-only |
| `allow_privilege_escalation` | Allow setuid/capabilities |
| `capabilities.drop` | Linux capabilities to drop |
| `seccomp_profile.type` | Seccomp profile (RuntimeDefault) |

### Pod Security Admission Labels
| Label | Values |
|-------|--------|
| `pod-security.kubernetes.io/enforce` | privileged, baseline, restricted |
| `pod-security.kubernetes.io/audit` | privileged, baseline, restricted |
| `pod-security.kubernetes.io/warn` | privileged, baseline, restricted |

## References
- kubernetes-client/python: https://github.com/kubernetes-client/python
- Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Network Policies: https://kubernetes.io/docs/concepts/services-networking/network-policies/
