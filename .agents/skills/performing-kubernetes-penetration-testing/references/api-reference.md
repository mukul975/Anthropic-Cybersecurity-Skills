# API Reference — Performing Kubernetes Penetration Testing

## Libraries Used
- **subprocess**: Execute kubectl commands for cluster reconnaissance and testing
- **json**: Parse Kubernetes API JSON output

## CLI Interface
```
python agent.py recon
python agent.py sa-perms [--namespace default]
python agent.py dashboards
python agent.py escape [--namespace default]
```

## Core Functions

### `enumerate_cluster_info()` — Cluster reconnaissance
Gathers: K8s version, node info (OS, kubelet), namespaces, services with types/ports.

### `test_service_account_permissions(namespace)` — RBAC permission testing
Tests 8 permissions via `kubectl auth can-i`:
get pods, list/get secrets, create pods, exec into pods, get nodes, list namespaces, create clusterroles.

### `scan_exposed_dashboards()` — Find management interfaces
Searches for: dashboard, grafana, prometheus, kibana, jaeger, argocd, rancher, lens.
Flags LoadBalancer/NodePort services as externally accessible.

### `check_pod_escape_vectors(namespace)` — Container escape analysis
Detects: privileged mode, CAP_SYS_ADMIN/SYS_PTRACE, hostPath mounts (/, /etc, docker.sock, /proc, /sys),
hostPID namespace, hostNetwork.

## Dangerous Permissions (CRITICAL)
- `list secrets` / `get secrets --all-namespaces`
- `create pods` (pod creation with escalation)
- `create pods/exec` (remote code execution)
- `create clusterroles` (RBAC escalation)

## Dependencies
System: kubectl with cluster access
No Python packages required.
