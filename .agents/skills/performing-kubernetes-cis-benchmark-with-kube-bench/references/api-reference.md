# API Reference — Performing Kubernetes CIS Benchmark with kube-bench

## Libraries Used
- **subprocess**: Execute kube-bench, kubectl commands
- **json**: Parse kube-bench JSON output and kubectl resource data

## CLI Interface
```
python agent.py bench [--target master|node|etcd|policies] [--benchmark cis-1.8]
python agent.py pods [--namespace default]
python agent.py rbac
python agent.py netpol [--namespace default]
```

## Core Functions

### `run_kube_bench(target, benchmark)` — Execute CIS benchmark scan
Runs kube-bench with JSON output. Returns pass/fail/warn/info summary and compliance percentage.
Targets: master, controlplane, node, etcd, policies.

### `check_pod_security(namespace)` — Audit pod security contexts
Checks for: privileged containers, root user, writable root filesystem,
dangerous capabilities (SYS_ADMIN, NET_ADMIN, ALL), privilege escalation.

### `check_rbac_config()` — Audit cluster RBAC
Detects wildcard permissions (`*` verbs on `*` resources), pod creation rights,
and cluster-admin bindings to service accounts/users.

### `check_network_policies(namespace)` — Verify network segmentation
Flags namespaces with no NetworkPolicy. Lists policy coverage details.

## Pod Security Issues Detected
| Issue | Description |
|-------|-------------|
| PRIVILEGED_CONTAINER | Container runs in privileged mode |
| RUNS_AS_ROOT | No runAsNonRoot constraint |
| WRITABLE_ROOT_FS | readOnlyRootFilesystem not set |
| DANGEROUS_CAPABILITIES | SYS_ADMIN/NET_ADMIN/ALL added |
| PRIVILEGE_ESCALATION_ALLOWED | allowPrivilegeEscalation not false |

## Dependencies
System: kube-bench (Aqua Security), kubectl with cluster access
No Python packages required.
