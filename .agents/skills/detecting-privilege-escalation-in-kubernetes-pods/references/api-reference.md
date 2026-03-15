# API Reference: Detecting Privilege Escalation in Kubernetes Pods

## Security Context Checks

| Check | Risk | Description |
|-------|------|-------------|
| privileged: true | CRITICAL | Full host access |
| allowPrivilegeEscalation | HIGH | setuid escalation |
| runAsUser: 0 | HIGH | Running as root |
| hostPID: true | CRITICAL | Host PID namespace |
| hostNetwork: true | HIGH | Host network access |

## Dangerous Capabilities

| Capability | Risk |
|------------|------|
| SYS_ADMIN | Container escape |
| SYS_PTRACE | Process debugging |
| SYS_MODULE | Kernel module loading |
| NET_ADMIN | Network manipulation |

## kubectl Audit Commands

```bash
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'
kubectl auth can-i --list --as=system:serviceaccount:ns:sa
```

## Pod Security Standards

```yaml
apiVersion: v1
kind: Namespace
metadata:
  labels:
    pod-security.kubernetes.io/enforce: restricted
```

## Falco Rules

```yaml
- rule: Pod with Privileged Container
  condition: kevt and kcreate and container.privileged=true
  priority: CRITICAL
```

## CLI Usage

```bash
python agent.py --namespace default
python agent.py --json-file pods.json
```
