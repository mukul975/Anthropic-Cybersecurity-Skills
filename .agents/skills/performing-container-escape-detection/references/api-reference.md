# API Reference: Performing Container Escape Detection

## kubernetes Python Client

```python
from kubernetes import client, config

config.load_kube_config()  # or config.load_incluster_config()
v1 = client.CoreV1Api()

pods = v1.list_pod_for_all_namespaces()
for pod in pods.items:
    spec = pod.spec
    # Check host namespace sharing
    print(spec.host_pid, spec.host_network, spec.host_ipc)
    for c in spec.containers:
        sc = c.security_context
        if sc:
            print(sc.privileged, sc.capabilities, sc.run_as_user)
    for vol in spec.volumes or []:
        if vol.host_path:
            print(vol.host_path.path)
```

## Container Escape Vectors

| Vector | Field | Severity |
|--------|-------|----------|
| Privileged mode | `securityContext.privileged` | CRITICAL |
| SYS_ADMIN cap | `capabilities.add` | CRITICAL |
| Docker socket | `hostPath: /var/run/docker.sock` | CRITICAL |
| Host PID ns | `hostPID: true` | HIGH |
| Host Network | `hostNetwork: true` | HIGH |
| Writable / mount | `hostPath: /` | CRITICAL |
| Run as root | `runAsUser: 0` | MEDIUM |

## Dangerous Linux Capabilities

```
SYS_ADMIN, SYS_PTRACE, SYS_RAWIO, SYS_MODULE,
DAC_READ_SEARCH, NET_ADMIN, NET_RAW
```

### References

- kubernetes Python client: https://github.com/kubernetes-client/python
- Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Container escapes: https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
