# API Reference: Cilium Tetragon Runtime Security

## TracingPolicy CRD

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-sensitive-files
spec:
  kprobes:
    - call: fd_install
      args:
        - index: 1
          type: file
      selectors:
        - matchArgs:
            - index: 1
              operator: Prefix
              values: ["/etc/shadow", "/etc/passwd"]
```

## Tetra CLI Commands

| Command | Description |
|---------|-------------|
| `tetra status` | Tetragon health |
| `tetra getevents` | Stream events |
| `tetra tracingpolicy list` | List policies |

## Event Types

| Type | Description |
|------|-------------|
| `process_exec` | Process execution |
| `process_exit` | Process termination |
| `process_kprobe` | Kernel probe trigger |

## Key Libraries

| Library | Use |
|---------|-----|
| `kubernetes` | K8s API client |
| `subprocess` | kubectl/tetra CLI |
| `grpc` | Tetragon gRPC API |
