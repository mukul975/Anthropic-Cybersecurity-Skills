# API Reference: Scanning Kubernetes Manifests with Kubesec

## Kubesec CLI Commands

| Command | Description |
|---------|-------------|
| `kubesec scan <file>` | Scan a manifest file |
| `kubesec scan -o json <file>` | JSON output |
| `kubesec http --port 8080` | Start local API server |
| `kubesec version` | Show version info |

## Kubesec HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `https://v2.kubesec.io/scan` | Public scan API |
| POST | `http://localhost:8080/scan` | Local scan API |

## Critical Checks (Negative Score)

| Check | Selector | Risk |
|-------|----------|------|
| Privileged | `securityContext.privileged == true` | Full host access |
| HostPID | `spec.hostPID == true` | Process namespace escape |
| HostNetwork | `spec.hostNetwork == true` | Network namespace escape |
| SYS_ADMIN | `capabilities.add contains SYS_ADMIN` | Near-root capability |

## Best Practice Checks (Positive Score)

| Check | Points | Description |
|-------|--------|-------------|
| ReadOnlyRootFilesystem | +1 | Prevents filesystem writes |
| RunAsNonRoot | +1 | Non-root execution |
| RunAsUser > 10000 | +1 | High UID |
| LimitsCPU | +1 | CPU limits set |
| LimitsMemory | +1 | Memory limits set |
| ServiceAccountName | +3 | Explicit service account |
| AppArmor annotation | +3 | MAC enforcement |
| Seccomp profile | +4 | Syscall filtering |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute kubesec CLI |
| `requests` | >=2.28 | HTTP API fallback |
| `json` | stdlib | Parse scan results |

## References

- Kubesec GitHub: https://github.com/controlplaneio/kubesec
- Kubesec Online: https://kubesec.io/
- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
