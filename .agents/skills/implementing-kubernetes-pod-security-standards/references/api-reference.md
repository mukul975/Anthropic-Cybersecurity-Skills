# API Reference: Implementing Kubernetes Pod Security Standards

## PSA Namespace Labels

```bash
# Apply restricted enforcement
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite
```

## Pod Security Standard Levels

| Level | Description | Blocks |
|-------|-------------|--------|
| Privileged | Unrestricted | Nothing |
| Baseline | Minimally restrictive | hostNetwork, privileged, hostPID/IPC |
| Restricted | Heavily restricted | + runAsNonRoot, drop ALL caps, seccomp |

## PSA Modes

| Mode | Behavior |
|------|----------|
| enforce | Reject violating pods |
| audit | Log violations (allow pod) |
| warn | Warn user (allow pod) |

## Baseline Violations

| Field | Forbidden Value |
|-------|----------------|
| `spec.hostNetwork` | true |
| `spec.hostPID` | true |
| `spec.hostIPC` | true |
| `containers[*].securityContext.privileged` | true |
| `containers[*].securityContext.capabilities.add` | Non-default |

## Restricted Violations (adds to Baseline)

| Field | Required |
|-------|----------|
| `runAsNonRoot` | true |
| `allowPrivilegeEscalation` | false |
| `capabilities.drop` | ["ALL"] |
| `seccompProfile.type` | RuntimeDefault or Localhost |

### References

- K8s PSS: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- PSA: https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Migrate from PSP: https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/
