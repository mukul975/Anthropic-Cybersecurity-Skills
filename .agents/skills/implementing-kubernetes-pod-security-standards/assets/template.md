# Pod Security Standards Implementation Template

## Namespace Classification

| Namespace | Current PSS Level | Target PSS Level | Migration Status |
|-----------|------------------|------------------|------------------|
| kube-system | privileged | privileged | N/A |
| production | | restricted | |
| staging | | baseline | |
| development | | baseline | |

## PSS Label Configuration

| Namespace | enforce | audit | warn | Version |
|-----------|---------|-------|------|---------|
| | | | | latest |

## Workload Compliance Checklist

### Pod Security Context
- [ ] runAsNonRoot: true
- [ ] runAsUser: non-zero (e.g., 65534)
- [ ] runAsGroup: non-zero
- [ ] fsGroup: appropriate group ID
- [ ] seccompProfile.type: RuntimeDefault

### Container Security Context
- [ ] allowPrivilegeEscalation: false
- [ ] readOnlyRootFilesystem: true
- [ ] capabilities.drop: ["ALL"]
- [ ] capabilities.add: only NET_BIND_SERVICE if needed
- [ ] privileged: false (or not set)

### Pod Spec
- [ ] automountServiceAccountToken: false (unless needed)
- [ ] No hostNetwork, hostPID, hostIPC
- [ ] No hostPath volumes
- [ ] No hostPort in container specs
- [ ] Resource requests and limits defined

## Migration Plan

| Phase | Action | Timeline | Status |
|-------|--------|----------|--------|
| 1 | Apply audit+warn labels | Week 1 | |
| 2 | Review audit violations | Week 2-3 | |
| 3 | Fix workload security contexts | Week 4-6 | |
| 4 | Enable baseline enforce | Week 7 | |
| 5 | Enable restricted enforce | Week 8 | |

## Exceptions

| Namespace | Workload | Required Level | Justification | Approved By |
|-----------|----------|---------------|---------------|-------------|
| | | | | |
