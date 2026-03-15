# Pod Security Admission Deployment Plan

## Namespace PSA Configuration

| Namespace | Enforce | Audit | Warn | Justification |
|-----------|---------|-------|------|---------------|
| production | restricted | restricted | restricted | Production workloads |
| staging | baseline | restricted | restricted | Pre-production testing |
| development | baseline | restricted | restricted | Developer workloads |
| kube-system | privileged | - | - | System components |
| monitoring | privileged | - | - | Prometheus, Grafana |
| ingress-nginx | baseline | restricted | restricted | Ingress controller |

## Migration Checklist

- [ ] Audit all namespaces with dry-run
- [ ] Document violations per namespace
- [ ] Apply audit+warn mode first
- [ ] Fix violations in workloads
- [ ] Test enforcement with dry-run
- [ ] Apply enforce mode
- [ ] Set cluster-wide defaults
- [ ] Monitor for rejected pods
- [ ] Remove deprecated PSPs (if applicable)

## Compliant Security Context Template

```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
```
