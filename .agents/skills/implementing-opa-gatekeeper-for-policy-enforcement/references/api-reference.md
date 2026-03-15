# API Reference: OPA Gatekeeper Policy Enforcement

## OPA REST API (localhost:8181)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/data/{path}` | GET/POST | Query policy |
| `/v1/policies/{id}` | PUT | Create/update policy |
| `/v1/data` | POST | Evaluate input against policy |

## Gatekeeper CRDs

| CRD | Description |
|-----|-------------|
| `ConstraintTemplate` | Define policy schema + Rego |
| `Constraint` | Instantiate a template |
| `Config` | Audit/sync configuration |

## ConstraintTemplate Example
```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          not input.review.object.metadata.labels["app"]
          msg := "Missing required label: app"
        }
```

## Key Libraries

| Library | Use |
|---------|-----|
| `kubernetes` | K8s API client |
| `requests` | OPA REST queries |
| `subprocess` | kubectl commands |
