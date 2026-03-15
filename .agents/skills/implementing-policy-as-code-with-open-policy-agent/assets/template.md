# OPA Policy as Code Templates

## Gatekeeper ConstraintTemplate Library

```yaml
# Block containers running as root
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockrootuser
spec:
  crd:
    spec:
      names:
        kind: K8sBlockRootUser
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockrootuser
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.runAsUser == 0
          msg := sprintf("Container %v runs as root (UID 0)", [container.name])
        }
        violation[{"msg": msg}] {
          input.review.object.spec.securityContext.runAsUser == 0
          msg := "Pod runs as root (UID 0)"
        }
```

## conftest Policy for CI/CD

```rego
# policies/kubernetes/security.rego
package kubernetes

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Privileged container '%v' not allowed", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits
  msg := sprintf("Container '%v' missing resource limits", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container '%v' uses :latest tag", [container.name])
}
```

## GitHub Actions Integration

```yaml
name: Policy Check
on:
  pull_request:
    paths: ['k8s/**']
jobs:
  conftest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: open-policy-agent/conftest-action@v1
        with:
          files: k8s/
          policy: policies/kubernetes/
```
