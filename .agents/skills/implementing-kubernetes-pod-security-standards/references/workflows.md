# Workflows - Kubernetes Pod Security Standards

## Workflow 1: PSS Migration from PodSecurityPolicy

```
[Identify PSP usage] --> [Map PSP to PSS levels] --> [Apply audit/warn labels]
        |                        |                           |
        v                        v                           v
  kubectl get psp          Privileged PSP -> baseline    Monitor audit logs
  List all namespaces      Restrictive PSP -> restricted  for 2-4 weeks
        |                        |                           |
        +------------------------+---------------------------+
                                 |
                                 v
                    [Enable enforce mode per namespace]
                                 |
                                 v
                    [Remove PodSecurityPolicy resources]
                                 |
                                 v
                    [Disable PSP admission controller]
```

## Workflow 2: New Namespace Onboarding

```
Step 1: Classify workload sensitivity
  - System/Infrastructure -> Privileged (only kube-system)
  - General workloads -> Baseline + Restricted warnings
  - Production/Sensitive -> Restricted enforce

Step 2: Create namespace with labels
  kubectl create namespace $NS
  kubectl label namespace $NS \
    pod-security.kubernetes.io/enforce=$LEVEL \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted

Step 3: Test with dry-run
  kubectl run test --image=nginx -n $NS --dry-run=server

Step 4: Deploy workloads with compliant security contexts

Step 5: Validate enforcement
  kubectl get events -n $NS --field-selector reason=FailedCreate
```

## Workflow 3: CI/CD PSS Compliance Check

```yaml
# Pre-deployment validation
name: PSS Compliance Check
on: pull_request

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install kubescape
        run: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

      - name: Scan manifests for PSS restricted compliance
        run: |
          kubescape scan framework nsa \
            --controls-config controls.json \
            --format junit --output results.xml \
            k8s-manifests/

      - name: Validate security contexts
        run: |
          for file in k8s-manifests/*.yaml; do
            echo "Checking $file..."
            # Verify runAsNonRoot
            if ! grep -q "runAsNonRoot: true" "$file"; then
              echo "FAIL: Missing runAsNonRoot in $file"
              exit 1
            fi
            # Verify drop ALL
            if ! grep -q "drop:" "$file" || ! grep -A1 "drop:" "$file" | grep -q "ALL"; then
              echo "FAIL: Missing drop ALL capabilities in $file"
              exit 1
            fi
          done
```

## Workflow 4: Violation Response

```
[PSA Violation Detected]
        |
        +-- enforce mode --> Pod rejected --> Alert developer
        |                                         |
        |                                         v
        |                                   Fix security context
        |                                   Re-deploy
        |
        +-- audit mode --> Pod allowed, audit log entry
        |                         |
        |                         v
        |                   Weekly audit review
        |                   Create remediation ticket
        |
        +-- warn mode --> Pod allowed, user warning
                                |
                                v
                          Developer sees warning
                          Fix before enforce rollout
```
