---
name: implementing-policy-as-code-with-open-policy-agent
description: >
  This skill covers implementing Open Policy Agent (OPA) and Gatekeeper for policy-as-code
  enforcement in Kubernetes and CI/CD pipelines. It addresses writing Rego policies, deploying
  OPA Gatekeeper as a Kubernetes admission controller, testing policies in development, and
  integrating policy evaluation into deployment pipelines.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, opa, gatekeeper, policy-as-code, kubernetes, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Policy as Code with Open Policy Agent

## When to Use

- When enforcing organizational security policies across Kubernetes clusters programmatically
- When requiring admission control that blocks non-compliant resources from being created
- When implementing policy governance that can be version-controlled, tested, and audited
- When standardizing security rules across multiple clusters and environments
- When needing a flexible policy engine that extends beyond Kubernetes to APIs and CI/CD

**Do not use** for vulnerability scanning (use Trivy/Checkov), for runtime threat detection (use Falco), or for network policy enforcement (use Kubernetes NetworkPolicy or Calico).

## Prerequisites

- Kubernetes cluster with admin access for Gatekeeper installation
- Helm for Gatekeeper deployment
- OPA CLI or conftest for local policy testing
- Rego knowledge for policy authoring

## Workflow

### Step 1: Install OPA Gatekeeper

```bash
# Install Gatekeeper via Helm
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set replicas=3 \
  --set audit.replicas=1 \
  --set audit.writeToRAMDisk=true
```

### Step 2: Create Constraint Templates

```yaml
# templates/k8s-required-labels.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
      validation:
        openAPIV3Schema:
          type: object
          properties:
            labels:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }

---
# templates/k8s-container-limits.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8scontainerlimits
spec:
  crd:
    spec:
      names:
        kind: K8sContainerLimits
      validation:
        openAPIV3Schema:
          type: object
          properties:
            cpu:
              type: string
            memory:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8scontainerlimits
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container %v has no CPU limit", [container.name])
        }
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container %v has no memory limit", [container.name])
        }

---
# templates/k8s-block-privileged.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblockprivileged
spec:
  crd:
    spec:
      names:
        kind: K8sBlockPrivileged
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblockprivileged
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged container not allowed: %v", [container.name])
        }
        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          container.securityContext.privileged == true
          msg := sprintf("Privileged init container not allowed: %v", [container.name])
        }
```

### Step 3: Apply Constraints

```yaml
# constraints/require-labels.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-team-labels
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
      - apiGroups: ["apps"]
        kinds: ["Deployment", "StatefulSet"]
    excludedNamespaces:
      - kube-system
      - gatekeeper-system
  parameters:
    labels:
      - "team"
      - "environment"
      - "cost-center"

---
# constraints/block-privileged.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockPrivileged
metadata:
  name: block-privileged-containers
spec:
  enforcementAction: deny
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
      - apiGroups: ["apps"]
        kinds: ["Deployment", "DaemonSet", "StatefulSet"]
    excludedNamespaces:
      - kube-system
```

### Step 4: Test Policies with conftest

```bash
# Install conftest
brew install conftest

# Test Kubernetes manifests against OPA policies locally
conftest test deployment.yaml --policy policies/ --output json

# Test Terraform against OPA policies
conftest test terraform/main.tf --policy policies/terraform/ --parser hcl2

# Test Dockerfiles
conftest test Dockerfile --policy policies/docker/
```

```rego
# policies/kubernetes/deny_latest_tag.rego
package kubernetes

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %v uses :latest tag. Pin to specific version.", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not contains(container.image, ":")
  msg := sprintf("Container %v has no tag. Pin to specific version.", [container.name])
}
```

### Step 5: Integrate Policy Testing in CI/CD

```yaml
# .github/workflows/policy-test.yml
name: Policy Validation

on:
  pull_request:
    paths: ['k8s/**', 'terraform/**', 'policies/**']

jobs:
  conftest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install conftest
        run: |
          wget -q https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz
          tar xzf conftest_0.50.0_Linux_x86_64.tar.gz
          sudo mv conftest /usr/local/bin/
      - name: Test K8s manifests
        run: conftest test k8s/**/*.yaml --policy policies/kubernetes/ --output json
      - name: Test Terraform
        run: conftest test terraform/*.tf --policy policies/terraform/ --parser hcl2
```

## Key Concepts

| Term | Definition |
|------|------------|
| OPA | Open Policy Agent — general-purpose policy engine using Rego language for policy decisions |
| Rego | OPA's declarative query language for writing policy rules |
| Gatekeeper | Kubernetes-native OPA integration implementing admission control via ConstraintTemplates |
| ConstraintTemplate | CRD defining the Rego policy logic and parameters schema for a class of constraints |
| Constraint | Instance of a ConstraintTemplate with specific parameters and scope (which resources to check) |
| Admission Controller | Kubernetes component that intercepts API requests before persistence and can allow or deny them |
| conftest | CLI tool for testing structured data (YAML, JSON, HCL) against OPA policies |

## Tools & Systems

- **Open Policy Agent (OPA)**: General-purpose policy engine for unified policy enforcement
- **Gatekeeper**: Kubernetes admission controller built on OPA with CRD-based configuration
- **conftest**: Testing framework for OPA policies against configuration files
- **Kyverno**: Alternative Kubernetes policy engine using YAML-based policies (no Rego required)
- **Styra DAS**: Commercial OPA management platform with policy authoring, testing, and distribution

## Common Scenarios

### Scenario: Enforcing Container Security Standards Across Clusters

**Context**: Multiple development teams deploy to shared Kubernetes clusters. Some teams run privileged containers and images without resource limits, causing security and stability issues.

**Approach**:
1. Deploy Gatekeeper on all clusters via GitOps (Helm chart in a FluxCD repository)
2. Create ConstraintTemplates for: no privileged containers, required resource limits, required labels, no latest tag
3. Start with `enforcementAction: warn` to identify violations without blocking deployments
4. Notify teams of violations and provide a 2-week remediation window
5. Switch to `enforcementAction: deny` after the remediation period
6. Add `excludedNamespaces` for kube-system and monitoring namespaces

**Pitfalls**: Deploying Gatekeeper with deny mode immediately can break existing workloads. Always start with warn mode. Overly restrictive policies without exemptions for system namespaces can prevent cluster components from functioning.

## Output Format

```
OPA Policy Evaluation Report
==============================
Cluster: production-east
Date: 2026-02-23
Gatekeeper Version: 3.16.0

CONSTRAINT SUMMARY:
  K8sRequiredLabels:        12 violations (warn)
  K8sBlockPrivileged:        0 violations (deny)
  K8sContainerLimits:        8 violations (deny)
  K8sBlockLatestTag:         3 violations (deny)

BLOCKED DEPLOYMENTS (deny):
  [K8sContainerLimits] deployment/api-server in ns/payments
    - Container 'api' has no memory limit
  [K8sBlockLatestTag] deployment/frontend in ns/web
    - Container 'nginx' uses :latest tag

AUDIT VIOLATIONS (warn):
  [K8sRequiredLabels] namespace/staging
    - Missing labels: {cost-center}
```
