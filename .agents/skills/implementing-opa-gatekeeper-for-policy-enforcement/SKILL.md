---
name: implementing-opa-gatekeeper-for-policy-enforcement
description: Enforce Kubernetes admission policies using OPA Gatekeeper with ConstraintTemplates, Rego rules, and the Gatekeeper policy library.
domain: cybersecurity
subdomain: container-security
tags: [opa, gatekeeper, kubernetes, admission-control, policy-as-code, rego]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing OPA Gatekeeper for Policy Enforcement

## Overview

OPA Gatekeeper is a Kubernetes admission controller that enforces policies written in Rego. It uses ConstraintTemplates (policy blueprints with Rego logic) and Constraints (instantiated policies with parameters) to validate, mutate, or deny Kubernetes resource requests at admission time.

## Prerequisites

- Kubernetes cluster v1.24+
- Helm 3
- kubectl with cluster-admin access
- Familiarity with Rego policy language

## Installing Gatekeeper

```bash
# Install via Helm
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update

helm install gatekeeper gatekeeper/gatekeeper \
  --namespace gatekeeper-system --create-namespace \
  --set replicas=3 \
  --set audit.replicas=1 \
  --set audit.logLevel=INFO

# Verify
kubectl get pods -n gatekeeper-system
kubectl get crd | grep gatekeeper
```

### Verify Installation

```bash
# Check webhook
kubectl get validatingwebhookconfigurations gatekeeper-validating-webhook-configuration

# Check CRDs
kubectl get crd constrainttemplates.templates.gatekeeper.sh
kubectl get crd configs.config.gatekeeper.sh
```

## ConstraintTemplate Examples

### 1. Require Labels on Resources

```yaml
# template-required-labels.yaml
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

        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("Missing required labels: %v", [missing])
        }
```

```yaml
# constraint-require-team-label.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: require-team-label
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
      - apiGroups: ["apps"]
        kinds: ["Deployment"]
  parameters:
    labels:
      - "team"
      - "environment"
```

### 2. Block Privileged Containers

```yaml
# template-block-privileged.yaml
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

```yaml
# constraint-block-privileged.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockPrivileged
metadata:
  name: block-privileged-containers
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces:
      - "production"
      - "staging"
```

### 3. Restrict Container Image Registries

```yaml
# template-allowed-repos.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sallowedrepos
spec:
  crd:
    spec:
      names:
        kind: K8sAllowedRepos
      validation:
        openAPIV3Schema:
          type: object
          properties:
            repos:
              type: array
              items:
                type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sallowedrepos

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not image_matches(container.image)
          msg := sprintf("Container image %v is not from an allowed registry. Allowed: %v", [container.image, input.parameters.repos])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.initContainers[_]
          not image_matches(container.image)
          msg := sprintf("Init container image %v is not from an allowed registry. Allowed: %v", [container.image, input.parameters.repos])
        }

        image_matches(image) {
          repo := input.parameters.repos[_]
          startswith(image, repo)
        }
```

```yaml
# constraint-allowed-repos.yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
metadata:
  name: restrict-image-repos
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    repos:
      - "gcr.io/my-project/"
      - "ghcr.io/my-org/"
      - "registry.k8s.io/"
```

### 4. Enforce Resource Limits

```yaml
# template-require-limits.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8srequirelimits
spec:
  crd:
    spec:
      names:
        kind: K8sRequireLimits
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequirelimits

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
```

### 5. Block Latest Image Tag

```yaml
# template-block-latest-tag.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sblocklatesttag
spec:
  crd:
    spec:
      names:
        kind: K8sBlockLatestTag
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sblocklatesttag

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          endswith(container.image, ":latest")
          msg := sprintf("Container %v uses ':latest' tag. Use specific version tags.", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not contains(container.image, ":")
          msg := sprintf("Container %v has no tag (defaults to latest). Use specific version tags.", [container.name])
        }
```

### 6. Enforce Read-Only Root Filesystem

```yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sreadonlyroot
spec:
  crd:
    spec:
      names:
        kind: K8sReadOnlyRoot
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sreadonlyroot

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.securityContext.readOnlyRootFilesystem
          msg := sprintf("Container %v must have readOnlyRootFilesystem set to true", [container.name])
        }
```

## Audit and Enforcement Modes

```yaml
# Dry-run mode (audit only, don't block)
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sBlockPrivileged
metadata:
  name: block-privileged-dryrun
spec:
  enforcementAction: dryrun   # dryrun | deny | warn
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
```

### Check Audit Violations

```bash
# List all constraint violations
kubectl get k8sblockprivileged block-privileged-containers -o yaml | grep -A 20 violations

# Check all constraints audit status
kubectl get constraints -o json | jq '.items[] | {name: .metadata.name, violations: (.status.violations // [] | length)}'
```

## Gatekeeper Config (Exempt Namespaces)

```yaml
apiVersion: config.gatekeeper.sh/v1alpha1
kind: Config
metadata:
  name: config
  namespace: gatekeeper-system
spec:
  match:
    - excludedNamespaces:
        - kube-system
        - gatekeeper-system
        - calico-system
      processes:
        - "*"
```

## Monitoring

```bash
# Check Gatekeeper metrics
kubectl port-forward -n gatekeeper-system svc/gatekeeper-webhook-service 8443:443

# Prometheus metrics
kubectl get --raw /metrics | grep gatekeeper
```

## Best Practices

1. **Start with dryrun** - Deploy constraints in `dryrun` mode first, review violations, then switch to `deny`
2. **Use the policy library** - Leverage https://github.com/open-policy-agent/gatekeeper-library for pre-built templates
3. **Exempt system namespaces** - Always exclude kube-system and gatekeeper-system
4. **Version control policies** - Store ConstraintTemplates and Constraints in Git
5. **Monitor audit results** - Check constraint `.status.violations` regularly
6. **Test Rego policies** - Use `opa test` or Rego Playground before deploying
7. **Combine with admission webhooks** - Layer Gatekeeper with Pod Security Admission for defense in depth
