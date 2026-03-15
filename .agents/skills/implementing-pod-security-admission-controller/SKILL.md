---
name: implementing-pod-security-admission-controller
description: Implement Kubernetes Pod Security Admission to enforce baseline and restricted security profiles at namespace level using built-in admission controller.
domain: cybersecurity
subdomain: container-security
tags: [kubernetes, pod-security-admission, psa, pod-security-standards, admission-controller]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Pod Security Admission Controller

## Overview

Pod Security Admission (PSA) is a built-in Kubernetes admission controller (stable since v1.25) that enforces Pod Security Standards at the namespace level. It replaces the deprecated PodSecurityPolicy (PSP) and provides three security profiles: Privileged, Baseline, and Restricted, with three enforcement modes: enforce, audit, and warn.

## Prerequisites

- Kubernetes v1.25+ (PSA is stable/GA)
- kubectl with cluster-admin access
- No dependency on external tools - PSA is built into kube-apiserver

## Pod Security Standards

### Privileged Profile
- **Unrestricted** - No restrictions applied
- Use case: System-level pods (kube-system, monitoring)

### Baseline Profile
- **Minimally restrictive** - Prevents known privilege escalation
- Blocks: privileged containers, hostPID, hostIPC, hostNetwork, hostPorts, certain volume types, adding capabilities beyond runtime defaults

### Restricted Profile
- **Heavily restricted** - Follows security best practices
- Requires: non-root, drop ALL capabilities, seccomp RuntimeDefault, read-only root filesystem considerations
- Blocks: Everything in Baseline plus running as root, privilege escalation, non-approved volume types

## Enforcement Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| enforce | Reject pods violating policy | Production enforcement |
| audit | Log violations to audit log | Pre-enforcement assessment |
| warn | Show warnings to user | Developer feedback |

## Implementation

### Apply to Namespace via Labels

```yaml
# Restricted enforcement with audit and warn
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
```

```yaml
# Baseline enforcement for staging
apiVersion: v1
kind: Namespace
metadata:
  name: staging
  labels:
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.28
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.28
```

```yaml
# Privileged for system namespaces
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
  labels:
    pod-security.kubernetes.io/enforce: privileged
```

### Apply Labels with kubectl

```bash
# Set restricted enforcement
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=v1.28 \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Set baseline enforcement
kubectl label namespace staging \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted

# Check current labels
kubectl get namespace production -o jsonpath='{.metadata.labels}' | jq .
```

## Dry-Run Testing

```bash
# Test what would happen with restricted policy on a namespace
kubectl label --dry-run=server --overwrite namespace staging \
  pod-security.kubernetes.io/enforce=restricted

# Output shows existing pods that would violate the policy
# Warning: existing pods in namespace "staging" violate the new PodSecurity enforce level "restricted:latest"
```

## Cluster-Wide Defaults (AdmissionConfiguration)

```yaml
# /etc/kubernetes/psa-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: baseline
        enforce-version: latest
        audit: restricted
        audit-version: latest
        warn: restricted
        warn-version: latest
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces:
          - kube-system
          - kube-public
          - kube-node-lease
          - calico-system
          - gatekeeper-system
          - monitoring
          - falco
```

### Apply to API Server

```bash
# Add to kube-apiserver manifests
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --admission-control-config-file=/etc/kubernetes/psa-config.yaml
    volumeMounts:
    - name: psa-config
      mountPath: /etc/kubernetes/psa-config.yaml
      readOnly: true
  volumes:
  - name: psa-config
    hostPath:
      path: /etc/kubernetes/psa-config.yaml
      type: File
```

## Compliant Pod Examples

### Restricted-Compliant Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
  namespace: production
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  automountServiceAccountToken: false
  containers:
    - name: app
      image: myregistry/myapp:v1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: 500m
          memory: 256Mi
        requests:
          cpu: 100m
          memory: 128Mi
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
```

### Baseline-Compliant Pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: baseline-pod
  namespace: staging
spec:
  containers:
    - name: app
      image: myregistry/myapp:v1.0.0
      securityContext:
        allowPrivilegeEscalation: false
      resources:
        limits:
          cpu: 500m
          memory: 256Mi
```

## Migration from PodSecurityPolicy

### Step 1: Audit Current State
```bash
# Check existing PSPs
kubectl get psp

# Check which service accounts use which PSP
kubectl get clusterrolebinding -o json | \
  jq '.items[] | select(.roleRef.name | startswith("psp-")) | {name: .metadata.name, subjects: .subjects}'
```

### Step 2: Map PSP to PSA Profiles
```bash
# For each namespace, determine required PSA level
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "Namespace: $ns"
  kubectl label --dry-run=server namespace $ns \
    pod-security.kubernetes.io/enforce=restricted 2>&1 | head -5
done
```

### Step 3: Apply PSA Labels (Audit First)
```bash
# Start with audit mode
kubectl label namespace production \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted
```

### Step 4: Review and Fix Violations
```bash
# Check audit logs for violations
kubectl get events --field-selector reason=FailedCreate -A
```

### Step 5: Enable Enforcement
```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted
```

## Monitoring

```bash
# Check PSA violations in events
kubectl get events --all-namespaces --field-selector reason=FailedCreate

# Check audit logs
kubectl logs -n kube-system kube-apiserver-* | grep "pod-security.kubernetes.io"

# List namespace PSA labels
kubectl get namespaces -L pod-security.kubernetes.io/enforce
```

## Best Practices

1. **Start with audit+warn** before enforce to assess impact
2. **Use dry-run** to test enforcement before applying
3. **Exempt system namespaces** (kube-system, monitoring) in cluster defaults
4. **Pin version** (enforce-version) for predictable behavior across upgrades
5. **Set cluster-wide baseline** as default, then restrict specific namespaces
6. **Combine with Gatekeeper** for additional custom policies beyond PSA
7. **Use restricted profile** for all production workloads
8. **Document exemptions** with clear justification
