---
name: detecting-privilege-escalation-in-kubernetes-pods
description: Detect and prevent privilege escalation in Kubernetes pods by monitoring security contexts, capabilities, and syscall patterns with Falco and OPA policies.
domain: cybersecurity
subdomain: container-security
tags: [kubernetes, privilege-escalation, security-context, capabilities, detection, pod-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Privilege Escalation in Kubernetes Pods

## Overview

Privilege escalation in Kubernetes occurs when a pod or container gains elevated permissions beyond its intended scope. This includes running as root, using privileged mode, mounting host filesystems, enabling dangerous Linux capabilities, or exploiting kernel vulnerabilities. Detection combines admission control (prevention), runtime monitoring (detection), and audit logging (investigation).

## Prerequisites

- Kubernetes cluster v1.25+ (Pod Security Admission support)
- kubectl with cluster-admin access
- Falco or similar runtime security tool
- OPA Gatekeeper or Kyverno for admission policies

## Privilege Escalation Vectors in Kubernetes

| Vector | Risk | Detection Method |
|--------|------|-----------------|
| privileged: true | Full host access | Admission control + audit |
| hostPID: true | Access host processes | Admission control |
| hostNetwork: true | Access host network stack | Admission control |
| hostPath volumes | Read/write host filesystem | Admission control |
| SYS_ADMIN capability | Near-privileged access | Admission + runtime |
| allowPrivilegeEscalation: true | setuid/setgid exploitation | Admission control |
| runAsUser: 0 | Container root | Admission control |
| automountServiceAccountToken | Token theft for API access | Admission control |
| Writable /proc or /sys | Kernel parameter manipulation | Runtime monitoring |

## Detection with Admission Control

### Pod Security Admission (Built-in)

```yaml
# Enforce restricted policy on namespace
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### OPA Gatekeeper Policies

```yaml
# Block dangerous capabilities
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdangerouspriv
spec:
  crd:
    spec:
      names:
        kind: K8sDangerousPriv
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdangerouspriv

        dangerous_caps := {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "NET_ADMIN", "NET_RAW"}

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          cap := container.securityContext.capabilities.add[_]
          dangerous_caps[cap]
          msg := sprintf("Container %v adds dangerous capability: %v", [container.name, cap])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.privileged == true
          msg := sprintf("Container %v runs in privileged mode", [container.name])
        }

        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          container.securityContext.allowPrivilegeEscalation == true
          msg := sprintf("Container %v allows privilege escalation", [container.name])
        }

        violation[{"msg": msg}] {
          input.review.object.spec.hostPID == true
          msg := "Pod uses host PID namespace"
        }

        violation[{"msg": msg}] {
          input.review.object.spec.hostNetwork == true
          msg := "Pod uses host network"
        }
```

## Runtime Detection with Falco

```yaml
# /etc/falco/rules.d/privesc-detection.yaml
- rule: Setuid Binary Execution in Container
  desc: Detect execution of setuid/setgid binaries in a container
  condition: >
    spawned_process and container and
    (proc.name in (su, sudo, newgrp, chsh, passwd) or
     proc.is_exe_upper_layer=true)
  output: >
    Setuid/setgid binary executed in container
    (user=%user.name container=%container.name image=%container.image.repository
     command=%proc.cmdline parent=%proc.pname)
  priority: WARNING
  tags: [container, privilege-escalation, T1548]

- rule: Capability Gained in Container
  desc: Detect when a process gains elevated capabilities
  condition: >
    evt.type = capset and container and
    evt.arg.cap != ""
  output: >
    Process gained capabilities in container
    (container=%container.name image=%container.image.repository
     capabilities=%evt.arg.cap command=%proc.cmdline)
  priority: WARNING
  tags: [container, privilege-escalation, T1548.001]

- rule: Container with Dangerous Capabilities Started
  desc: Detect container launched with dangerous capabilities
  condition: >
    container_started and container and
    (container.image.repository != "registry.k8s.io/pause") and
    (container.cap_effective contains SYS_ADMIN or
     container.cap_effective contains SYS_PTRACE or
     container.cap_effective contains SYS_MODULE)
  output: >
    Container with dangerous capabilities
    (container=%container.name image=%container.image.repository
     caps=%container.cap_effective)
  priority: CRITICAL
  tags: [container, privilege-escalation, T1068]

- rule: Write to /etc/passwd in Container
  desc: Detect writes to /etc/passwd inside container
  condition: >
    open_write and container and fd.name = /etc/passwd
  output: >
    Write to /etc/passwd in container
    (container=%container.name image=%container.image.repository
     command=%proc.cmdline user=%user.name)
  priority: CRITICAL
  tags: [container, privilege-escalation, T1136]
```

## Kubernetes Audit Log Detection

```yaml
# audit-policy.yaml - Capture privilege escalation events
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log pod creation with security context details
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["pods"]
    verbs: ["create", "update", "patch"]

  # Log privilege escalation attempts
  - level: RequestResponse
    resources:
      - group: "rbac.authorization.k8s.io"
        resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
    verbs: ["create", "update", "patch", "bind", "escalate"]

  # Log service account token requests
  - level: Metadata
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]
    verbs: ["create"]
```

### Query Audit Logs for Privilege Escalation

```bash
# Find pods created with privileged security context
kubectl logs -n kube-system kube-apiserver-* | \
  jq 'select(.verb == "create" and .objectRef.resource == "pods") |
  select(.requestObject.spec.containers[].securityContext.privileged == true)'

# Find RBAC escalation attempts
kubectl logs -n kube-system kube-apiserver-* | \
  jq 'select(.objectRef.resource == "clusterrolebindings" and .verb == "create")'
```

## Investigation Playbook

```bash
# Check pod security context
kubectl get pod <pod-name> -n <ns> -o jsonpath='{.spec.containers[*].securityContext}'

# Check effective capabilities
kubectl exec <pod-name> -n <ns> -- cat /proc/1/status | grep -i cap

# List pods running as root
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsUser == 0 or .spec.containers[].securityContext.privileged == true) | {name: .metadata.name, ns: .metadata.namespace}'

# Check for hostPath volumes
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {name: .metadata.name, ns: .metadata.namespace, paths: [.spec.volumes[].hostPath.path]}'
```

## Best Practices

1. **Enable Pod Security Admission** at `restricted` level for production namespaces
2. **Drop ALL capabilities** and add back only what is needed
3. **Set allowPrivilegeEscalation: false** on all containers
4. **Run as non-root** (runAsNonRoot: true, runAsUser > 0)
5. **Disable automountServiceAccountToken** unless API access is needed
6. **Monitor with Falco** for runtime privilege escalation attempts
7. **Audit RBAC changes** with Kubernetes audit logging
8. **Use seccomp profiles** to restrict syscalls
