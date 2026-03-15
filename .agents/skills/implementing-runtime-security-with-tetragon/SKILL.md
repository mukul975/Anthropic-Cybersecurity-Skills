---
name: implementing-runtime-security-with-tetragon
description: Implement eBPF-based runtime security observability and enforcement in Kubernetes clusters using Cilium Tetragon for kernel-level threat detection and policy enforcement.
domain: cybersecurity
subdomain: container-security
tags: [tetragon, ebpf, runtime-security, kubernetes, cilium, container-security, observability, kernel-security, cncf]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Runtime Security with Tetragon

## Overview

Tetragon is a CNCF project under Cilium that provides flexible Kubernetes-aware security observability and runtime enforcement using eBPF. By operating at the Linux kernel level, Tetragon can monitor and enforce policies on process execution, file access, network connections, and system calls with less than 1% performance overhead -- far more efficient than traditional user-space security agents.

## Prerequisites

- Kubernetes cluster v1.24+ with Helm 3.x installed
- Linux kernel 5.4+ (5.10+ recommended for full eBPF feature support)
- kubectl access with cluster-admin privileges
- Familiarity with eBPF concepts and Kubernetes security primitives

## Core Concepts

### eBPF-Based Security

Tetragon attaches eBPF programs directly to kernel functions, enabling:

- **Process lifecycle tracking**: Monitor every process creation, execution, and termination across all pods
- **File integrity monitoring**: Detect unauthorized reads/writes to sensitive files
- **Network observability**: Track all TCP/UDP connections with full pod context
- **System call filtering**: Enforce policies on dangerous syscalls like ptrace, mount, or unshare

### TracingPolicy Custom Resources

Tetragon uses `TracingPolicy` CRDs to define what kernel events to observe and what actions to take:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-privilege-escalation
spec:
  kprobes:
    - call: "security_bprm_check"
      syscall: false
      args:
        - index: 0
          type: "linux_binprm"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                - "/bin/su"
                - "/usr/bin/sudo"
                - "/usr/bin/passwd"
          matchNamespaces:
            - namespace: Pid
              operator: NotIn
              values:
                - "host_ns"
          matchActions:
            - action: Post
```

### Enforcement Actions

Tetragon can take three types of actions directly in the kernel:

1. **Sigkill**: Immediately terminate the offending process
2. **Signal**: Send a configurable signal to the process
3. **Override**: Override the return value of a kernel function to deny an operation

## Installation and Configuration

### Step 1: Install Tetragon with Helm

```bash
helm repo add cilium https://helm.cilium.io
helm repo update

helm install tetragon cilium/tetragon \
  --namespace kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true \
  --set tetragon.grpc.address="localhost:54321"
```

### Step 2: Install the Tetragon CLI

```bash
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L --remote-name-all \
  https://github.com/cilium/tetragon/releases/latest/download/tetra-${GOOS}-${GOARCH}.tar.gz
tar -xzvf tetra-${GOOS}-${GOARCH}.tar.gz
sudo install tetra /usr/local/bin/
```

### Step 3: Verify Installation

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
tetra status
```

## Practical Implementation

### Detecting Container Escape Attempts

Create a TracingPolicy to detect processes attempting to escape container namespaces:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-container-escape
spec:
  kprobes:
    - call: "__x64_sys_setns"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "int"
      selectors:
        - matchNamespaces:
            - namespace: Pid
              operator: NotIn
              values:
                - "host_ns"
          matchActions:
            - action: Sigkill
```

### Monitoring Sensitive File Access

Detect reads of sensitive credentials:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-sensitive-files
spec:
  kprobes:
    - call: "security_file_open"
      syscall: false
      args:
        - index: 0
          type: "file"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/kubernetes/pki"
                - "/var/run/secrets/kubernetes.io"
          matchActions:
            - action: Post
```

### Blocking Crypto-Miner Execution

Prevent known crypto-mining binaries from executing:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-cryptominers
spec:
  kprobes:
    - call: "security_bprm_check"
      syscall: false
      args:
        - index: 0
          type: "linux_binprm"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                - "/usr/bin/xmrig"
                - "/tmp/xmrig"
                - "/usr/bin/minerd"
          matchActions:
            - action: Sigkill
```

### Observing Events with Tetra CLI

Stream runtime events in real-time:

```bash
# Watch all process execution events
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --process-only

# Filter events for a specific namespace
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o compact --namespace production

# Export events in JSON for SIEM integration
kubectl exec -n kube-system ds/tetragon -c tetragon -- \
  tetra getevents -o json | tee /var/log/tetragon-events.json
```

## Integration with SIEM and Alerting

### Export to Elasticsearch

```yaml
# tetragon-helm-values.yaml
export:
  stdout:
    enabledCommand: true
    enabledArgs: true
  filenames:
    - /var/log/tetragon/tetragon.log
  elasticsearch:
    enabled: true
    url: "https://elasticsearch.monitoring:9200"
    index: "tetragon-events"
```

### Prometheus Metrics

Tetragon exposes metrics at `:2112/metrics`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: tetragon-metrics
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: tetragon
  endpoints:
    - port: metrics
      interval: 15s
```

## Key Metrics and Alerts

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `tetragon_events_total` | Total security events observed | Spike > 3x baseline |
| `tetragon_policy_events_total` | Events matching TracingPolicies | Any Sigkill action |
| `tetragon_process_exec_total` | Process executions tracked | Anomalous new binaries |
| `tetragon_missed_events_total` | Dropped events due to buffer overflow | > 0 sustained |

## References

- [Tetragon Official Documentation](https://tetragon.io/docs/)
- [Cilium Tetragon GitHub Repository](https://github.com/cilium/tetragon)
- [CNCF Tetragon Project Page](https://www.cncf.io/projects/tetragon/)
- [eBPF Security Observability with Tetragon - CoreWeave](https://docs.coreweave.com/security/tutorials/ebpf-observability)
- [Kubernetes Security: eBPF & Tetragon for Runtime Monitoring](https://medium.com/@noah_h/kubernetes-security-ebpf-tetragon-for-runtime-monitoring-policy-enforcement-819b6ed97953)
