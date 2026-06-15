---
name: implementing-ebpf-security-monitoring
description: 'Implements eBPF-based security monitoring using Cilium Tetragon for
  real-time process execution tracking, network connection observability, file access
  auditing, and runtime enforcement. Covers TracingPolicy CRD authoring with kprobe/tracepoint
  hooks, in-kernel filtering via matchArgs/matchBinaries selectors, JSON event export,
  and integration with SIEM pipelines. Use when building kernel-level runtime security
  observability for Linux hosts or Kubernetes clusters.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- ebpf
- tetragon
- cilium
- runtime-security
- observability
- kernel-security
- kubernetes-security
version: '1.0'
author: mukul975
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1078
- T1190
- T1059
- T1685.002
- T1685.005
---

# Implementing eBPF Security Monitoring

## When to Use

- When deploying kernel-level runtime security monitoring on Linux hosts or Kubernetes clusters
- When you need sub-millisecond visibility into process execution, network connections, and file access
- When traditional userspace monitoring tools introduce unacceptable performance overhead
- When building detection pipelines that require in-kernel filtering before events reach userspace
- When enforcing runtime security policies (kill process, send signal) at the kernel level

## Prerequisites

- Linux kernel 5.3+ with BTF (BPF Type Format) support enabled
- Kubernetes 1.24+ cluster (for Kubernetes deployment) or standalone Linux host
- Helm 3.x installed (for Kubernetes deployment)
- `kubectl` configured with cluster access
- `tetra` CLI installed for local event streaming
- Python 3.8+ with `requests`, `kubernetes`, `pyyaml` dependencies
- Root or CAP_BPF/CAP_SYS_ADMIN capabilities for eBPF program loading

## Instructions

### 1. Install Tetragon on Kubernetes

Deploy Tetragon via Helm to get default process lifecycle observability:

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system \
  --set tetragon.enableProcessCred=true \
  --set tetragon.enableProcessNs=true
```

Verify the installation:

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | head -20
```

### 2. Install Tetragon on Standalone Linux

For non-Kubernetes Linux hosts, install from the tarball release:

```bash
curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz
tar xzf tetragon-linux-amd64.tar.gz
sudo cp tetragon /usr/local/bin/
sudo cp tetra /usr/local/bin/

# Start tetragon daemon
sudo tetragon --btf /sys/kernel/btf/vmlinux &

# Stream events
tetra getevents -o compact
```

### 3. Monitor Process Execution (Default)

Tetragon generates `process_exec` and `process_exit` events by default without any TracingPolicy:

```bash
# Stream process events in compact format
tetra getevents -o compact

# Stream in JSON for SIEM ingestion
tetra getevents -o json | jq '.process_exec // .process_exit'
```

Example `process_exec` JSON event:

```json
{
  "process_exec": {
    "process": {
      "binary": "/usr/bin/curl",
      "arguments": "https://malicious.example.com/payload",
      "cwd": "/tmp",
      "uid": 1000,
      "pod": {
        "namespace": "default",
        "name": "webapp-7b4d9f8c6-x2k9p"
      },
      "parent": {
        "binary": "/bin/bash",
        "pid": 1234
      }
    }
  }
}
```

### 4. Author TracingPolicy for File Access Monitoring

Create a TracingPolicy CRD to monitor access to sensitive files via the `sys_openat` kprobe:

```yaml
# file-access-monitor.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-sensitive-file-access
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "file"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
                - "/etc/sudoers"
                - "/root/.ssh/"
                - "/etc/kubernetes/pki/"
          matchActions:
            - action: Post
```

Apply and observe:

```bash
kubectl apply -f file-access-monitor.yaml
tetra getevents -o compact --process-filter "event_set:PROCESS_KPROBE"
```

### 5. Author TracingPolicy for Network Connection Monitoring

Monitor outbound TCP connections using the `tcp_connect` kprobe:

```yaml
# network-monitor.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: monitor-tcp-connections
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchActions:
            - action: Post
```

### 6. Author TracingPolicy for Privilege Escalation Detection

Detect setuid/setgid calls that may indicate privilege escalation:

```yaml
# privilege-escalation-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-privilege-escalation
spec:
  kprobes:
    - call: "__sys_setuid"
      syscall: false
      args:
        - index: 0
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Equal"
              values:
                - "0"
          matchActions:
            - action: Post
    - call: "commit_creds"
      syscall: false
      args:
        - index: 0
          type: "cred"
      selectors:
        - matchActions:
            - action: Post
```

### 7. Runtime Enforcement with Sigkill Action

Block unauthorized binary execution by killing the process in-kernel:

```yaml
# enforce-binary-allowlist.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: enforce-no-crypto-miners
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"
              values:
                - "xmrig"
                - "minerd"
                - "cpuminer"
                - "cryptonight"
          matchActions:
            - action: Sigkill
```

### 8. Export Events to SIEM

Configure Tetragon to export JSON events to a file sink for Fluentd/Filebeat/Vector ingestion:

```bash
# Helm values for file export
helm upgrade tetragon cilium/tetragon -n kube-system \
  --set tetragon.exportFilename=/var/log/tetragon/tetragon.log \
  --set tetragon.exportFileMaxSizeMB=100 \
  --set tetragon.exportFileMaxBackups=5
```

Then configure your log shipper (e.g., Filebeat) to tail `/var/log/tetragon/tetragon.log` and send to your SIEM.

### 9. Kubernetes-Aware Namespace Filtering

Use `TracingPolicyNamespaced` to scope monitoring to specific namespaces:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: monitor-production-file-access
  namespace: production
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "file"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/passwd"
```

## Examples

### Detect Reverse Shell Connections

```yaml
# reverse-shell-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-reverse-shells
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                - "/bin/bash"
                - "/bin/sh"
                - "/usr/bin/python3"
                - "/usr/bin/perl"
                - "/usr/bin/nc"
                - "/usr/bin/ncat"
          matchActions:
            - action: Post
```

### Monitor Container Escape Attempts

```yaml
# container-escape-detect.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: detect-container-escape
spec:
  kprobes:
    - call: "sys_openat"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Prefix"
              values:
                - "/proc/1/root"
                - "/proc/1/ns"
                - "/sys/kernel/security"
                - "/proc/sysrq-trigger"
          matchActions:
            - action: Post
    - call: "sys_mount"
      syscall: true
      args:
        - index: 0
          type: "string"
        - index: 1
          type: "string"
        - index: 2
          type: "string"
      selectors:
        - matchActions:
            - action: Post
```

### Full Event Pipeline: Tetragon to Elasticsearch

```bash
# Use tetra CLI to pipe events through jq into Elasticsearch
tetra getevents -o json | jq -c 'select(.process_kprobe != null)' | \
  while IFS= read -r line; do
    curl -s -X POST "http://elasticsearch:9200/tetragon-events/_doc" \
      -H "Content-Type: application/json" \
      -d "$line"
  done
```
