---
name: performing-kubernetes-cis-benchmark-with-kube-bench
description: Audit Kubernetes cluster security posture against CIS benchmarks using kube-bench with automated checks for control plane, worker nodes, and RBAC.
domain: cybersecurity
subdomain: container-security
tags: [kube-bench, cis-benchmark, kubernetes, compliance, hardening, aquasecurity]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Kubernetes CIS Benchmark with kube-bench

## Overview

kube-bench is an open-source Go tool by Aqua Security that runs the CIS Kubernetes Benchmark checks. It verifies control plane, etcd, worker node, and policy configurations against security best practices, producing actionable pass/fail/warn reports.

## Prerequisites

- Kubernetes cluster (v1.24+)
- kubectl with cluster-admin access
- Node access for direct runs or privileged pod access

## Installation

```bash
# Binary installation
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.3/kube-bench_0.7.3_linux_amd64.tar.gz | tar xz
sudo mv kube-bench /usr/local/bin/

# Run as Kubernetes Job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# Run as a pod with host access
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-master.yaml
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-node.yaml
```

## Running Benchmarks

### Full Benchmark

```bash
# Run all checks (auto-detects node type)
kube-bench run

# Run with JSON output
kube-bench run --json > kube-bench-results.json

# Run with JUnit output for CI
kube-bench run --junit > kube-bench-results.xml
```

### Component-Specific Checks

```bash
# Control plane (master) checks
kube-bench run --targets master

# Worker node checks
kube-bench run --targets node

# etcd checks
kube-bench run --targets etcd

# Policies checks
kube-bench run --targets policies

# Control plane + etcd
kube-bench run --targets master,etcd
```

### Managed Kubernetes

```bash
# Amazon EKS
kube-bench run --benchmark eks-1.2.0

# Google GKE
kube-bench run --benchmark gke-1.4.0

# Azure AKS
kube-bench run --benchmark aks-1.0

# Red Hat OpenShift
kube-bench run --benchmark rh-1.0
```

### Filtering Results

```bash
# Show only failures
kube-bench run --targets master | grep "\[FAIL\]"

# Run specific check
kube-bench run --check 1.2.1

# Run check group
kube-bench run --group 1.2
```

## CIS Benchmark Sections

| Section | Component | Key Checks |
|---------|-----------|------------|
| 1.1 | Control Plane - API Server | Anonymous auth, RBAC, audit logging |
| 1.2 | Control Plane - API Server | Admission controllers, encryption |
| 1.3 | Control Plane - Controller Manager | Service account tokens, bind address |
| 1.4 | Control Plane - Scheduler | Profiling, bind address |
| 2.1 | etcd | Client cert auth, peer encryption |
| 3.1 | Control Plane - Authentication | OIDC, client certs |
| 4.1 | Worker - kubelet | Anonymous auth, authorization |
| 4.2 | Worker - kubelet | TLS, read-only port |
| 5.1 | Policies - RBAC | Cluster-admin usage, service accounts |
| 5.2 | Policies - Pod Security | Privileged, host namespaces |
| 5.3 | Policies - Network | Network policies per namespace |
| 5.7 | Policies - General | Secrets, security context |

## Output Example

```
[INFO] 1 Control Plane Security Configuration
[INFO] 1.1 Control Plane Node Configuration Files
[PASS] 1.1.1 Ensure that the API server pod specification file permissions are set to 600
[PASS] 1.1.2 Ensure that the API server pod specification file ownership is set to root:root
[FAIL] 1.1.3 Ensure that the controller manager pod specification file permissions are set to 600
[WARN] 1.1.4 Ensure that the scheduler pod specification file permissions are set to 600

== Summary ==
45 checks PASS
12 checks FAIL
8 checks WARN
0 checks INFO
```

## CI/CD Integration

### GitHub Actions

```yaml
name: CIS Benchmark
on:
  schedule:
    - cron: '0 6 * * 1'

jobs:
  kube-bench:
    runs-on: ubuntu-latest
    steps:
      - name: Configure kubectl
        uses: azure/setup-kubectl@v3

      - name: Run kube-bench
        run: |
          kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
          kubectl wait --for=condition=complete job/kube-bench --timeout=120s
          kubectl logs job/kube-bench > kube-bench-report.txt

      - name: Check for failures
        run: |
          FAILS=$(grep -c "\[FAIL\]" kube-bench-report.txt || true)
          echo "Failed checks: $FAILS"
          if [ "$FAILS" -gt 0 ]; then
            echo "::warning::$FAILS CIS benchmark checks failed"
          fi

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: kube-bench-report
          path: kube-bench-report.txt
```

## Remediation Examples

### 1.2.1 - Ensure --anonymous-auth is set to false
```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --anonymous-auth=false
```

### 4.2.1 - Ensure --anonymous-auth is set to false on kubelet
```yaml
# /var/lib/kubelet/config.yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
```

### 5.2.1 - Minimize wildcard RBAC
```bash
# Find roles with wildcard permissions
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[] == "*") | .metadata.name'
```

## Best Practices

1. **Run kube-bench before and after** cluster provisioning
2. **Schedule weekly scans** via CronJob for drift detection
3. **Export JSON** for SIEM/compliance reporting
4. **Fix FAIL items first**, then address WARN items
5. **Use benchmark profiles** matching your Kubernetes distribution
6. **Track score over time** to measure security posture improvement
7. **Combine with admission controllers** to prevent drift
