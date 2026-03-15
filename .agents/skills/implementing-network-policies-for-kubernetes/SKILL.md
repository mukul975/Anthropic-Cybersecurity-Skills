---
name: implementing-network-policies-for-kubernetes
description: Kubernetes NetworkPolicies provide pod-level network segmentation by defining ingress and egress rules that control traffic flow between pods, namespaces, and external endpoints. Combined with CNI plu
domain: cybersecurity
subdomain: container-security
tags: [containers, kubernetes, security, network-policies, microsegmentation]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Network Policies for Kubernetes

## Overview

Kubernetes NetworkPolicies provide pod-level network segmentation by defining ingress and egress rules that control traffic flow between pods, namespaces, and external endpoints. Combined with CNI plugins like Calico or Cilium, network policies enforce zero-trust microsegmentation to prevent lateral movement within the cluster.

## Prerequisites

- Kubernetes cluster with NetworkPolicy-supporting CNI (Calico, Cilium, Antrea)
- kubectl configured with admin access
- Understanding of pod labels and selectors

## Implementation Steps

### Step 1: Default Deny All Traffic

```yaml
# default-deny-all.yaml - Apply to every namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
    - Ingress
    - Egress
```

### Step 2: Allow DNS Egress (Required for Service Discovery)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Step 3: Application-Specific Policies

```yaml
# Allow frontend to reach backend only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-allow-frontend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
---
# Allow backend to reach database only
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-allow-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: backend
      ports:
        - protocol: TCP
          port: 5432
```

### Step 4: Cross-Namespace Policies

```yaml
# Allow monitoring namespace to scrape metrics
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-scrape
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              purpose: monitoring
      ports:
        - protocol: TCP
          port: 9090  # Prometheus metrics port
```

### Step 5: Egress Restrictions

```yaml
# Restrict egress to specific external services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    - to:  # Allow external API
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - protocol: TCP
          port: 443
    - to:  # DNS
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
```

### Step 6: Block Cloud Metadata Access

```yaml
# Prevent SSRF to cloud metadata service
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 169.254.169.254/32  # AWS/GCP metadata
              - 100.100.100.200/32  # Azure metadata
```

## Validation Commands

```bash
# Verify policies are applied
kubectl get networkpolicies -n production

# Test connectivity (should be blocked)
kubectl run test-pod --image=busybox --restart=Never -n production -- wget -qO- --timeout=2 http://database-service:5432
# Expected: timeout (blocked by policy)

# Test allowed traffic
kubectl run frontend-test --image=busybox --labels=app=frontend --restart=Never -n production -- wget -qO- --timeout=2 http://backend-service:8080
# Expected: connection succeeds
```

## References

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Calico Network Policies](https://docs.tigera.io/calico/latest/network-policy/)
- [Cilium Network Policies](https://docs.cilium.io/en/stable/security/policy/)
- [Network Policy Editor](https://editor.networkpolicy.io/)
