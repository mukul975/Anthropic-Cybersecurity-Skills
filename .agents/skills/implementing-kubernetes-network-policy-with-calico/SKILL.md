---
name: implementing-kubernetes-network-policy-with-calico
description: Implement Kubernetes network segmentation using Calico NetworkPolicy and GlobalNetworkPolicy for zero-trust pod-to-pod communication.
domain: cybersecurity
subdomain: container-security
tags: [calico, kubernetes, network-policy, network-segmentation, zero-trust, cni]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Kubernetes Network Policy with Calico

## Overview

Calico is an open-source CNI plugin that provides fine-grained network policy enforcement for Kubernetes clusters. It implements the full Kubernetes NetworkPolicy API and extends it with Calico-specific GlobalNetworkPolicy, supporting policy ordering, deny rules, and service-account-based selectors.

## Prerequisites

- Kubernetes cluster (v1.24+)
- Calico CNI installed (v3.26+)
- `kubectl` and `calicoctl` CLI tools
- Cluster admin RBAC permissions

## Installing Calico

### Operator-based Installation (Recommended)

```bash
# Install the Tigera operator
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/tigera-operator.yaml

# Install Calico custom resources
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml

# Verify installation
kubectl get pods -n calico-system
watch kubectl get pods -n calico-system

# Install calicoctl
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calicoctl.yaml
```

### Verify Calico is Running

```bash
# Check Calico pods
kubectl get pods -n calico-system

# Check Calico node status
kubectl exec -n calico-system calicoctl -- calicoctl node status

# Check IP pools
kubectl exec -n calico-system calicoctl -- calicoctl get ippool -o wide
```

## Kubernetes NetworkPolicy

### Default Deny All Traffic

```yaml
# deny-all-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress

---
# deny-all-egress.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
```

### Allow Specific Pod-to-Pod Communication

```yaml
# allow-frontend-to-backend.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
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
```

### Allow DNS Egress

```yaml
# allow-dns-egress.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

### Namespace Isolation

```yaml
# allow-same-namespace.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector: {}
```

## Calico-Specific Policies

### GlobalNetworkPolicy (Cluster-Wide)

```yaml
# global-deny-external.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-external-ingress
spec:
  order: 100
  selector: "projectcalico.org/namespace != 'ingress-nginx'"
  types:
    - Ingress
  ingress:
    - action: Deny
      source:
        nets:
          - 0.0.0.0/0
      destination: {}
```

### Calico NetworkPolicy with Deny Rules

```yaml
# calico-deny-policy.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: deny-database-from-frontend
  namespace: production
spec:
  order: 10
  selector: app == 'database'
  types:
    - Ingress
  ingress:
    - action: Deny
      source:
        selector: app == 'frontend'
    - action: Allow
      source:
        selector: app == 'backend'
      destination:
        ports:
          - 5432
```

### Service Account Based Policy

```yaml
# sa-based-policy.yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-by-service-account
  namespace: production
spec:
  selector: app == 'api'
  ingress:
    - action: Allow
      source:
        serviceAccounts:
          names:
            - frontend-sa
            - monitoring-sa
  egress:
    - action: Allow
      destination:
        serviceAccounts:
          names:
            - database-sa
```

### Host Endpoint Protection

```yaml
# host-endpoint-policy.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-host-ssh
spec:
  order: 10
  selector: "has(kubernetes.io/hostname)"
  applyOnForward: false
  types:
    - Ingress
  ingress:
    - action: Allow
      protocol: TCP
      source:
        nets:
          - 10.0.0.0/8
      destination:
        ports:
          - 22
    - action: Deny
      protocol: TCP
      destination:
        ports:
          - 22
```

## Calico Policy Tiers

```yaml
# security-tier.yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security
spec:
  order: 100

---
# platform-tier.yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: platform
spec:
  order: 200
```

## Monitoring and Troubleshooting

```bash
# List all network policies
kubectl get networkpolicy --all-namespaces

# List Calico-specific policies
kubectl exec -n calico-system calicoctl -- calicoctl get networkpolicy --all-namespaces -o wide
kubectl exec -n calico-system calicoctl -- calicoctl get globalnetworkpolicy -o wide

# Check policy evaluation for a specific endpoint
kubectl exec -n calico-system calicoctl -- calicoctl get workloadendpoint -n production -o yaml

# View Calico logs
kubectl logs -n calico-system -l k8s-app=calico-node --tail=100

# Test connectivity
kubectl exec -n production frontend-pod -- wget -qO- --timeout=2 http://backend-svc:8080/health
```

## Best Practices

1. **Start with default deny** - Apply deny-all policies to every namespace, then allow specific traffic
2. **Use labels consistently** - Define a labeling standard for app, tier, environment
3. **Order policies** - Use Calico policy ordering (`order` field) to control evaluation precedence
4. **Allow DNS first** - Always create DNS egress rules before applying egress deny policies
5. **Use GlobalNetworkPolicy** for cluster-wide security baselines
6. **Test policies in staging** - Validate network connectivity after applying policies
7. **Monitor denied traffic** - Enable Calico flow logs for visibility into blocked connections
8. **Use tiers** - Organize policies into security, platform, and application tiers
