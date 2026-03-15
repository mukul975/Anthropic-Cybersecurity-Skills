# API Reference: Implementing Network Policies for Kubernetes

## Default Deny-All Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

## Allow Specific Ingress

```yaml
spec:
  podSelector:
    matchLabels: { app: backend }
  ingress:
    - from:
        - podSelector: { matchLabels: { app: frontend } }
      ports:
        - port: 8080
```

## kubectl Commands

```bash
# List all network policies
kubectl get networkpolicy --all-namespaces
# Describe policy
kubectl describe networkpolicy default-deny -n production
# Apply policy
kubectl apply -f netpol.yaml
```

## Policy Types

| Type | Behavior when present |
|------|-----------------------|
| Ingress | Restrict inbound traffic |
| Egress | Restrict outbound traffic |
| Both empty | Default deny all |

## Common Patterns

| Pattern | Description |
|---------|-------------|
| Default deny | Empty podSelector, no rules |
| Allow DNS | Egress to kube-system:53 |
| Allow same namespace | namespaceSelector match |
| Allow from ingress controller | Label-based ingress |

### References

- K8s NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Network Policy Editor: https://editor.networkpolicy.io/
- CNI Comparison: https://kubernetes.io/docs/concepts/cluster-administration/networking/
