# API Reference: Implementing Kubernetes Network Policy with Calico

## Kubernetes NetworkPolicy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

## Calico GlobalNetworkPolicy

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-external
spec:
  order: 100
  selector: app == "backend"
  types: [Ingress]
  ingress:
    - action: Deny
      source:
        nets: ["0.0.0.0/0"]
```

## calicoctl CLI

```bash
# Apply policy
calicoctl apply -f policy.yaml
# Get policies
calicoctl get globalnetworkpolicy -o yaml
# Get host endpoints
calicoctl get hostendpoint
```

## Policy Types

| Type | Scope | Ordering |
|------|-------|----------|
| NetworkPolicy | Namespace | Additive (OR) |
| GlobalNetworkPolicy | Cluster-wide | Ordered by `order` field |

## Common Policy Patterns

| Pattern | Description |
|---------|-------------|
| Default deny | Empty podSelector, no rules |
| Allow DNS | Egress to kube-system UDP/TCP 53 |
| Allow ingress from namespace | namespaceSelector match |
| Allow to external CIDR | ipBlock in egress |

### References

- Calico Docs: https://docs.tigera.io/calico/
- K8s NetworkPolicy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Calico Policy Tutorial: https://docs.tigera.io/calico/latest/network-policy/
