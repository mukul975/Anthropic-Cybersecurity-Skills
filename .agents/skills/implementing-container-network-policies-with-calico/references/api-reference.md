# API Reference: Implementing Container Network Policies with Calico

## calicoctl Commands

```bash
# List network policies across all namespaces
calicoctl get networkpolicy --all-namespaces -o json

# List global network policies
calicoctl get globalnetworkpolicy -o json

# Check Calico node status
calicoctl node status

# Apply a Calico network policy
calicoctl apply -f policy.yaml

# Get workload endpoints
calicoctl get workloadendpoint -o wide

# Check IP pool configuration
calicoctl get ippool -o json
```

## Kubernetes NetworkPolicy vs Calico

| Feature | K8s NetworkPolicy | Calico NetworkPolicy | Calico GlobalNetworkPolicy |
|---------|-------------------|---------------------|-----------------------------|
| Scope | Namespace | Namespace | Cluster-wide |
| Selector | Pod labels | Pod + service account | All workloads + host endpoints |
| Rule types | Ingress, Egress | Ingress, Egress | Ingress, Egress |
| DNS policy | No | Yes | Yes |
| Order/Priority | No | Yes (order field) | Yes (order field) |
| CIDR ranges | Yes | Yes | Yes |

## Default-Deny Policy Template

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
```

## Python kubernetes Client

```python
from kubernetes import client, config

config.load_kube_config()
net_v1 = client.NetworkingV1Api()
policies = net_v1.list_network_policy_for_all_namespaces()
for p in policies.items:
    print(p.metadata.name, p.metadata.namespace)
```

Install: `pip install kubernetes`

## References

- Calico Network Policy: https://docs.tigera.io/calico/latest/network-policy/get-started/calico-policy/calico-network-policy
- calicoctl Reference: https://docs.tigera.io/calico-enterprise/latest/reference/clis/calicoctl/overview
- K8s Network Policy: https://kubernetes.io/docs/concepts/services-networking/network-policies/
