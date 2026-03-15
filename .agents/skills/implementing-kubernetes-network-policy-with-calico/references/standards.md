# Standards and References - Kubernetes Network Policy with Calico

## Industry Standards

### NIST SP 800-190: Application Container Security Guide
- Section 4.4: Container Networking - Isolate container network traffic using network policies
- Section 5.3: Network Security - Implement micro-segmentation between containers
- Recommends default-deny policies with explicit allowlisting

### CIS Kubernetes Benchmark v1.8
- 5.3.1: Ensure that the CNI in use supports Network Policies
- 5.3.2: Ensure that all Namespaces have Network Policies defined
- 5.3.3: Ensure that the default namespace does not contain any pods

### NIST SP 800-53 Rev 5
- SC-7: Boundary Protection - Implement network segmentation controls
- AC-4: Information Flow Enforcement - Control network traffic between pods
- SC-7(5): Deny by Default / Allow by Exception

### NSA/CISA Kubernetes Hardening Guide v1.2
- Section 3: Network Separation and Hardening
  - Use network policies to isolate workloads
  - Implement default deny ingress and egress policies
  - Limit pod-to-pod communication to minimum required

## Calico Documentation References

| Resource | URL |
|----------|-----|
| Calico NetworkPolicy | https://docs.tigera.io/calico/latest/network-policy/get-started/calico-policy/calico-network-policy |
| Kubernetes Policy Tutorial | https://docs.tigera.io/calico/latest/network-policy/get-started/kubernetes-policy/kubernetes-policy-basic |
| GlobalNetworkPolicy | https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy |
| Policy Tiers | https://docs.tigera.io/calico-enterprise/latest/network-policy/policy-tiers/tiered-policy |
| Calico eBPF Dataplane | https://docs.tigera.io/calico/latest/operations/ebpf/enabling-ebpf |

## Zero Trust Network Model

### Principles Applied
1. **Never trust, always verify** - Default deny all traffic between pods
2. **Least privilege access** - Only allow specific required communication paths
3. **Micro-segmentation** - Isolate workloads at pod-to-pod granularity
4. **Identity-based policies** - Use service accounts and labels for policy selection
5. **Continuous monitoring** - Log and alert on denied traffic patterns

## Compliance Mappings

### PCI DSS v4.0
- Requirement 1.2.1: Restrict inbound and outbound traffic to that which is necessary
- Requirement 1.3.1: Inbound traffic is restricted to that which is necessary
- Requirement 1.3.2: Outbound traffic is restricted to that which is necessary

### SOC 2 Type II
- CC6.1: Logical access security - Network isolation between components
- CC6.6: Network boundaries - Restrict access at network boundaries

### HIPAA
- 164.312(e)(1): Transmission Security - Protect data in transit between services
