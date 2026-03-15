# Standards Reference - Kubernetes Network Policies

## CIS Kubernetes Benchmark v1.8 - Section 5.3
- 5.3.1: Ensure CNI supports Network Policies
- 5.3.2: Ensure default deny NetworkPolicy for all namespaces

## NSA/CISA Kubernetes Hardening Guide
- Implement network segmentation between namespaces
- Apply default-deny network policies
- Restrict pod-to-pod communication to required paths only
- Block access to cloud metadata endpoints

## MITRE ATT&CK Mitigations
| Technique | Mitigation via Network Policy |
|-----------|------------------------------|
| T1046 - Network Service Scanning | Limit reachable services |
| T1021 - Remote Services | Block lateral movement |
| T1552 - Credentials from IMDS | Block 169.254.169.254 |
