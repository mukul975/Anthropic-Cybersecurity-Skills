# Standards and References - Kubernetes CIS Benchmark with kube-bench

## CIS Kubernetes Benchmark Versions

| Benchmark Version | Kubernetes Versions | Released |
|-------------------|-------------------|----------|
| CIS 1.8 | 1.27+ | 2023 |
| CIS 1.7 | 1.25-1.26 | 2022 |
| CIS 1.6 | 1.20-1.24 | 2021 |
| EKS 1.2.0 | EKS 1.23+ | 2023 |
| GKE 1.4.0 | GKE 1.25+ | 2023 |
| AKS 1.0 | AKS 1.24+ | 2023 |

## NIST SP 800-53 Rev 5 Mappings

| CIS Check | NIST Control | Description |
|-----------|-------------|-------------|
| 1.2.1 Anonymous auth | AC-14 | Permitted Actions without Authentication |
| 1.2.6 RBAC | AC-3 | Access Enforcement |
| 1.2.22 Audit logging | AU-2, AU-3 | Audit Events, Content of Audit Records |
| 2.1 etcd encryption | SC-28 | Protection of Information at Rest |
| 4.2.1 kubelet auth | IA-2 | Identification and Authentication |
| 5.1 RBAC policies | AC-6 | Least Privilege |
| 5.2 Pod security | CM-7 | Least Functionality |
| 5.3 Network policies | SC-7 | Boundary Protection |

## NSA/CISA Kubernetes Hardening Guide v1.2
- Section 1: Kubernetes Pod Security
- Section 2: Network Separation and Hardening
- Section 3: Authentication and Authorization
- Section 4: Audit Logging and Threat Detection

## Compliance Frameworks

### PCI DSS v4.0
- Req 2.2: Develop configuration standards for all system components
- Req 6.3.2: Develop software securely

### SOC 2
- CC6.1: Logical access security for system components
- CC8.1: Change management controls
