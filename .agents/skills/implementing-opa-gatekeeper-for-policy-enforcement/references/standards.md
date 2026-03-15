# Standards and References - OPA Gatekeeper Policy Enforcement

## Industry Standards

### NIST SP 800-190
- Section 4.1: Image vulnerabilities - Enforce image registry restrictions
- Section 4.2: Image configuration defects - Enforce security context requirements
- Section 5.2: Registry security - Restrict allowed image sources

### CIS Kubernetes Benchmark v1.8
- 5.2.1: Ensure Pods cannot run with privileged containers
- 5.2.2: Ensure Pods cannot share host PID namespace
- 5.2.3: Ensure Pods cannot share host IPC namespace
- 5.2.4: Ensure Pods cannot share host network namespace
- 5.2.5: Ensure containers do not allow privilege escalation
- 5.2.6: Ensure containers do not run as root
- 5.2.7: Ensure Pods use seccomp profile
- 5.2.8: Ensure Pods restrict volume types
- 5.2.9: Ensure Pods restrict host path volumes
- 5.7.1: Create administrative boundaries using namespaces
- 5.7.2: Ensure seccomp profile is set
- 5.7.3: Apply security context to pods

### NSA/CISA Kubernetes Hardening Guide
- Section 2: Pod Security - Admission control enforcement
- Recommends admission controllers to enforce security baselines

## Gatekeeper Policy Library

| Template | Purpose | CIS Mapping |
|----------|---------|-------------|
| K8sPSPPrivilegedContainer | Block privileged containers | 5.2.1 |
| K8sPSPHostNamespace | Block host PID/IPC/Network | 5.2.2-5.2.4 |
| K8sPSPAllowPrivilegeEscalation | Prevent privilege escalation | 5.2.5 |
| K8sPSPRunAsNonRoot | Require non-root | 5.2.6 |
| K8sPSPSeccomp | Require seccomp profiles | 5.2.7 |
| K8sPSPVolumeTypes | Restrict volume types | 5.2.8 |
| K8sPSPHostFilesystem | Restrict hostPath | 5.2.9 |
| K8sAllowedRepos | Restrict image registries | 5.1.1 |
| K8sRequiredLabels | Enforce labeling standards | Organizational |
| K8sContainerLimits | Enforce resource limits | Operational |

## Compliance Mappings

### PCI DSS v4.0
- Req 2.2: Secure system components per configuration standards
- Req 6.3.2: Develop software securely with automated controls

### SOC 2
- CC6.1: Logical access to system components is restricted
- CC8.1: Changes to infrastructure are controlled
