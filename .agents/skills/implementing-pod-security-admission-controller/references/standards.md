# Standards - Pod Security Admission Controller

## Kubernetes Pod Security Standards

| Profile | Controls Enforced |
|---------|------------------|
| Baseline | No privileged, no hostPID/IPC/Network, no hostPorts, restricted volumes, no procMount, restricted seccomp, restricted capabilities |
| Restricted | All Baseline + non-root, drop ALL caps, seccomp required, restricted volume types, no privilege escalation |

## CIS Kubernetes Benchmark v1.8
- 5.2.1: Ensure privileged containers are not used
- 5.2.2-5.2.4: Ensure host namespace sharing is disabled
- 5.2.5: Ensure privilege escalation is not allowed
- 5.2.6: Ensure root containers are not admitted
- 5.2.7: Ensure seccomp profile is set
- 5.7.3: Apply security context to pods

## NIST SP 800-190
- Section 4.3: Container runtime security
- Section 5.4: Admission control enforcement

## NSA/CISA Kubernetes Hardening Guide v1.2
- Section 1: Pod Security - Use Pod Security Standards

## Compliance Mappings
- PCI DSS v4.0 Req 2.2: Configuration standards
- SOC 2 CC6.1: Logical access controls
- HIPAA 164.312(a)(1): Access controls
