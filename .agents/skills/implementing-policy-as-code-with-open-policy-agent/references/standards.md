# Standards Reference: Policy as Code with OPA

## NIST SP 800-53 - Security and Privacy Controls

| Control | OPA Policy | Description |
|---------|-----------|-------------|
| AC-3 | Block unauthorized access | Enforce RBAC and namespace isolation |
| AC-6 | Least privilege | Block privileged containers and host access |
| CM-2 | Baseline configuration | Require resource limits and labels |
| CM-6 | Configuration settings | Enforce approved image registries |
| SI-7 | Software integrity | Require image signatures and digests |

## CIS Kubernetes Benchmark Mapping

- 5.1.1: Ensure RBAC is enabled → OPA can enforce RBAC policies
- 5.2.1: Minimize privileged containers → K8sBlockPrivileged constraint
- 5.2.2: Minimize host namespace sharing → Block hostNetwork/hostPID
- 5.2.5: Ensure allowPrivilegeEscalation is false → OPA constraint
- 5.7.1: Create administrative boundaries between resources → Namespace policies

## OWASP Kubernetes Security Cheat Sheet

- Enforce Pod Security Standards via admission control
- Restrict container capabilities using OPA policies
- Enforce network policies and resource quotas
- Validate image provenance and signatures
