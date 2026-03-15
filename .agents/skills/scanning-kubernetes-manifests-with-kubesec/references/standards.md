# Standards and References - Kubesec Manifest Scanning

## Industry Standards

### CIS Kubernetes Benchmark v1.9
- Section 5.2: Pod Security Standards -- Kubesec validates privileged mode, host namespaces
- Section 5.7: General Policies -- Service account configuration, resource limits
- Maps directly to kubesec scoring checks for container security contexts

### NIST SP 800-190: Application Container Security Guide
- Section 3.1: Image vulnerabilities and configuration defects
- Section 3.4: Orchestrator security -- manifest validation before deployment
- Section 4.1: Countermeasures for image vulnerabilities

### Kubernetes Pod Security Standards (PSS)
- **Privileged**: No restrictions (kubesec score = lowest)
- **Baseline**: Prevents known privilege escalation (kubesec validates hostPID, hostNetwork, privileged)
- **Restricted**: Best practices enforcement (kubesec validates all recommended controls)

## Compliance Mapping

| Kubesec Check | CIS Control | NIST 800-190 | PCI DSS |
|---------------|-------------|--------------|---------|
| Privileged containers | 5.2.1 | 3.4.4 | 2.2 |
| Host PID namespace | 5.2.2 | 3.4.2 | 2.2 |
| Host network | 5.2.4 | 3.4.3 | 1.3 |
| Root execution | 5.2.6 | 3.4.1 | 7.1 |
| ReadOnlyRootFilesystem | 5.2.8 | 4.1.2 | 2.2 |
| Resource limits | 5.4.1 | 4.3.1 | 2.2 |
| Service accounts | 5.1.5 | 3.4.5 | 7.2 |

## Tool Ecosystem

### Complementary Scanning Tools
- **Kubescape**: NSA/CISA framework compliance scanning
- **Checkov**: Infrastructure-as-code security scanning (covers Kubernetes)
- **Datree**: Policy enforcement with custom rules
- **OPA/Gatekeeper**: Runtime policy enforcement as admission controller

### Integration Points
- Pre-commit hooks for developer feedback
- CI/CD pipeline gates to prevent insecure deployments
- Admission webhooks for runtime enforcement
- IDE plugins for shift-left security
