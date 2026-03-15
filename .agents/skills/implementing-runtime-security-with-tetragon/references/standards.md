# Standards and References - Runtime Security with Tetragon

## Industry Standards

### NIST SP 800-190: Application Container Security Guide
- Section 4.2: Runtime monitoring and anomaly detection for containers
- Section 4.4: Container-level network monitoring requirements
- Recommends kernel-level security monitoring for container environments

### CIS Kubernetes Benchmark v1.9
- Control 5.7.1: Create administrative boundaries between resources using namespaces
- Control 5.7.3: Apply Security Context to pods and containers
- Control 5.7.4: The default namespace should not be used

### MITRE ATT&CK for Containers
- T1611: Escape to Host -- Tetragon detects namespace manipulation attempts
- T1059.004: Command and Scripting Interpreter: Unix Shell -- process execution monitoring
- T1053.007: Container Orchestration Job -- detects unauthorized job creation
- T1496: Resource Hijacking -- crypto-miner detection and blocking

## CNCF Landscape Positioning

Tetragon is positioned in the CNCF Runtime Security category alongside:
- Falco (audit-log and syscall-based detection)
- KubeArmor (LSM-based enforcement)
- Tracee (eBPF-based tracing)

### Key Differentiators
- Kernel-level filtering reduces event volume before reaching user space
- Native enforcement (Sigkill/Override) without requiring separate enforcement engine
- Deep integration with Cilium for combined network + runtime security
- TracingPolicy CRD for Kubernetes-native policy management

## Compliance Mapping

| Requirement | Framework | Tetragon Capability |
|-------------|-----------|-------------------|
| Runtime threat detection | PCI DSS 11.5 | TracingPolicy with file integrity monitoring |
| Unauthorized process detection | SOC 2 CC6.8 | Process execution monitoring with namespace context |
| Container isolation enforcement | NIST 800-190 4.2 | Namespace escape detection and blocking |
| Audit trail generation | ISO 27001 A.12.4 | JSON event export to SIEM systems |
| Incident response automation | NIST CSF DE.AE | Real-time Sigkill enforcement on policy violations |
