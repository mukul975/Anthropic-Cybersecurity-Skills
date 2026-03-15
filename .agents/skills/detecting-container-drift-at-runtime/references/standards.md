# Standards and References - Container Drift Detection

## Industry Standards

### NIST SP 800-190: Application Container Security Guide
- Section 3.3: Containers modified at runtime indicate compromise
- Section 4.2: Monitor containers for unauthorized changes
- Recommends treating containers as immutable infrastructure

### CIS Kubernetes Benchmark v1.9
- Control 5.2.8: Minimize container readOnlyRootFilesystem
- Control 5.7.3: Apply security contexts to pods
- Control 5.7.4: Default namespace restrictions

### MITRE ATT&CK for Containers
- T1610: Deploy Container -- unauthorized container deployment
- T1611: Escape to Host -- container boundary violation
- T1059.004: Unix Shell execution in containers
- T1105: Ingress Tool Transfer -- downloading tools into containers

## Compliance Mapping

| Requirement | Framework | Drift Detection Capability |
|-------------|-----------|--------------------------|
| Change detection | PCI DSS 11.5 | File integrity monitoring in containers |
| Unauthorized software | SOC 2 CC6.8 | Binary execution drift alerts |
| Configuration management | ISO 27001 A.12.1 | Image digest verification |
| Incident detection | NIST CSF DE.CM-7 | Runtime behavioral anomaly detection |
