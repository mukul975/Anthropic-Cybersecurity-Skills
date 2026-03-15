# Standards - etcd Security Assessment

## CIS Kubernetes Benchmark v1.9 - Section 2: etcd
- 2.1: Ensure cert-file and key-file arguments are set
- 2.2: Ensure client-cert-auth argument is set to true
- 2.3: Ensure auto-tls argument is not set to true
- 2.4: Ensure peer-cert-file and peer-key-file arguments are set
- 2.5: Ensure peer-client-cert-auth argument is set to true
- 2.6: Ensure peer-auto-tls argument is not set to true
- 2.7: Ensure a unique Certificate Authority is used for etcd

## NIST SP 800-190
- Section 3.4.4: Data store encryption requirements
- Section 4.4.2: Secrets management for orchestrators

## Compliance Mapping
| Control | PCI DSS | SOC 2 | HIPAA |
|---------|---------|-------|-------|
| Encryption at rest | 3.4 | CC6.1 | 164.312(a)(2)(iv) |
| TLS transport | 4.1 | CC6.7 | 164.312(e)(1) |
| Access control | 7.1 | CC6.3 | 164.312(a)(1) |
| Backup encryption | 3.4 | CC6.1 | 164.310(d)(2)(iv) |
