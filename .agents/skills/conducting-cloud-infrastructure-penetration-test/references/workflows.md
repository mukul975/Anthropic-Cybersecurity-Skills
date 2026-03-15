# Workflows — Cloud Infrastructure Penetration Testing

## Attack Flow
```
Cloud Credentials / Unauthenticated
    │
    ├── IAM Enumeration (permissions, roles, policies)
    ├── Resource Discovery (compute, storage, serverless)
    ├── Privilege Escalation (IAM chaining, role assumption)
    ├── Data Access (storage buckets, databases, secrets)
    ├── Lateral Movement (cross-account, cross-service)
    └── Impact Demonstration (data exfiltration proof)
```
