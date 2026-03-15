# Standards and References - Kubernetes RBAC

## Kubernetes Documentation
- **RBAC Authorization**: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- **Authenticating**: https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- **Audit Logging**: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/

## Security Benchmarks
- **CIS Kubernetes Benchmark**: Section 5.1 - RBAC and Service Accounts
- **NSA/CISA Kubernetes Hardening Guide**: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF

## NIST Standards
- **NIST SP 800-53 Rev 5**: AC-2, AC-3, AC-5, AC-6, AU-3, AU-12
- **NIST SP 800-190**: Application Container Security Guide

## Tools
- **kubectl auth can-i**: Test RBAC permissions
- **rakkess**: Review access matrix for Kubernetes resources
- **rbac-lookup**: Find roles and bindings for users/groups
- **KubiScan**: Scan for risky RBAC configurations
- **kube-bench**: CIS benchmark checker for Kubernetes
