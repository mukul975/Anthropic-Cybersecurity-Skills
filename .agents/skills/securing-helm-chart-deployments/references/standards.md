# Standards and References - Securing Helm Chart Deployments

## NIST SP 800-190
- Section 4.1: Image vulnerabilities and configuration defects
- Section 5.2: Registry security and chart provenance
- Section 5.4: Secure deployment configuration

## CIS Kubernetes Benchmark v1.8
- 5.2.1-5.2.9: Pod Security Standards enforced via chart defaults
- 5.7.3: Apply security context to pods and containers

## SLSA (Supply chain Levels for Software Artifacts)
- Level 1: Documented build process (Helm chart CI)
- Level 2: Source version controlled, signed provenance
- Level 3: Hardened build platform, signed artifacts
- Level 4: Two-party review, hermetic builds

## Helm Security Resources

| Resource | URL |
|----------|-----|
| Helm Security Best Practices | https://helm.sh/docs/chart_best_practices/ |
| Helm Provenance and Integrity | https://helm.sh/docs/topics/provenance/ |
| kube-linter | https://github.com/stackrox/kube-linter |
| checkov Kubernetes checks | https://www.checkov.io/5.Policy%20Index/kubernetes.html |
| helm-secrets plugin | https://github.com/jkroepke/helm-secrets |

## Compliance Mappings

### PCI DSS v4.0
- Req 6.3.1: Security vulnerabilities identified and managed
- Req 6.5.1: Changes controlled by change control processes

### SOC 2
- CC8.1: Change management - Controlled deployment processes
