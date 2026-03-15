# Cloud Security Posture Management - Assessment Template

## Scope Definition
- **Cloud Providers**: [ ] AWS [ ] Azure [ ] GCP
- **Accounts/Subscriptions**: [List accounts in scope]
- **Compliance Framework**: [ ] CIS Benchmark [ ] PCI DSS [ ] NIST 800-53 [ ] SOC 2
- **Assessment Frequency**: [ ] Daily [ ] Weekly [ ] Monthly

## Critical Checks by Cloud Provider

### AWS Priority Checks
- [ ] S3 buckets not publicly accessible
- [ ] Root account MFA enabled
- [ ] CloudTrail enabled in all regions
- [ ] IAM access keys rotated within 90 days
- [ ] Security groups no unrestricted inbound (0.0.0.0/0)
- [ ] RDS instances not publicly accessible
- [ ] EBS volumes encrypted
- [ ] VPC flow logs enabled

### Azure Priority Checks
- [ ] Storage accounts not publicly accessible
- [ ] MFA enabled for all privileged accounts
- [ ] Activity log alerts configured
- [ ] NSG rules reviewed for unrestricted access
- [ ] SQL databases encrypted at rest
- [ ] Key Vault access policies reviewed
- [ ] Defender for Cloud enabled

### GCP Priority Checks
- [ ] Cloud Storage buckets not publicly accessible
- [ ] 2FA enforced for all users
- [ ] Audit logging enabled
- [ ] Firewall rules reviewed
- [ ] Cloud SQL instances not publicly accessible
- [ ] VPC Service Controls configured

## Report Deliverables
- [ ] Posture score by cloud account
- [ ] Failed checks by severity
- [ ] Compliance gap analysis
- [ ] Remediation priority list
- [ ] Month-over-month trend analysis
