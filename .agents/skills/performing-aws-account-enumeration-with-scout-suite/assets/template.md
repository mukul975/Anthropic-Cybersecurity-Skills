# ScoutSuite AWS Security Assessment Template

## Assessment Information

| Field | Value |
|-------|-------|
| Assessment Date | YYYY-MM-DD |
| AWS Account ID | |
| Assessor | |
| ScoutSuite Version | |
| Scan Scope | Full / Targeted Services |
| Regions Scanned | |

## Findings Summary

| Severity | Count | Remediated |
|----------|-------|------------|
| Critical (Danger) | | |
| Warning | | |
| Passing | | |

## Service-Level Findings

### IAM
- [ ] Root account MFA enabled
- [ ] Password policy meets CIS requirements
- [ ] No unused IAM users (>90 days)
- [ ] No unused access keys (>90 days)
- [ ] No inline policies on users
- [ ] No wildcard (*) permissions in policies

### S3
- [ ] No publicly accessible buckets
- [ ] Default encryption enabled on all buckets
- [ ] Server access logging enabled
- [ ] Versioning enabled on critical buckets
- [ ] Block Public Access settings enabled

### EC2
- [ ] No security groups allowing 0.0.0.0/0 on SSH (22)
- [ ] No security groups allowing 0.0.0.0/0 on RDP (3389)
- [ ] EBS volumes encrypted
- [ ] No instances with public IPs in private subnets
- [ ] IMDSv2 required on all instances

### RDS
- [ ] No publicly accessible databases
- [ ] Encryption at rest enabled
- [ ] Automated backups configured
- [ ] Multi-AZ for production databases

### CloudTrail
- [ ] CloudTrail enabled in all regions
- [ ] Log file validation enabled
- [ ] CloudTrail logs encrypted with KMS
- [ ] CloudTrail integrated with CloudWatch

### Lambda
- [ ] No functions with public access
- [ ] No secrets in environment variables
- [ ] Functions deployed in VPC where appropriate
- [ ] Execution roles follow least privilege

## Remediation Plan

| Priority | Finding | Service | Remediation | Owner | Due Date | Status |
|----------|---------|---------|-------------|-------|----------|--------|
| P1 | | | | | | |
| P2 | | | | | | |
| P3 | | | | | | |

## Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Assessor | | | |
| Account Owner | | | |
| CISO | | | |
