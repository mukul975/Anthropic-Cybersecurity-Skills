# Standards and References - AWS Account Enumeration with ScoutSuite

## Industry Standards

### CIS AWS Foundations Benchmark v3.0
- Section 1: Identity and Access Management
- Section 2: Logging
- Section 3: Monitoring
- Section 4: Networking
- Section 5: Storage

### AWS Well-Architected Framework - Security Pillar
- SEC 1: Securely operate your workload
- SEC 2: Manage identities for people and machines
- SEC 3: Manage permissions for people and machines
- SEC 6: Protect compute resources
- SEC 8: Protect data at rest
- SEC 9: Protect data in transit

### NIST 800-53 Mapped Controls
- AC-2: Account Management
- AU-2: Audit Events
- AU-6: Audit Review, Analysis, and Reporting
- CM-6: Configuration Settings
- SC-7: Boundary Protection

## ScoutSuite Rule Mappings

### IAM Rules
| Rule ID | Description | CIS Benchmark |
|---------|-------------|---------------|
| iam-root-account-no-mfa | Root account MFA not enabled | 1.5 |
| iam-user-no-mfa | IAM user without MFA | 1.10 |
| iam-password-policy-no-uppercase | Weak password policy | 1.5 |
| iam-unused-access-key | Access key unused > 90 days | 1.12 |
| iam-inline-policy | Inline policies attached to users | 1.16 |

### S3 Rules
| Rule ID | Description | CIS Benchmark |
|---------|-------------|---------------|
| s3-bucket-public-access | Bucket allows public access | 2.1.5 |
| s3-bucket-no-logging | Server access logging disabled | 2.1.3 |
| s3-bucket-no-versioning | Versioning not enabled | N/A |
| s3-bucket-no-encryption | Default encryption not set | 2.1.1 |

### EC2 Rules
| Rule ID | Description | CIS Benchmark |
|---------|-------------|---------------|
| ec2-security-group-opens-all-ports | Security group allows all traffic | 5.2 |
| ec2-instance-with-public-ip | Instance has public IP | N/A |
| ec2-ebs-volume-not-encrypted | EBS volume unencrypted | 2.2.1 |

## Compliance Framework Coverage
- SOC 2 Type II
- PCI DSS v4.0
- HIPAA Security Rule
- ISO 27001:2022
- GDPR (data protection controls)
