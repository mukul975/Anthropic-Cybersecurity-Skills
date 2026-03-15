# Standards & References - Ransomware Backup Strategy

## Industry Standards

### NIST SP 800-209: Security Guidelines for Storage Infrastructure
- Defines security controls for storage systems including backup infrastructure
- Covers access control, encryption, integrity verification, and audit logging for storage
- Section 5.3: Backup and recovery security controls

### NIST IR 8374: Ransomware Risk Management
- Identifies backup as a critical control in the Recover function
- Recommends maintaining offline, encrypted backups with regular testing
- Emphasizes credential separation for backup administration

### CISA #StopRansomware Guide (2023, updated 2025)
- Prescribes 3-2-1 backup rule as baseline, recommends extending to 3-2-1-1-0
- Mandates backup credential isolation from production domains
- Requires documented and tested recovery procedures

### CIS Controls v8
- Control 11: Data Recovery
  - 11.1: Establish and maintain a data recovery process
  - 11.2: Perform automated backups
  - 11.3: Protect recovery data (encryption, access control)
  - 11.4: Establish and maintain an isolated instance of recovery data (air-gapped/immutable)
  - 11.5: Test data recovery

### ISO 27001:2022
- A.8.13: Information backup
- A.8.14: Redundancy of information processing facilities

## Regulatory Requirements

### PCI DSS v4.0
- Requirement 9.4.1: Backup media physically secured
- Requirement 12.10.1: Incident response plan includes recovery procedures

### HIPAA Security Rule
- 45 CFR 164.308(a)(7): Contingency plan including data backup, disaster recovery, emergency mode operation
- 45 CFR 164.312(a)(2)(ii): Emergency access procedure

### SOX
- Section 302/404: Internal controls over financial reporting must include IT controls for data backup and recovery

## Vendor Documentation

### Veeam
- Hardened Repository Guide: https://helpcenter.veeam.com/docs/backup/vsphere/hardened_repository.html
- SureBackup: https://helpcenter.veeam.com/docs/backup/vsphere/surebackup_job.html
- Immutability: https://helpcenter.veeam.com/docs/backup/vsphere/immutability.html

### AWS
- S3 Object Lock: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- AWS Backup Vault Lock: https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html

### Azure
- Immutable Blob Storage: https://learn.microsoft.com/en-us/azure/storage/blobs/immutable-storage-overview
- Azure Backup Immutable Vault: https://learn.microsoft.com/en-us/azure/backup/backup-azure-immutable-vault-concept
