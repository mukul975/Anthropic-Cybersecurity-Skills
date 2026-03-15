# Standards Reference: IaC Security Scanning

## CIS Cloud Benchmarks

### CIS AWS Foundations Benchmark v3.0
- Maps directly to Checkov CKV_AWS_* checks
- Covers IAM, logging, monitoring, networking, and storage security
- Automated scanning validates 100+ benchmark controls

### CIS Azure Foundations Benchmark v2.1
- Maps to Checkov CKV_AZURE_* checks
- Covers identity, security center, storage, database, and network controls

### CIS GCP Foundations Benchmark v2.0
- Maps to Checkov CKV_GCP_* checks
- Covers IAM, logging, networking, VM, storage, and database controls

## NIST SP 800-53 Mapping

| NIST Control | IaC Check | Checkov ID |
|-------------|-----------|------------|
| AC-3 Access Enforcement | S3 bucket public access | CKV_AWS_18, CKV_AWS_20 |
| AU-2 Audit Events | CloudTrail enabled | CKV_AWS_35 |
| SC-8 Transmission Confidentiality | HTTPS/TLS enforcement | CKV_AWS_2 |
| SC-28 Protection at Rest | Encryption at rest | CKV_AWS_19, CKV_AWS_17 |
| SI-4 System Monitoring | CloudWatch/logging | CKV_AWS_24, CKV_AWS_66 |

## OWASP SAMM - Secure Architecture

### Security Architecture Level 2
- Validate infrastructure configurations against security standards before deployment
- Use automated tools to enforce architecture security requirements

### Security Architecture Level 3
- Custom policies encode organization-specific architecture requirements
- Continuous validation prevents configuration drift from approved patterns

## NIST SSDF (SP 800-218)

### PO.1: Define Security Requirements
- IaC security policies translate security requirements into enforceable checks
- Custom policies capture organization-specific requirements

### PW.5: Configure Software Securely
- PW.5.1: Configure software to have secure settings by default
- IaC scanning enforces secure defaults in infrastructure provisioning
