# API Reference: Implementing Infrastructure as Code Security Scanning

## Checkov CLI

```bash
# Scan Terraform directory
checkov -d /path/to/tf --framework terraform --output json
# Scan specific file
checkov -f main.tf
# Scan CloudFormation
checkov -d . --framework cloudformation
# Scan Kubernetes manifests
checkov -d . --framework kubernetes
# Skip specific checks
checkov -d . --skip-check CKV_AWS_18,CKV_AWS_21
```

## tfsec CLI

```bash
# Scan directory
tfsec /path/to/tf --format json
# Exclude specific rules
tfsec . --exclude aws-s3-enable-bucket-logging
# Minimum severity
tfsec . --minimum-severity HIGH
```

## Common IaC Security Checks

| Check ID | Description | Severity |
|----------|-------------|----------|
| CKV_AWS_18 | S3 bucket logging | MEDIUM |
| CKV_AWS_19 | S3 bucket encryption | HIGH |
| CKV_AWS_23 | Security group open to 0.0.0.0/0 | HIGH |
| CKV_AWS_41 | RDS encryption | HIGH |
| CKV_AWS_145 | KMS key rotation | MEDIUM |
| CKV_K8S_1 | Pod privileged container | CRITICAL |

## GitHub Actions Integration

```yaml
- uses: bridgecrewio/checkov-action@master
  with:
    directory: .
    framework: terraform
    output_format: sarif
    soft_fail: false
```

### References

- Checkov: https://www.checkov.io/
- tfsec: https://aquasecurity.github.io/tfsec/
- KICS: https://kics.io/
- Bridgecrew: https://www.bridgecrew.io/
