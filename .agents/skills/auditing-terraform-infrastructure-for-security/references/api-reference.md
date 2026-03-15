# API Reference: Auditing Terraform Infrastructure for Security

## Checkov CLI

```bash
# Scan directory
checkov -d ./terraform/ --framework terraform --output json

# Scan plan file
terraform plan -out=tfplan && terraform show -json tfplan > tfplan.json
checkov -f tfplan.json --framework terraform_plan

# Skip specific checks
checkov -d ./terraform/ --skip-check CKV_AWS_145

# List all checks
checkov --list --framework terraform | grep CKV_AWS
```

## tfsec CLI

```bash
# Scan with minimum severity
tfsec ./terraform/ --minimum-severity HIGH --format json

# Generate SARIF for GitHub
tfsec ./terraform/ --format sarif > tfsec.sarif
```

## Checkov Python API

```python
from checkov.runner_registry import RunnerRegistry
from checkov.terraform.runner import Runner

runner = Runner()
report = runner.run(root_folder="./terraform/")
for check in report.failed_checks:
    print(check.check_id, check.resource, check.file_path)
```

## Common CKV Check IDs

| Check ID | Description |
|----------|-------------|
| CKV_AWS_18 | S3 access logging |
| CKV_AWS_19 | S3 server-side encryption |
| CKV_AWS_20 | S3 Block Public Access |
| CKV_AWS_24 | Security group allows SSH from 0.0.0.0/0 |
| CKV_AWS_1 | IAM policy with wildcard actions |
| CKV_AWS_145 | RDS encryption |
| CKV_AWS_41 | Secrets in Lambda environment variables |

## OPA/Conftest

```bash
# Evaluate plan against Rego policies
conftest test tfplan.json --policy ./policy/ --output json
```

```rego
package terraform.aws.s3
deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' missing encryption", [name])
}
```

### References

- Checkov: https://www.checkov.io/
- tfsec: https://aquasecurity.github.io/tfsec/
- Terrascan: https://runterrascan.io/
- Conftest: https://www.conftest.dev/
