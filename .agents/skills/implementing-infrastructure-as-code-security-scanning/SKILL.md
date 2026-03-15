---
name: implementing-infrastructure-as-code-security-scanning
description: >
  This skill covers implementing automated security scanning for Infrastructure as Code
  (IaC) templates using tools like Checkov, tfsec, and KICS. It addresses detecting
  misconfigurations in Terraform, CloudFormation, Kubernetes manifests, and Helm charts
  before deployment, establishing policy-based governance, and integrating IaC scanning
  into CI/CD pipelines to prevent insecure cloud resource provisioning.
domain: cybersecurity
subdomain: devsecops
tags: [devsecops, cicd, iac-security, checkov, tfsec, terraform, secure-sdlc]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Implementing Infrastructure as Code Security Scanning

## When to Use

- When provisioning cloud infrastructure with Terraform, CloudFormation, or Pulumi and needing automated security validation
- When compliance frameworks require evidence of infrastructure configuration review before deployment
- When preventing common cloud misconfigurations like public S3 buckets, open security groups, or unencrypted storage
- When establishing guardrails that block insecure infrastructure changes in pull requests
- When managing multi-cloud environments requiring consistent security policies across AWS, Azure, and GCP

**Do not use** for scanning application source code (use SAST), for monitoring already-deployed infrastructure drift (use cloud security posture management tools), or for container image vulnerability scanning (use Trivy).

## Prerequisites

- Checkov v3.x installed (`pip install checkov`) or tfsec installed
- Terraform, CloudFormation, or Kubernetes IaC files in the repository
- CI/CD pipeline with access to IaC directories
- Bridgecrew API key (optional, for Checkov platform integration)

## Workflow

### Step 1: Run Checkov Against Terraform Files

```bash
# Scan all Terraform files in a directory
checkov -d ./terraform/ --framework terraform --output cli --output json --output-file-path ./results

# Scan specific file
checkov -f main.tf --output json

# Scan Terraform plan (more accurate for dynamic values)
terraform init && terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
checkov -f tfplan.json --framework terraform_plan

# Scan with specific checks only
checkov -d ./terraform/ --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_20

# Skip specific checks
checkov -d ./terraform/ --skip-check CKV_AWS_145,CKV2_AWS_6
```

### Step 2: Integrate IaC Scanning into GitHub Actions

```yaml
# .github/workflows/iac-security.yml
name: IaC Security Scan

on:
  pull_request:
    paths:
      - 'terraform/**'
      - 'cloudformation/**'
      - 'k8s/**'

jobs:
  checkov:
    name: Checkov IaC Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@v12
        with:
          directory: terraform/
          framework: terraform
          output_format: cli,sarif
          output_file_path: console,checkov.sarif
          soft_fail: false
          skip_check: CKV_AWS_145

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov.sarif
          category: checkov-iac

  tfsec:
    name: tfsec Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.3
        with:
          working_directory: terraform/
          sarif_file: tfsec.sarif
          soft_fail: false

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: tfsec.sarif
          category: tfsec
```

### Step 3: Create Custom Checkov Policies

```python
# custom_checks/s3_versioning.py
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class S3BucketVersioning(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has versioning enabled"
        id = "CKV_CUSTOM_1"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories,
                         supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        versioning = conf.get("versioning", [{}])
        if isinstance(versioning, list) and len(versioning) > 0:
            if versioning[0].get("enabled", [False])[0]:
                return CheckResult.PASSED
        return CheckResult.FAILED


check = S3BucketVersioning()
```

### Step 4: Configure Baseline and Suppressions

```yaml
# .checkov.yaml
branch: main
compact: true
directory:
  - terraform/
  - cloudformation/
framework:
  - terraform
  - cloudformation
  - kubernetes
output:
  - cli
  - sarif
skip-check:
  - CKV_AWS_145    # S3 default encryption with CMK (using SSE-S3 is acceptable)
  - CKV2_AWS_6     # S3 bucket request logging (handled at CloudTrail level)
soft-fail: false
```

### Step 5: Scan Kubernetes Manifests and Helm Charts

```bash
# Scan Kubernetes manifests
checkov -d ./k8s/ --framework kubernetes

# Scan Helm charts (renders templates first)
checkov -d ./charts/myapp/ --framework helm

# Scan with KICS (Keeping Infrastructure as Code Secure)
docker run -v $(pwd)/k8s:/path checkmarx/kics:latest scan \
  --path /path \
  --output-path /path/results \
  --type Kubernetes \
  --report-formats json,sarif
```

## Key Concepts

| Term | Definition |
|------|------------|
| IaC Scanning | Automated analysis of infrastructure code templates to detect security misconfigurations before deployment |
| Policy as Code | Security policies defined as executable code that can be version-controlled, tested, and enforced automatically |
| CKV Check ID | Checkov's unique identifier for each security check (e.g., CKV_AWS_18 for S3 public access) |
| Terraform Plan Scanning | Scanning the resolved Terraform plan JSON which includes computed values and module expansions |
| Graph-based Scanning | Checkov's ability to analyze relationships between resources, not just individual resource configs |
| Drift Detection | Identifying differences between IaC definitions and actual deployed infrastructure state |
| Custom Policy | Organization-specific security checks authored in Python or YAML to enforce internal standards |

## Tools & Systems

- **Checkov**: Open-source IaC scanner by Bridgecrew with 2500+ built-in policies covering major cloud providers
- **tfsec**: Terraform-focused static analysis tool by Aqua Security with deep HCL understanding
- **KICS**: Open-source IaC scanner by Checkmarx supporting 15+ IaC frameworks
- **Terrascan**: IaC scanner with OPA Rego policy support for custom policy authoring
- **Snyk IaC**: Commercial IaC scanner integrated with the Snyk platform

## Common Scenarios

### Scenario: Preventing Public S3 Buckets in Terraform

**Context**: A development team repeatedly creates S3 buckets without proper access controls. A recent incident exposed customer data through a public bucket.

**Approach**:
1. Enable Checkov in the CI/CD pipeline for all Terraform changes
2. Enforce CKV_AWS_18 (no public read ACL), CKV_AWS_19 (encryption), CKV_AWS_20 (no public access block disabled)
3. Create a custom policy requiring the `aws_s3_bucket_public_access_block` resource for every S3 bucket
4. Set `soft_fail: false` to block PR merges when S3 security checks fail
5. Provide Terraform modules with security defaults that teams can reuse

**Pitfalls**: Scanning only `.tf` files misses dynamically computed values. Use Terraform plan scanning for higher accuracy. Checkov's resource-relationship checks (CKV2 prefix) require graph analysis mode.

## Output Format

```
IaC Security Scan Report
==========================
Framework: Terraform
Directory: terraform/
Scan Date: 2026-02-23

Checkov Results:
  Passed: 187
  Failed: 12
  Skipped: 3
  Unknown: 0

FAILED CHECKS:
  CKV_AWS_18  [HIGH]   S3 Bucket has public read ACL
              Resource: aws_s3_bucket.data_lake
              File:     terraform/storage.tf:15-28

  CKV_AWS_24  [HIGH]   CloudWatch log group not encrypted
              Resource: aws_cloudwatch_log_group.app
              File:     terraform/monitoring.tf:3-8

  CKV_AWS_79  [MEDIUM] Instance metadata service v1 enabled
              Resource: aws_instance.web
              File:     terraform/compute.tf:12-30

QUALITY GATE: FAILED (2 HIGH severity findings)
```
