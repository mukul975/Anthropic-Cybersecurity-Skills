---
name: auditing-terraform-infrastructure-for-security
description: >
  Auditing Terraform infrastructure-as-code for security misconfigurations using Checkov,
  tfsec, Terrascan, and OPA/Rego policies to detect overly permissive IAM policies, public
  resource exposure, missing encryption, and insecure defaults before cloud deployment.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, terraform, infrastructure-as-code, checkov, tfsec, policy-as-code]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Auditing Terraform Infrastructure for Security

## When to Use

- When integrating security scanning into CI/CD pipelines for Terraform deployments
- When reviewing Terraform plans and modules for security best practices before applying
- When building policy-as-code guardrails for cloud infrastructure provisioning
- When auditing existing Terraform state files to identify deployed misconfigurations
- When enforcing organizational security standards across multiple Terraform projects

**Do not use** for runtime security monitoring (use CSPM tools), for application security testing (use SAST/DAST tools), or for cloud configuration drift detection (use AWS Config or Azure Policy after deployment).

## Prerequisites

- Checkov installed (`pip install checkov`)
- tfsec installed (`brew install tfsec` or binary from GitHub)
- Terrascan installed (`brew install terrascan`)
- Terraform v1.0+ for plan generation
- OPA (Open Policy Agent) for custom policy enforcement
- Git repository with Terraform code to audit

## Workflow

### Step 1: Scan Terraform Code with Checkov

Run Checkov for comprehensive IaC security scanning with built-in and custom policies.

```bash
# Scan a Terraform directory
checkov -d ./terraform/ --framework terraform

# Scan with specific check categories
checkov -d ./terraform/ --check CKV_AWS_18,CKV_AWS_19,CKV_AWS_20,CKV_AWS_21

# Scan and output results in JSON
checkov -d ./terraform/ --output json > checkov-results.json

# Scan a Terraform plan file for more accurate analysis
terraform init && terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
checkov -f tfplan.json --framework terraform_plan

# Skip specific checks with justification
checkov -d ./terraform/ --skip-check CKV_AWS_145 \
  --bc-api-key $BRIDGECREW_API_KEY

# Scan Terraform modules
checkov -d ./modules/ --framework terraform --compact

# List all available checks
checkov --list --framework terraform | grep CKV_AWS
```

### Step 2: Scan with tfsec for Terraform-Specific Issues

Use tfsec for Terraform-native security analysis with detailed remediation guidance.

```bash
# Scan a Terraform directory
tfsec ./terraform/

# Scan with minimum severity threshold
tfsec ./terraform/ --minimum-severity HIGH

# Output in JSON for CI/CD processing
tfsec ./terraform/ --format json > tfsec-results.json

# Scan with custom checks
tfsec ./terraform/ --custom-check-dir ./custom-checks/

# Exclude specific rules
tfsec ./terraform/ --exclude-downloaded-modules \
  --exclude aws-s3-enable-bucket-logging

# Scan and fail on specific severity
tfsec ./terraform/ --minimum-severity CRITICAL --soft-fail

# Generate SARIF output for GitHub Security tab
tfsec ./terraform/ --format sarif > tfsec.sarif
```

### Step 3: Run Terrascan for Multi-Framework Compliance

Execute Terrascan for compliance checking against CIS, NIST, and SOC 2 frameworks.

```bash
# Scan Terraform against CIS AWS benchmark
terrascan scan -t aws -i terraform -d ./terraform/ \
  --policy-type aws --verbose

# Scan against specific compliance frameworks
terrascan scan -t aws -i terraform -d ./terraform/ \
  --policy-type aws \
  --categories "Compliance Validation"

# Output in JSON
terrascan scan -t aws -i terraform -d ./terraform/ \
  --output json > terrascan-results.json

# Scan a Terraform plan
terrascan scan -t aws -i terraform \
  --iac-file tfplan.json \
  --iac-type tfplan

# List available policies
terrascan scan --list-policies -t aws
```

### Step 4: Create Custom OPA Policies for Organization Standards

Write Rego policies for organization-specific security requirements.

```rego
# policy/aws_s3_encryption.rego
package terraform.aws.s3

deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [name])
}

# policy/aws_iam_no_wildcards.rego
package terraform.aws.iam

deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Action == "*"
    statement.Effect == "Allow"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) actions", [name])
}

deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Resource == "*"
    statement.Effect == "Allow"
    contains(statement.Action[_], "*")
    msg := sprintf("IAM policy '%s' has overly permissive actions on wildcard resources", [name])
}

# policy/aws_no_public_ingress.rego
package terraform.aws.security_group

deny[msg] {
    resource := input.resource.aws_security_group_rule[name]
    resource.type == "ingress"
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port <= 22
    resource.to_port >= 22
    msg := sprintf("Security group rule '%s' allows SSH from 0.0.0.0/0", [name])
}
```

```bash
# Evaluate Terraform plan against OPA policies
terraform show -json tfplan | opa eval \
  --data ./policy/ \
  --input /dev/stdin \
  "data.terraform.aws" \
  --format pretty

# Run Conftest for easier OPA policy testing
conftest test tfplan.json --policy ./policy/ --output json
```

### Step 5: Integrate Security Scanning into CI/CD Pipeline

Add IaC security scanning as a mandatory CI/CD gate.

```yaml
# GitHub Actions: Terraform security pipeline
name: Terraform Security Scan
on:
  pull_request:
    paths: ['terraform/**']

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init & Plan
        run: |
          cd terraform/
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: Checkov Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov.sarif
          soft_fail: false

      - name: tfsec Scan
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: terraform/
          soft_fail: false

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: checkov.sarif

      - name: OPA Policy Check
        run: |
          conftest test terraform/tfplan.json \
            --policy ./policy/ \
            --output json
```

### Step 6: Scan Terraform State for Deployed Misconfigurations

Audit the current Terraform state to identify already-deployed security issues.

```bash
# Export current state as JSON
terraform show -json > terraform-state.json

# Scan the state with Checkov
checkov -f terraform-state.json --framework terraform_plan

# Query state for specific security issues
terraform state list | while read resource; do
  terraform state show "$resource" 2>/dev/null | grep -i "public\|0.0.0.0\|encrypt.*false\|password"
done

# Find resources without required tags
terraform state list | grep aws_instance | while read resource; do
  tags=$(terraform state show "$resource" | grep -A20 "tags")
  if ! echo "$tags" | grep -q "Environment"; then
    echo "MISSING TAG: $resource lacks 'Environment' tag"
  fi
done
```

## Key Concepts

| Term | Definition |
|------|------------|
| Infrastructure as Code | Practice of managing cloud infrastructure through declarative configuration files (Terraform, CloudFormation) rather than manual console operations |
| Policy as Code | Expressing security and compliance policies as executable code (Rego, Python) that can be automatically evaluated against infrastructure definitions |
| Shift Left Security | Moving security checks earlier in the development lifecycle by scanning IaC before deployment rather than auditing after provisioning |
| Terraform Plan | Preview of changes Terraform will make, which can be exported as JSON for security scanning before applying changes |
| Checkov | Open-source static analysis tool for IaC supporting Terraform, CloudFormation, Kubernetes, and Docker with 1000+ built-in policies |
| OPA/Rego | Open Policy Agent and its policy language Rego for defining custom security rules that evaluate against structured data inputs |

## Tools & Systems

- **Checkov**: Comprehensive IaC scanner with 1000+ policies for Terraform, CloudFormation, Kubernetes, ARM, and Dockerfile
- **tfsec**: Terraform-specific static analysis tool with detailed remediation guidance and SARIF output
- **Terrascan**: Multi-IaC scanner supporting compliance frameworks (CIS, NIST, SOC 2) with policy-as-code
- **OPA/Conftest**: Custom policy engine for defining organization-specific security rules using Rego language
- **Bridgecrew**: Commercial platform built on Checkov providing drift detection and supply chain security

## Common Scenarios

### Scenario: Adding Security Gates to an Existing Terraform CI/CD Pipeline

**Context**: A DevOps team deploys infrastructure via Terraform in GitHub Actions but has no security scanning. Recent audit findings show multiple S3 buckets without encryption and security groups allowing SSH from the internet.

**Approach**:
1. Add Checkov as the first security gate in the GitHub Actions workflow
2. Run `checkov -d ./terraform/` to establish the current baseline of findings
3. Triage existing findings: fix CRITICAL issues, create tickets for HIGH, suppress accepted risks
4. Add tfsec as a secondary scanner for Terraform-specific checks
5. Write custom OPA policies for organization standards (required tags, naming conventions)
6. Configure the pipeline to block PRs with CRITICAL or HIGH findings
7. Generate SARIF reports for GitHub Security tab integration

**Pitfalls**: Adding security scanning to an existing project will initially produce hundreds of findings. Implement gradually by starting with CRITICAL-only blocking, then expanding to HIGH. Use inline suppression comments (`#checkov:skip=CKV_AWS_18:Public bucket for static website`) for intentional exceptions with documented justification.

## Output Format

```
Terraform Security Audit Report
==================================
Repository: acme-corp/infrastructure
Branch: main
Scan Date: 2026-02-23
Tools: Checkov 3.x, tfsec 1.x, OPA custom policies

SCAN RESULTS:
  Checkov checks passed:    187
  Checkov checks failed:     34
  tfsec checks passed:      156
  tfsec checks failed:       28
  OPA custom policies:       12 passed, 3 failed

CRITICAL FINDINGS:
[TF-001] S3 Bucket Without Encryption
  File: modules/storage/main.tf:24
  Resource: aws_s3_bucket.data_lake
  Check: CKV_AWS_19
  Fix: Add server_side_encryption_configuration block

[TF-002] Security Group Allows SSH from 0.0.0.0/0
  File: modules/network/security.tf:45
  Resource: aws_security_group_rule.ssh_access
  Check: CKV_AWS_24
  Fix: Restrict cidr_blocks to bastion subnet

[TF-003] IAM Policy with Wildcard Actions
  File: modules/iam/policies.tf:12
  Resource: aws_iam_policy.developer_policy
  Check: CKV_AWS_1
  Fix: Scope actions to specific services required

SUMMARY BY SEVERITY:
  Critical:  6 findings
  High:     14 findings
  Medium:   28 findings
  Low:      18 findings
  Info:     12 findings
```
