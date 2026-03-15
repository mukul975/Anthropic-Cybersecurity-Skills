# IaC Security Scanning Templates

## Checkov Configuration File

```yaml
# .checkov.yaml
branch: main
compact: true
directory:
  - terraform/
  - cloudformation/
  - k8s/
framework:
  - terraform
  - cloudformation
  - kubernetes
output:
  - cli
  - sarif
skip-check:
  - CKV_AWS_145   # CMK encryption for S3 (SSE-S3 acceptable)
  - CKV2_AWS_6    # S3 request logging (CloudTrail covers this)
soft-fail: false
```

## GitHub Actions Pipeline

```yaml
# .github/workflows/iac-security.yml
name: IaC Security

on:
  pull_request:
    paths: ['terraform/**', 'k8s/**', 'cloudformation/**']

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bridgecrewio/checkov-action@v12
        with:
          directory: terraform/
          framework: terraform
          output_format: cli,sarif
          output_file_path: console,checkov.sarif
          soft_fail: false
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: checkov.sarif
```

## Secure Terraform Module Template

```hcl
# modules/secure-s3-bucket/main.tf
resource "aws_s3_bucket" "this" {
  bucket = var.bucket_name
  tags   = var.tags
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = var.kms_key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logging_bucket
  target_prefix = "s3-access-logs/${var.bucket_name}/"
}
```
