# Workflow Reference: IaC Security Scanning

## IaC Scanning Pipeline

```
Terraform/IaC Code Change
       │
       ▼
┌──────────────────┐
│ PR Created       │
└──────┬───────────┘
       │
       ├──────────────────────┐
       ▼                      ▼
┌──────────────┐    ┌──────────────┐
│ Checkov      │    │ tfsec        │
│ (2500+ rules)│    │ (Terraform)  │
└──────┬───────┘    └──────┬───────┘
       │                    │
       └──────────┬─────────┘
                  ▼
       ┌──────────────────┐
       │ SARIF Upload     │
       │ to GitHub        │
       └──────┬───────────┘
              │
              ▼
       ┌──────────────────┐
       │ Quality Gate     │
       │ (Block on HIGH+) │
       └──────┬───────────┘
              │
    ┌─────────┴──────────┐
    ▼                    ▼
 PASS                  FAIL
 terraform apply      Block merge
 permitted            + Fix required
```

## Checkov Command Reference

| Command | Purpose |
|---------|---------|
| `checkov -d ./terraform/` | Scan directory |
| `checkov -f main.tf` | Scan single file |
| `checkov -f tfplan.json --framework terraform_plan` | Scan Terraform plan |
| `checkov --list` | List all available checks |
| `checkov -d . --check CKV_AWS_18` | Run specific check |
| `checkov -d . --skip-check CKV_AWS_145` | Skip specific check |
| `checkov -d . --bc-api-key KEY` | Upload to Bridgecrew |
| `checkov -d . --create-baseline` | Create baseline file |
| `checkov -d . --baseline BASELINE` | Scan against baseline |
| `checkov -d . --external-checks-dir ./custom/` | Use custom checks |
| `checkov -d . --compact` | Compact output |
| `checkov -d . --output sarif` | SARIF format output |

## Common Misconfigurations by Cloud Provider

### AWS Top 10 IaC Misconfigurations
1. S3 bucket public access enabled (CKV_AWS_18, CKV_AWS_20)
2. Security group with open ingress 0.0.0.0/0 (CKV_AWS_23)
3. RDS instance not encrypted (CKV_AWS_16)
4. CloudTrail not enabled (CKV_AWS_35)
5. EBS volume not encrypted (CKV_AWS_3)
6. IAM policy with wildcard actions (CKV_AWS_1)
7. ALB not using HTTPS (CKV_AWS_2)
8. CloudWatch logs not encrypted (CKV_AWS_24)
9. IMDSv2 not required (CKV_AWS_79)
10. VPC flow logs not enabled (CKV_AWS_9)

### Kubernetes Top Misconfigurations
1. Container running as root (CKV_K8S_6)
2. Privileged container (CKV_K8S_16)
3. No resource limits (CKV_K8S_11, CKV_K8S_13)
4. No readiness/liveness probes (CKV_K8S_9)
5. hostNetwork enabled (CKV_K8S_19)
