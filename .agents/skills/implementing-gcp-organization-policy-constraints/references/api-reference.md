# API Reference: Implementing GCP Organization Policy Constraints

## gcloud CLI Commands

```bash
# List all org policies
gcloud org-policies list --organization=ORG_ID

# Describe specific constraint
gcloud org-policies describe constraints/compute.vmExternalIpAccess --organization=ORG_ID

# Set policy from YAML
gcloud resource-manager org-policies set-policy policy.yaml --organization=ORG_ID

# Set custom constraint
gcloud org-policies set-custom-constraint custom-constraint.yaml

# Check effective policy on project
gcloud org-policies list --project=PROJECT_ID
```

## Baseline Security Constraints

| Constraint | Type | Purpose |
|-----------|------|---------|
| `compute.vmExternalIpAccess` | List/Deny | Block public VM IPs |
| `compute.requireOsLogin` | Boolean | Mandate OS Login for SSH |
| `compute.disableSerialPortAccess` | Boolean | Disable serial port |
| `storage.uniformBucketLevelAccess` | Boolean | Uniform bucket ACLs |
| `sql.restrictPublicIp` | Boolean | No public Cloud SQL |
| `iam.disableServiceAccountKeyCreation` | Boolean | Force Workload Identity |
| `gcp.resourceLocations` | List/Allow | Restrict to approved regions |

## Policy YAML Formats

### Boolean Policy
```yaml
constraint: constraints/compute.requireOsLogin
booleanPolicy:
  enforced: true
```

### List Policy (Deny All)
```yaml
constraint: constraints/compute.vmExternalIpAccess
listPolicy:
  allValues: DENY
```

### List Policy (Allow Specific)
```yaml
constraint: constraints/gcp.resourceLocations
listPolicy:
  allowedValues:
    - "in:us-locations"
    - "in:eu-locations"
```

## Terraform Resource

```hcl
resource "google_organization_policy" "example" {
  org_id     = var.org_id
  constraint = "constraints/compute.requireOsLogin"
  boolean_policy { enforced = true }
}
```

### References

- GCP Org Policy: https://cloud.google.com/resource-manager/docs/organization-policy/overview
- Constraint List: https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- CIS GCP Benchmark: https://www.cisecurity.org/benchmark/google_cloud_computing_platform
