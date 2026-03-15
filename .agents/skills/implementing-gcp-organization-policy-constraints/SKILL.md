---
name: implementing-gcp-organization-policy-constraints
description: Implement GCP Organization Policy constraints to enforce security guardrails across the entire resource hierarchy, restricting risky configurations and ensuring compliance at organization, folder, and project levels.
domain: cybersecurity
subdomain: cloud-security
tags: [gcp, organization-policy, constraints, governance, compliance, cloud-security, resource-manager]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing GCP Organization Policy Constraints

## Overview

The GCP Organization Policy Service provides centralized and programmatic control over cloud resources. Organization policies configure constraints that restrict one or more Google Cloud services, enforced at organization, folder, or project levels. They improve security by blocking external IPs, requiring encryption, and minimizing unauthorized access. Changes can take up to 15 minutes to propagate.

## Prerequisites

- GCP Organization with Organization Administrator role
- `gcloud` CLI configured and authenticated
- Terraform or gcloud for policy management
- Organization Policy Administrator IAM role (`roles/orgpolicy.policyAdmin`)

## Core Concepts

### Constraint Types

1. **List Constraints**: Allow or deny specific values (e.g., allowed regions)
2. **Boolean Constraints**: Enable or disable a capability (e.g., disable serial port access)
3. **Custom Constraints**: User-defined rules targeting specific resource fields (Preview)

### Policy Inheritance

Policies inherit from the lowest ancestor with an enforced policy. If no ancestor has a policy, Google's managed default behavior applies.

## Essential Security Constraints

### Restrict VM External IP Addresses

```bash
# Deny external IP addresses on all VMs
gcloud resource-manager org-policies set-policy \
  --organization=ORGANIZATION_ID \
  policy.yaml
```

policy.yaml:
```yaml
constraint: constraints/compute.vmExternalIpAccess
listPolicy:
  allValues: DENY
```

### Restrict Resource Locations

```bash
gcloud org-policies set-policy \
  --organization=ORGANIZATION_ID \
  location-policy.yaml
```

location-policy.yaml:
```yaml
constraint: constraints/gcp.resourceLocations
listPolicy:
  allowedValues:
    - "in:us-locations"
    - "in:eu-locations"
```

### Disable Default Service Account Creation

```yaml
constraint: constraints/iam.automaticIamGrantsForDefaultServiceAccounts
booleanPolicy:
  enforced: true
```

### Require OS Login for SSH

```yaml
constraint: constraints/compute.requireOsLogin
booleanPolicy:
  enforced: true
```

### Disable Serial Port Access

```yaml
constraint: constraints/compute.disableSerialPortAccess
booleanPolicy:
  enforced: true
```

### Enforce Uniform Bucket-Level Access

```yaml
constraint: constraints/storage.uniformBucketLevelAccess
booleanPolicy:
  enforced: true
```

### Restrict Public IP on Cloud SQL

```yaml
constraint: constraints/sql.restrictPublicIp
booleanPolicy:
  enforced: true
```

### Disable Service Account Key Creation

```yaml
constraint: constraints/iam.disableServiceAccountKeyCreation
booleanPolicy:
  enforced: true
```

## Terraform Implementation

```hcl
resource "google_organization_policy" "restrict_vm_external_ip" {
  org_id     = var.org_id
  constraint = "constraints/compute.vmExternalIpAccess"

  list_policy {
    deny {
      all = true
    }
  }
}

resource "google_organization_policy" "restrict_locations" {
  org_id     = var.org_id
  constraint = "constraints/gcp.resourceLocations"

  list_policy {
    allow {
      values = ["in:us-locations", "in:eu-locations"]
    }
  }
}

resource "google_organization_policy" "require_os_login" {
  org_id     = var.org_id
  constraint = "constraints/compute.requireOsLogin"

  boolean_policy {
    enforced = true
  }
}

resource "google_folder_organization_policy" "dev_folder_external_ip" {
  folder     = google_folder.dev.name
  constraint = "constraints/compute.vmExternalIpAccess"

  list_policy {
    allow {
      values = ["projects/dev-project/zones/us-central1-a/instances/bastion-host"]
    }
  }
}
```

## Dry-Run Testing

Use Policy Intelligence tools to test changes before enforcement:

```bash
# Create a dry-run policy to monitor impact
gcloud org-policies set-policy \
  --organization=ORGANIZATION_ID \
  dry-run-policy.yaml
```

dry-run-policy.yaml:
```yaml
constraint: constraints/compute.vmExternalIpAccess
listPolicy:
  allValues: DENY
dryRunSpec: true
```

```bash
# Check violations against dry-run policy
gcloud org-policies list-custom-constraints \
  --organization=ORGANIZATION_ID
```

## Custom Constraints

```yaml
# custom-constraint.yaml
name: organizations/ORGANIZATION_ID/customConstraints/custom.disableGKEAutoUpgrade
resourceTypes:
  - container.googleapis.com/NodePool
methodTypes:
  - CREATE
  - UPDATE
condition: "resource.management.autoUpgrade == true"
actionType: DENY
displayName: Deny GKE auto-upgrade on node pools
description: Prevents enabling auto-upgrade on GKE node pools for controlled upgrades
```

```bash
gcloud org-policies set-custom-constraint custom-constraint.yaml
```

## Monitoring and Compliance

### List active policies

```bash
gcloud org-policies list --organization=ORGANIZATION_ID
```

### Describe a specific policy

```bash
gcloud org-policies describe constraints/compute.vmExternalIpAccess \
  --organization=ORGANIZATION_ID
```

### Audit policy violations with Cloud Asset Inventory

```bash
gcloud asset search-all-resources \
  --scope=organizations/ORGANIZATION_ID \
  --query="policy:constraints/compute.vmExternalIpAccess"
```

## Recommended Baseline Policies

| Constraint | Type | Scope | Purpose |
|-----------|------|-------|---------|
| compute.vmExternalIpAccess | List/Deny | Org | Prevent public VM IPs |
| gcp.resourceLocations | List/Allow | Org | Restrict to approved regions |
| iam.disableServiceAccountKeyCreation | Boolean | Org | Force Workload Identity |
| compute.requireOsLogin | Boolean | Org | Mandate OS Login for SSH |
| storage.uniformBucketLevelAccess | Boolean | Org | Enforce uniform bucket access |
| sql.restrictPublicIp | Boolean | Org | No public Cloud SQL |
| compute.disableSerialPortAccess | Boolean | Org | Disable serial port |
| compute.disableNestedVirtualization | Boolean | Org | No nested VMs |

## References

- GCP Organization Policy Constraints: https://docs.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- GCP Policy Intelligence: https://cloud.google.com/policy-intelligence
- CIS GCP Foundations Benchmark
