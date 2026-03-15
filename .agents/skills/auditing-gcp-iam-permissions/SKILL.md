---
name: auditing-gcp-iam-permissions
description: >
  Auditing Google Cloud Platform IAM permissions to identify overly permissive bindings,
  primitive role usage, service account key proliferation, and cross-project access risks
  using gcloud CLI, Policy Analyzer, and IAM Recommender.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, gcp, iam, permissions-audit, service-accounts, policy-analyzer]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Auditing GCP IAM Permissions

## When to Use

- When performing security assessments of GCP organization or project IAM configurations
- When identifying service accounts with excessive permissions or unused access
- When compliance requirements mandate review of access controls and role assignments
- When investigating potential lateral movement through IAM misconfigurations
- When reducing the blast radius of compromised credentials by scoping down permissions

**Do not use** for VPC firewall rule auditing (use network security tools), for GKE RBAC auditing (use Kubernetes-specific RBAC tools), or for real-time threat detection on IAM actions (use SCC Event Threat Detection).

## Prerequisites

- GCP organization or project with `roles/iam.securityReviewer` and `roles/cloudAsset.viewer`
- gcloud CLI authenticated with appropriate permissions
- Cloud Asset API enabled (`gcloud services enable cloudasset.googleapis.com`)
- IAM Recommender API enabled (`gcloud services enable recommender.googleapis.com`)
- Policy Analyzer API enabled (`gcloud services enable policyanalyzer.googleapis.com`)

## Workflow

### Step 1: Enumerate IAM Bindings Across the Organization

List all IAM bindings at organization, folder, and project levels to understand the full access landscape.

```bash
# Organization-level IAM bindings
gcloud organizations get-iam-policy ORG_ID \
  --format=json > org-iam-policy.json

# Search all IAM policies across the organization
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --format="table(resource, policy.bindings.role, policy.bindings.members)" \
  --limit=500

# Find all users and service accounts with Owner role
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner" \
  --format="table(resource, policy.bindings.members)"

# Find all bindings using primitive roles (Owner, Editor, Viewer)
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner OR policy:roles/editor" \
  --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data:
    resource = result.get('resource', '')
    for binding in result.get('policy', {}).get('bindings', []):
        role = binding.get('role', '')
        if role in ['roles/owner', 'roles/editor']:
            for member in binding.get('members', []):
                print(f'{resource} | {role} | {member}')
"
```

### Step 2: Audit Service Accounts and Their Keys

Identify service accounts with excessive permissions, user-managed keys, and unused accounts.

```bash
# List all service accounts in a project
gcloud iam service-accounts list \
  --project=PROJECT_ID \
  --format="table(email, displayName, disabled)"

# Check for user-managed keys (should be minimized)
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  keys=$(gcloud iam service-accounts keys list \
    --iam-account="$sa" \
    --managed-by=user \
    --format="table(name.basename(),validAfterTime,validBeforeTime)")
  if [ -n "$keys" ]; then
    echo "=== $sa ==="
    echo "$keys"
  fi
done

# Find service accounts with admin roles across all projects
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy.bindings.members:serviceAccount AND (policy:roles/owner OR policy:roles/editor OR policy:admin)" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

# Check service account IAM policies (who can impersonate)
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  echo "=== $sa ==="
  gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null
done
```

### Step 3: Use IAM Recommender to Identify Excess Permissions

Leverage GCP's IAM Recommender to find roles that grant more access than actually used.

```bash
# List IAM role recommendations for a project
gcloud recommender recommendations list \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format="table(name, description, priority, stateInfo.state)"

# Get detailed recommendation
gcloud recommender recommendations describe RECOMMENDATION_ID \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format=json

# List insights about IAM usage
gcloud recommender insights list \
  --project=PROJECT_ID \
  --insight-type=google.iam.policy.Insight \
  --location=global \
  --format="table(name, description, severity, category)"

# Apply a recommendation (after review)
gcloud recommender recommendations mark-claimed RECOMMENDATION_ID \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --etag=ETAG
```

### Step 4: Analyze Effective Permissions with Policy Analyzer

Use Policy Analyzer to determine effective access for specific principals or resources.

```bash
# Check who has access to a specific resource
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --full-resource-name="//storage.googleapis.com/projects/_/buckets/sensitive-data-bucket" \
  --format="table(identityList.identities, accessControlLists.accesses.role)"

# Check what resources a specific user can access
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --identity="user:developer@company.com" \
  --format="table(accessControlLists.resources.fullResourceName, accessControlLists.accesses.role)"

# Check who can perform a specific action
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --full-resource-name="//cloudresourcemanager.googleapis.com/projects/PROJECT_ID" \
  --permissions="iam.serviceAccounts.actAs,iam.serviceAccountKeys.create" \
  --format="table(identityList.identities, accessControlLists.accesses.permission)"

# Find all principals with allUsers or allAuthenticatedUsers access
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"
```

### Step 5: Check for Domain-Wide Delegation and Impersonation Risks

Identify service accounts with domain-wide delegation and impersonation capabilities.

```bash
# Check for service accounts with domain-wide delegation
# (Requires Admin SDK access to list delegated accounts)
gcloud iam service-accounts list --project=PROJECT_ID --format=json | python3 -c "
import json, sys
accounts = json.load(sys.stdin)
for sa in accounts:
    email = sa.get('email', '')
    # Check if the SA has domain-wide delegation enabled
    # This requires Admin SDK API access
    print(f'SA: {email} - Check admin.google.com for delegation status')
"

# Find service accounts that other identities can impersonate
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  policy=$(gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null)
  if echo "$policy" | python3 -c "
import json, sys
p = json.load(sys.stdin)
for b in p.get('bindings', []):
    if b['role'] in ['roles/iam.serviceAccountTokenCreator', 'roles/iam.serviceAccountUser']:
        print(f'  {b[\"role\"]}: {b[\"members\"]}')
" 2>/dev/null; then
    echo "=== Impersonation risk: $sa ==="
  fi
done
```

### Step 6: Generate Audit Report and Apply Remediation

Compile findings and implement recommended permission reductions.

```bash
# Remove primitive role and replace with predefined role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/editor"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/compute.viewer"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/storage.objectViewer"

# Delete unused service account keys
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL

# Disable unused service accounts
gcloud iam service-accounts disable SA_EMAIL --project=PROJECT_ID
```

## Key Concepts

| Term | Definition |
|------|------------|
| Primitive Role | Legacy GCP roles (Owner, Editor, Viewer) that grant broad permissions across all services, not recommended for production |
| Predefined Role | GCP-managed role scoped to specific services and actions, providing more granular access than primitive roles |
| IAM Recommender | GCP ML-based service that analyzes actual permission usage and suggests role reductions to achieve least privilege |
| Policy Analyzer | Tool for analyzing effective IAM access across the organization hierarchy, answering who-can-access-what queries |
| Service Account Key | User-managed credential for service account authentication, a security risk as keys can be exported and do not auto-expire |
| Domain-Wide Delegation | Grants a service account the ability to impersonate any user in the Google Workspace domain, a significant privilege escalation risk |

## Tools & Systems

- **gcloud CLI**: Primary tool for querying and managing GCP IAM policies, service accounts, and role bindings
- **IAM Recommender**: ML-based recommendation engine for reducing excessive permissions based on actual usage
- **Policy Analyzer**: Organization-wide effective access analysis tool for understanding who can access what
- **Cloud Asset Inventory**: Cross-project search for IAM policies and resource metadata
- **ScoutSuite**: Multi-cloud auditing tool with GCP IAM-specific checks for role assignments and service accounts

## Common Scenarios

### Scenario: Reducing Primitive Role Usage Across a GCP Organization

**Context**: An audit reveals that 60% of IAM bindings across the organization use primitive roles (Owner/Editor). The security team needs to migrate to predefined roles without disrupting developer workflows.

**Approach**:
1. Run `gcloud asset search-all-iam-policies` to inventory all primitive role bindings
2. Use IAM Recommender to get ML-based suggestions for replacement predefined roles
3. For each binding, use Policy Analyzer to understand what the principal actually accesses
4. Create a mapping document: primitive role -> specific predefined roles needed
5. Apply predefined roles alongside primitive roles for a testing period
6. Monitor for access denied errors using Cloud Audit Logs
7. Remove primitive roles after confirming no access issues over 2 weeks

**Pitfalls**: Primitive roles include permissions across all GCP services, so replacing them requires multiple predefined roles. The Recommender may suggest overly restrictive roles if the observation period does not capture all use cases. Custom roles can fill gaps where no predefined role matches the exact permission set needed.

## Output Format

```
GCP IAM Permissions Audit Report
===================================
Organization: acme-org (ORG_ID: 123456789)
Projects Audited: 25
Audit Date: 2026-02-23

IAM BINDING SUMMARY:
  Total bindings:                    342
  Using primitive roles:             205 (60%)
  Using predefined roles:            112 (33%)
  Using custom roles:                 25 (7%)

CRITICAL FINDINGS:
[IAM-001] Service Account with Owner Role
  SA: admin-sa@prod-project.iam.gserviceaccount.com
  Role: roles/owner on project prod-project
  User-Managed Keys: 3 (oldest: 14 months)
  Remediation: Replace with specific predefined roles, delete old keys

[IAM-002] allAuthenticatedUsers Binding
  Resource: gs://public-data-bucket
  Role: roles/storage.objectViewer
  Risk: Any Google account holder can read bucket contents
  Remediation: Restrict to specific user groups or service accounts

SERVICE ACCOUNT HEALTH:
  Total service accounts:            67
  With user-managed keys:            23
  Keys older than 90 days:           18
  Unused accounts (90+ days):        12
  With domain-wide delegation:        2

RECOMMENDER SUGGESTIONS:
  Total recommendations:             45
  Priority HIGH:                     12
  Estimated permissions reduced:     2,847 individual permissions
```
