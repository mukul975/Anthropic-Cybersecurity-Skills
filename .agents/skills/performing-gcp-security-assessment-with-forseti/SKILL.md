---
name: performing-gcp-security-assessment-with-forseti
description: >
  Performing comprehensive security assessments of Google Cloud Platform environments using
  Forseti Security, Security Command Center, and gcloud CLI to audit IAM policies, firewall
  rules, storage permissions, and compliance against CIS GCP Foundations Benchmark.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, gcp, forseti, security-command-center, iam-audit, cis-benchmark]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing GCP Security Assessment with Forseti

## When to Use

- When conducting periodic security assessments of GCP organizations and projects
- When onboarding new GCP projects and establishing security baselines
- When compliance mandates CIS GCP Foundations Benchmark evaluation
- When auditing IAM bindings, firewall rules, and storage ACLs across multiple GCP projects
- When building continuous security monitoring for GCP infrastructure

**Do not use** as a replacement for GCP Security Command Center Premium for real-time threat detection, for application-level vulnerability scanning (use Web Security Scanner), or for GKE-specific security (use GKE Security Posture).

## Prerequisites

- GCP Organization with Organization Admin or Security Admin IAM role
- gcloud CLI authenticated with sufficient permissions (`roles/securitycenter.admin`, `roles/iam.securityReviewer`)
- Security Command Center (SCC) enabled at the organization level
- ScoutSuite installed for multi-cloud comparison (`pip install scoutsuite`)
- Python 3.8+ for custom audit scripts using google-cloud-asset and google-cloud-securitycenter libraries

## Workflow

### Step 1: Enable Security Command Center and Asset Inventory

Enable SCC and set up Cloud Asset Inventory for comprehensive resource visibility.

```bash
# Enable Security Command Center API
gcloud services enable securitycenter.googleapis.com \
  --project=PROJECT_ID

# Enable Cloud Asset API
gcloud services enable cloudasset.googleapis.com \
  --project=PROJECT_ID

# List all assets in the organization
gcloud asset search-all-resources \
  --scope=organizations/ORG_ID \
  --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount" \
  --format="table(name, assetType, location, project)"

# Export asset inventory to BigQuery for analysis
gcloud asset export \
  --organization=ORG_ID \
  --output-bigquery-force \
  --output-bigquery-dataset=projects/PROJECT_ID/datasets/asset_inventory \
  --output-bigquery-table=resources \
  --content-type=resource
```

### Step 2: Audit IAM Policies and Bindings

Review IAM policies across the organization for overly permissive bindings, primitive roles, and service account misuse.

```bash
# List all IAM policy bindings at org level
gcloud organizations get-iam-policy ORG_ID \
  --format=json > org-iam-policy.json

# Find all users with Owner or Editor roles across projects
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner OR policy:roles/editor" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

# Identify service accounts with admin roles
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy.bindings.members:serviceAccount AND policy:roles/owner" \
  --format=json

# Check for allUsers or allAuthenticatedUsers bindings (public access)
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

# List service account keys older than 90 days
gcloud iam service-accounts keys list \
  --iam-account=SA_EMAIL \
  --managed-by=user \
  --format="table(name,validAfterTime,validBeforeTime)"
```

### Step 3: Assess Firewall Rules and Network Configuration

Audit VPC firewall rules for overly permissive ingress rules, missing logging, and network exposure.

```bash
# List all firewall rules allowing ingress from 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, sourceRanges, targetTags)"

# Find firewall rules allowing all protocols/ports
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"

# Check for SSH (22) and RDP (3389) open to internet
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"

# Audit VPC flow log configuration
gcloud compute networks subnets list \
  --format="table(name, region, enableFlowLogs, logConfig.aggregationInterval)"
```

### Step 4: Audit Cloud Storage Bucket Permissions

Check for publicly accessible storage buckets and missing encryption configurations.

```bash
# List all buckets in a project
gsutil ls -p PROJECT_ID

# Check bucket IAM for public access
for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil iam get "$bucket" | grep -E "allUsers|allAuthenticatedUsers" && \
    echo "  WARNING: PUBLIC ACCESS DETECTED" || \
    echo "  OK: No public access"
done

# Check bucket encryption configuration
for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil kms encryption "$bucket" 2>/dev/null || echo "  Using Google-managed encryption"
done

# Check uniform bucket-level access enforcement
for bucket in $(gsutil ls -p PROJECT_ID); do
  gsutil uniformbucketlevelaccess get "$bucket"
done
```

### Step 5: Run ScoutSuite for Comprehensive Assessment

Execute ScoutSuite for an automated multi-check security assessment of the GCP environment.

```bash
# Run ScoutSuite against GCP
python3 -m ScoutSuite gcp \
  --user-account \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report

# Run with service account credentials
python3 -m ScoutSuite gcp \
  --service-account /path/to/service-account-key.json \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report

# Open the HTML report
open ./scoutsuite-gcp-report/gcp-report.html
```

### Step 6: Query Security Command Center Findings

Retrieve and analyze SCC findings for vulnerabilities, misconfigurations, and threats.

```bash
# List active SCC findings
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\"" \
  --format="table(finding.category, finding.severity, finding.resourceName, finding.eventTime)"

# List findings by category
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND category=\"PUBLIC_BUCKET_ACL\"" \
  --format=json

# Get finding statistics grouped by category
gcloud scc findings group ORG_ID \
  --group-by="category" \
  --filter="state=\"ACTIVE\""

# List compliance violations from SCC
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND sourceProperties.compliance_standard=\"CIS\"" \
  --format="table(finding.category, finding.severity, finding.resourceName)"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Command Center | GCP-native security and risk management platform that provides asset inventory, vulnerability detection, and threat monitoring |
| Forseti Security | Open-source GCP security toolkit (now deprecated in favor of SCC) that provided inventory, scanning, enforcement, and notification capabilities |
| Cloud Asset Inventory | GCP service that provides a complete inventory of cloud resources with metadata, IAM policies, and org policy configurations |
| CIS GCP Foundations Benchmark | Security best practice guidelines from Center for Internet Security specific to Google Cloud Platform configuration |
| Uniform Bucket-Level Access | GCP storage setting that disables legacy ACLs and enforces access exclusively through IAM policies for consistent access control |
| Organization Policy | GCP constraint-based governance mechanism that restricts resource configurations across the organization hierarchy |

## Tools & Systems

- **Security Command Center**: GCP-native CSPM providing asset inventory, vulnerability findings, and compliance scoring
- **ScoutSuite**: Multi-cloud security auditing tool with comprehensive GCP checks for IAM, compute, storage, and networking
- **gcloud CLI**: Primary command-line interface for querying GCP resource configurations and security settings
- **Cloud Asset Inventory**: API for searching and exporting resource metadata and IAM policies across GCP projects
- **Forseti Security**: Legacy open-source GCP security toolkit, superseded by SCC but still referenced in compliance frameworks

## Common Scenarios

### Scenario: Assessing a Newly Acquired GCP Organization

**Context**: After a company acquisition, the security team needs to assess the security posture of the acquired company's GCP organization with 30+ projects.

**Approach**:
1. Enable Cloud Asset API and export full resource inventory to BigQuery for analysis
2. Run `gcloud asset search-all-iam-policies` to find all Owner/Editor bindings and public access grants
3. Audit firewall rules across all projects for overly permissive ingress from `0.0.0.0/0`
4. Check all storage buckets for public access using `gsutil iam get`
5. Run ScoutSuite for a comprehensive automated assessment with HTML report
6. Enable SCC and review all CRITICAL and HIGH findings
7. Generate a risk-prioritized remediation roadmap for the integration team

**Pitfalls**: GCP IAM bindings are inherited from organization to folder to project. A permissive binding at the organization level affects all downstream projects. Always audit IAM at every level of the hierarchy, not just at the project level.

## Output Format

```
GCP Security Assessment Report
=================================
Organization: acme-acquired-org (ORG_ID: 123456789)
Projects Assessed: 34
Assessment Date: 2026-02-23
Standards: CIS GCP Foundations 2.0

IAM FINDINGS:
  Users with Owner role at org level:       3
  Service accounts with Editor role:        12
  Resources with allUsers binding:           5
  Service account keys > 90 days:           18

NETWORK FINDINGS:
  Firewall rules allowing 0.0.0.0/0:       14
  SSH open to internet:                      7
  RDP open to internet:                      2
  Subnets without VPC flow logs:            22

STORAGE FINDINGS:
  Publicly accessible buckets:               5
  Buckets without CMEK encryption:          28
  Buckets without uniform access:           15

CRITICAL FINDINGS: 12
HIGH FINDINGS: 34
MEDIUM FINDINGS: 78
LOW FINDINGS: 145

TOP REMEDIATION PRIORITIES:
  1. Remove allUsers bindings from 5 storage buckets (CRITICAL)
  2. Restrict 0.0.0.0/0 firewall rules to specific CIDRs (HIGH)
  3. Rotate 18 service account keys older than 90 days (HIGH)
  4. Enable VPC flow logs on 22 subnets (MEDIUM)
```
