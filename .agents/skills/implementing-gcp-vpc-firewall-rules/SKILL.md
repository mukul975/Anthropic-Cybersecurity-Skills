---
name: implementing-gcp-vpc-firewall-rules
description: >
  Implementing and auditing GCP VPC firewall rules to enforce network segmentation,
  restrict ingress and egress traffic, apply hierarchical firewall policies across
  the organization, and monitor firewall rule effectiveness using VPC Flow Logs.
domain: cybersecurity
subdomain: cloud-security
tags: [cloud-security, gcp, vpc, firewall-rules, network-security, segmentation]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing GCP VPC Firewall Rules

## When to Use

- When deploying new GCP workloads that require network-level access controls
- When auditing existing firewall configurations for overly permissive rules
- When implementing zero trust network segmentation within GCP VPC networks
- When responding to Security Command Center findings about open firewall rules
- When building hierarchical firewall policies across a GCP organization

**Do not use** for application-layer filtering (use Cloud Armor WAF), for DNS-based filtering (use Cloud DNS response policies), or for VPN/interconnect traffic filtering without understanding that VPC firewall rules apply to traffic within the VPC.

## Prerequisites

- GCP project with Compute Engine API enabled
- IAM roles: `roles/compute.securityAdmin` for firewall management, `roles/compute.networkViewer` for auditing
- Organization Admin role for hierarchical firewall policies
- gcloud CLI authenticated with appropriate permissions
- VPC Flow Logs enabled on target subnets for monitoring

## Workflow

### Step 1: Audit Existing Firewall Rules for Security Gaps

Enumerate all firewall rules and identify overly permissive configurations.

```bash
# List all firewall rules in the project
gcloud compute firewall-rules list \
  --format="table(name, network, direction, priority, allowed[].map().firewall_rule().list():label=ALLOWED, sourceRanges, targetTags)"

# Find rules allowing all traffic from 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, priority, targetTags)" \
  --sort-by=priority

# Find rules allowing all protocols and ports
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"

# Find rules with SSH (22) or RDP (3389) open to the internet
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"

# Check for disabled rules
gcloud compute firewall-rules list \
  --filter="disabled=true" \
  --format="table(name, network, direction)"
```

### Step 2: Create Restrictive Ingress Firewall Rules

Implement least-privilege ingress rules using network tags and service accounts for targeting.

```bash
# Create rule allowing HTTPS from the internet to web servers only
gcloud compute firewall-rules create allow-https-web \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=web-server \
  --priority=1000 \
  --description="Allow HTTPS to web servers from internet"

# Create rule allowing SSH only from bastion host subnet
gcloud compute firewall-rules create allow-ssh-bastion \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=10.0.1.0/24 \
  --target-tags=ssh-allowed \
  --priority=1000 \
  --description="Allow SSH only from bastion subnet"

# Create rule allowing internal communication between app tiers
gcloud compute firewall-rules create allow-app-to-db \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-tags=app-server \
  --target-tags=db-server \
  --priority=1000 \
  --description="Allow PostgreSQL from app tier to database tier"

# Create service-account-based rule (more secure than tags)
gcloud compute firewall-rules create allow-api-internal \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-service-accounts=api-client@project.iam.gserviceaccount.com \
  --target-service-accounts=api-server@project.iam.gserviceaccount.com \
  --priority=1000
```

### Step 3: Implement Egress Restrictions

Configure egress firewall rules to control outbound traffic and prevent data exfiltration.

```bash
# Deny all egress by default (low priority)
gcloud compute firewall-rules create deny-all-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=DENY \
  --rules=all \
  --destination-ranges=0.0.0.0/0 \
  --priority=65534 \
  --description="Default deny all egress traffic"

# Allow egress to Google APIs via restricted VIP
gcloud compute firewall-rules create allow-google-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=199.36.153.4/30 \
  --priority=1000 \
  --description="Allow HTTPS to Google APIs restricted VIP"

# Allow DNS resolution
gcloud compute firewall-rules create allow-dns-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=udp:53,tcp:53 \
  --destination-ranges=169.254.169.254/32,8.8.8.8/32,8.8.4.4/32 \
  --priority=1000 \
  --description="Allow DNS resolution to metadata and Google DNS"

# Allow egress to specific external services
gcloud compute firewall-rules create allow-external-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=PARTNER_CIDR/32 \
  --target-tags=api-client \
  --priority=1000
```

### Step 4: Deploy Hierarchical Firewall Policies

Create organization and folder-level firewall policies that apply across all projects.

```bash
# Create an organization-level firewall policy
gcloud compute firewall-policies create \
  --organization=ORG_ID \
  --short-name=org-security-policy \
  --description="Organization-wide security firewall policy"

# Add rule to block known malicious IP ranges at org level
gcloud compute firewall-policies rules create 100 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=deny \
  --src-ip-ranges=THREAT_INTEL_CIDR_1,THREAT_INTEL_CIDR_2 \
  --layer4-configs=all \
  --description="Block known malicious IPs organization-wide"

# Add rule to enforce HTTPS-only ingress at org level
gcloud compute firewall-policies rules create 200 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=allow \
  --src-ip-ranges=0.0.0.0/0 \
  --layer4-configs=tcp:443 \
  --description="Allow only HTTPS from external sources"

# Associate policy with the organization
gcloud compute firewall-policies associations create \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID
```

### Step 5: Enable VPC Flow Logs for Monitoring

Configure VPC Flow Logs to monitor traffic patterns and validate firewall rule effectiveness.

```bash
# Enable flow logs on a subnet
gcloud compute networks subnets update production-subnet \
  --region=us-central1 \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0 \
  --logging-metadata=include-all

# Query flow logs in Cloud Logging for denied traffic
gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.disposition="DENIED"
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=50 --format=json

# Find traffic hitting overly permissive rules
gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.rule_details.reference:"/firewall-rules/default-allow-"
' --limit=100 --format="table(jsonPayload.connection.src_ip,jsonPayload.connection.dest_ip,jsonPayload.connection.dest_port)"

# Export flow logs to BigQuery for analysis
gcloud logging sinks create vpc-flow-bq \
  bigquery.googleapis.com/projects/PROJECT/datasets/vpc_flow_logs \
  --log-filter='resource.type="gce_subnetwork"'
```

## Key Concepts

| Term | Definition |
|------|------------|
| VPC Firewall Rule | Stateful network-level access control that allows or denies traffic to and from VM instances based on IP ranges, protocols, ports, and tags |
| Hierarchical Firewall Policy | Organization or folder-level firewall policy that is evaluated before VPC-level rules and applies across all child projects |
| Network Tag | Label applied to VM instances that determines which firewall rules apply, used for targeting ingress and egress rules |
| Service Account Firewall Rule | Firewall rule that targets instances based on their attached service account, providing more secure targeting than mutable network tags |
| VPC Flow Logs | Network telemetry captured at the subnet level that records traffic metadata for monitoring, forensics, and firewall rule validation |
| Implied Rules | Default GCP firewall rules that allow egress to all destinations and deny ingress from all sources, with lowest priority (65535) |

## Tools & Systems

- **gcloud compute firewall-rules**: CLI commands for creating, listing, and managing VPC firewall rules in GCP
- **Hierarchical Firewall Policies**: Organization and folder-level policies enforcing security controls across all projects
- **VPC Flow Logs**: Subnet-level traffic logging for monitoring, troubleshooting, and validating firewall effectiveness
- **Cloud Logging**: Query engine for analyzing VPC Flow Logs and firewall rule hit counts
- **Security Command Center**: GCP-native security platform with findings for overly permissive firewall configurations

## Common Scenarios

### Scenario: Locking Down a Production VPC After Discovery of Overly Permissive Rules

**Context**: A security audit reveals that the production VPC has default-allow rules permitting SSH from `0.0.0.0/0` and unrestricted egress. SCC reports 14 firewall findings.

**Approach**:
1. Enumerate all existing rules with `gcloud compute firewall-rules list` and categorize by risk
2. Enable VPC Flow Logs on all subnets to capture baseline traffic patterns for 7 days
3. Analyze flow logs to identify legitimate traffic that needs explicit allow rules
4. Create targeted ingress rules for each application tier (web: 443, app: 8080, db: 5432)
5. Replace the SSH-from-anywhere rule with SSH-from-bastion-subnet-only
6. Implement default-deny egress and add explicit allow rules for required outbound destinations
7. Delete the overly permissive default-allow rules after verifying applications function correctly

**Pitfalls**: Deleting firewall rules without understanding traffic patterns causes outages. Always enable flow logs and analyze traffic before removing rules. Network tags can be added by anyone with compute.instances.setTags permission, making them less secure than service-account-based targeting for critical rules.

## Output Format

```
GCP VPC Firewall Audit Report
================================
Project: production-project
VPC Network: production-vpc
Audit Date: 2026-02-23

RULE INVENTORY:
  Total firewall rules: 34
  Ingress rules: 22
  Egress rules: 12
  Disabled rules: 3

CRITICAL FINDINGS:
[FW-001] SSH Open to Internet
  Rule: default-allow-ssh
  Source: 0.0.0.0/0 -> tcp:22
  Target: All instances (no tags)
  Priority: 65534
  Remediation: Restrict to bastion subnet CIDR

[FW-002] No Egress Restrictions
  Issue: Only implied allow-all-egress rule exists
  Risk: No controls on outbound data exfiltration
  Remediation: Add default-deny egress and explicit allow rules

REMEDIATION ACTIONS COMPLETED:
  Rules deleted: 3 (overly permissive defaults)
  Rules created: 8 (targeted allow rules)
  Egress deny rule: Created at priority 65534
  Flow logs enabled: 6 subnets
```
