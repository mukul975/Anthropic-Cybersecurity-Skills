---
name: auditing-cloud-with-cis-benchmarks
description: >
  This skill details how to conduct cloud security audits using Center for Internet
  Security benchmarks for AWS, Azure, and GCP. It covers interpreting CIS Foundations
  Benchmark controls, running automated assessments with tools like Prowler and
  ScoutSuite, remediating failed controls, and maintaining continuous compliance
  monitoring against CIS v5 for AWS, v4 for Azure, and v4 for GCP.
domain: cybersecurity
subdomain: cloud-security
tags: [cis-benchmarks, cloud-audit, compliance-assessment, prowler, security-hardening]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Auditing Cloud with CIS Benchmarks

## When to Use

- When performing initial security audits of cloud environments against industry-standard benchmarks
- When preparing for SOC 2, ISO 27001, or regulatory audits that reference CIS controls
- When establishing a measurable security baseline for new cloud accounts or subscriptions
- When tracking compliance improvement over time with periodic reassessment
- When evaluating the security posture of acquired or inherited cloud environments

**Do not use** for runtime threat detection (see detecting-cloud-threats-with-guardduty), for application-level security testing (see conducting-cloud-penetration-testing), or for compliance frameworks not based on CIS (refer to specific regulatory skill files).

## Prerequisites

- Read-only access to target cloud accounts (AWS SecurityAudit policy, Azure Reader role, GCP Viewer role)
- Prowler, ScoutSuite, or cloud-native CSPM tools installed and configured
- Understanding of CIS benchmark structure: sections, controls, profiles (Level 1 and Level 2)
- Remediation access for implementing fixes (separate from audit credentials)

## Workflow

### Step 1: Select Appropriate CIS Benchmark Version

Choose the correct benchmark version for each cloud provider. Current versions as of 2025 include CIS AWS Foundations Benchmark v5.0, CIS Azure Foundations Benchmark v4.0, and CIS GCP Foundations Benchmark v4.0.

```
CIS Benchmark Coverage Areas:
+-------------------+-------------------------+------------------------+
| Section           | AWS v5.0                | Azure v4.0             |
+-------------------+-------------------------+------------------------+
| Identity & Access | IAM policies, MFA, root | Azure AD, RBAC, PIM    |
| Logging           | CloudTrail, Config      | Activity Log, Diag     |
| Monitoring        | CloudWatch alarms       | Defender, Sentinel     |
| Networking        | VPC, SG, NACLs         | NSG, ASG, Firewall     |
| Storage           | S3 encryption, access   | Storage encryption     |
| Database          | RDS encryption          | SQL TDE, auditing      |
+-------------------+-------------------------+------------------------+

CIS Profile Levels:
  Level 1: Practical security settings that can be implemented without significant
           performance impact or reduced functionality
  Level 2: Defense-in-depth settings that may reduce functionality or require
           additional planning for implementation
```

### Step 2: Run Automated Assessment with Prowler

Execute comprehensive CIS benchmark scans using Prowler for automated control evaluation across AWS, Azure, and GCP.

```bash
# AWS CIS v5.0 assessment
prowler aws \
  --compliance cis_5.0_aws \
  --profile audit-account \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-$(date +%Y%m%d)

# Azure CIS v4.0 assessment
prowler azure \
  --compliance cis_4.0_azure \
  --subscription-ids "sub-id-1,sub-id-2" \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-azure-$(date +%Y%m%d)

# GCP CIS v4.0 assessment
prowler gcp \
  --compliance cis_4.0_gcp \
  --project-ids "project-1,project-2" \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-gcp-$(date +%Y%m%d)

# Multi-account AWS scan using ScoutSuite
scout suite aws \
  --profile audit-account \
  --report-dir ./scout-report \
  --ruleset cis-5.0 \
  --force
```

### Step 3: Interpret Results and Prioritize Remediation

Analyze audit results by section and severity. Prioritize Level 1 controls first as they represent fundamental security hygiene, then address Level 2 controls for defense in depth.

```bash
# Parse Prowler results for failed controls
cat ./cis-audit-*/prowler-output-*.json | \
  jq '[.[] | select(.StatusExtended == "FAIL")] | group_by(.CheckID) |
  map({control: .[0].CheckID, description: .[0].CheckTitle,
  failed_resources: length, severity: .[0].Severity}) |
  sort_by(-.failed_resources)'

# Generate compliance score by section
cat ./cis-audit-*/prowler-output-*.json | \
  jq 'group_by(.Section) | map({
    section: .[0].Section,
    total: length,
    passed: [.[] | select(.StatusExtended == "PASS")] | length,
    failed: [.[] | select(.StatusExtended == "FAIL")] | length,
    score: (([.[] | select(.StatusExtended == "PASS")] | length) / length * 100 | round)
  })'
```

### Step 4: Remediate Critical and High Controls

Address failed controls starting with the highest impact items. Use AWS Config remediation, Azure Policy, or Terraform to apply fixes systematically.

```bash
# CIS 1.4: Ensure no root account access key exists
aws iam list-access-keys --user-name root
# If keys exist, delete them
aws iam delete-access-key --user-name root --access-key-id AKIAEXAMPLE

# CIS 2.1.1: Ensure S3 bucket default encryption is enabled
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api put-bucket-encryption --bucket "$bucket" \
    --server-side-encryption-configuration '{
      "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }' 2>/dev/null && echo "Encrypted: $bucket" || echo "FAILED: $bucket"
done

# CIS 3.1: Ensure CloudTrail is enabled in all regions
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name cloudtrail-logs-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/key-id

aws cloudtrail start-logging --name organization-trail

# CIS 4.x: Configure CloudWatch metric filters and alarms
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name UnauthorizedAPICalls \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations metricName=UnauthorizedAPICalls,metricNamespace=CISBenchmark,metricValue=1
```

### Step 5: Establish Continuous Compliance Monitoring

Deploy automated compliance monitoring to detect configuration drift between periodic audits. Use AWS Security Hub, Azure Policy, or GCP Security Command Center.

```bash
# AWS: Enable CIS v5.0 in Security Hub
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0"}
  ]'

# Azure: Assign CIS benchmark policy initiative
az policy assignment create \
  --name cis-azure-benchmark \
  --scope "/subscriptions/<sub-id>" \
  --policy-set-definition "1a5bb27d-173f-493e-9568-eb56638dbd0e" \
  --params '{"effect": {"value": "AuditIfNotExists"}}'

# Schedule periodic Prowler assessments
# Run weekly via cron or CI/CD pipeline
0 2 * * 1 prowler aws --compliance cis_5.0_aws --output-formats csv --output-directory /opt/audits/weekly-$(date +\%Y\%m\%d)
```

## Key Concepts

| Term | Definition |
|------|------------|
| CIS Benchmark | Prescriptive security configuration guidelines developed by the Center for Internet Security through community consensus |
| Level 1 Profile | Practical security controls implementable without significant performance or functionality impact, representing security hygiene |
| Level 2 Profile | Defense-in-depth controls that may restrict functionality and require careful planning before implementation |
| Foundations Benchmark | CIS benchmark specifically for cloud providers covering IAM, logging, monitoring, networking, and storage security |
| Control ID | Unique numerical identifier for each CIS recommendation (e.g., 1.4 for root access key checks, 2.1.1 for S3 encryption) |
| Compliance Score | Percentage of CIS controls in a passing state, tracked over time to measure security posture improvement |
| Automated Assessment | Tool-driven evaluation of CIS controls using cloud provider APIs to check resource configurations against benchmark requirements |
| Remediation Runbook | Documented step-by-step procedure for fixing a specific failed CIS control, including pre-checks and validation |

## Tools & Systems

- **Prowler**: Open-source cloud security tool performing 300+ checks including CIS benchmark assessments for AWS, Azure, and GCP
- **ScoutSuite**: Multi-cloud security auditing tool with CIS benchmark rule sets generating HTML reports
- **AWS Security Hub**: Native AWS service supporting CIS AWS Foundations Benchmark as a security standard
- **Azure Policy**: Governance service with built-in CIS benchmark policy initiatives for automated compliance monitoring
- **GCP Security Command Center**: Native GCP service evaluating configurations against CIS GCP Foundations Benchmark

## Common Scenarios

### Scenario: Pre-Audit CIS Assessment for SOC 2 Certification

**Context**: A SaaS company pursuing SOC 2 Type II certification needs to demonstrate cloud security controls aligned to CIS benchmarks. The auditor requires evidence of continuous compliance monitoring across 45 AWS accounts.

**Approach**:
1. Run Prowler CIS v5.0 assessment across all 45 accounts to establish the baseline compliance score
2. Export results to CSV and categorize failures by section (IAM, Logging, Monitoring, Networking)
3. Map each CIS control to the relevant SOC 2 Trust Services Criteria (CC6.1, CC6.6, CC7.1, etc.)
4. Remediate all Level 1 control failures within 30 days and Level 2 within 60 days
5. Enable CIS v5.0 in AWS Security Hub for continuous monitoring and automated drift detection
6. Generate weekly compliance reports showing improvement trajectory for the auditor
7. Document exceptions for controls intentionally not implemented with risk acceptance justification

**Pitfalls**: Remediating controls without testing in a staging environment first can break production workloads. Ignoring Level 2 controls entirely weakens the audit narrative even if they are not strictly required.

## Output Format

```
CIS Benchmark Audit Report
============================
Cloud Provider: AWS
Benchmark Version: CIS AWS Foundations Benchmark v5.0
Accounts Assessed: 45
Assessment Date: 2025-02-23
Tool: Prowler v4.3.0

OVERALL COMPLIANCE SCORE: 74%

COMPLIANCE BY SECTION:
  1. Identity and Access Management:  68% (41/60 controls passed)
  2. Storage:                         82% (28/34 controls passed)
  3. Logging:                         91% (20/22 controls passed)
  4. Monitoring:                      55% (18/33 controls passed)
  5. Networking:                      78% (32/41 controls passed)

TOP FAILED CONTROLS (by affected accounts):
  [1.4]   Root account has active access keys           - 3/45 accounts
  [1.5]   MFA not enabled for root account              - 2/45 accounts
  [2.1.1] S3 default encryption not enabled             - 12/45 accounts
  [3.1]   CloudTrail not multi-region                   - 8/45 accounts
  [4.3]   No alarm for root account usage               - 28/45 accounts
  [5.1]   VPC flow logs not enabled                     - 15/45 accounts
  [5.4]   Security groups allow 0.0.0.0/0 ingress      - 22/45 accounts

REMEDIATION PRIORITY:
  Critical (Fix within 7 days):  Root access keys, missing root MFA
  High (Fix within 30 days):     S3 encryption, CloudTrail, VPC flow logs
  Medium (Fix within 60 days):   CloudWatch alarms, security group restrictions
  Low (Fix within 90 days):      Level 2 controls, informational items
```
