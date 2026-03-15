---
name: building-cloud-security-posture-management
description: >
  This skill guides security architects through designing and implementing a cloud
  security posture management program that continuously monitors infrastructure
  configurations across AWS, Azure, and GCP. It covers selecting CSPM tooling such
  as Wiz, Prisma Cloud, or native services, defining policy baselines, automating
  drift detection, and integrating posture findings into SOC workflows.
domain: cybersecurity
subdomain: cloud-security
tags: [cspm, cloud-misconfiguration, security-posture, drift-detection, multi-cloud-governance]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Building Cloud Security Posture Management

## When to Use

- When an organization lacks visibility into cloud misconfigurations across multiple accounts and providers
- When compliance requirements demand continuous posture monitoring against CIS, NIST, or SOC 2 frameworks
- When security teams need to prioritize which misconfigurations to remediate based on actual risk
- When migrating workloads to the cloud and establishing security baselines before production deployment
- When integrating cloud posture findings into an existing SOC or SIEM platform

**Do not use** for runtime threat detection (see detecting-cloud-threats-with-guardduty), for application-level vulnerability scanning (see securing-serverless-functions), or for network traffic analysis (see implementing-cloud-network-segmentation).

## Prerequisites

- Cloud accounts across target providers (AWS, Azure, GCP) with read-only API access for CSPM tools
- Defined compliance framework requirements (CIS Benchmarks, NIST 800-53, PCI-DSS, SOC 2)
- SIEM or ticketing system for finding ingestion and workflow management
- Budget allocation for commercial CSPM tooling or engineering capacity for native tool integration

## Workflow

### Step 1: Assess Current Cloud Estate and Risk Appetite

Inventory all cloud accounts, subscriptions, and projects. Classify them by data sensitivity, regulatory requirements, and business criticality to determine CSPM coverage scope.

```
Cloud Estate Inventory:
+----------------+----------+------------+--------------------+------------------+
| Provider       | Accounts | Workloads  | Data Classification| Compliance Needs |
+----------------+----------+------------+--------------------+------------------+
| AWS            | 45       | Production | Confidential       | PCI-DSS, SOC 2   |
| AWS            | 12       | Dev/Test   | Internal           | SOC 2            |
| Azure          | 8        | Production | Restricted (PII)   | GDPR, SOC 2      |
| GCP            | 3        | Analytics  | Confidential       | SOC 2            |
+----------------+----------+------------+--------------------+------------------+
```

### Step 2: Select and Deploy CSPM Tooling

Evaluate CSPM solutions based on multi-cloud support, policy coverage, agentless scanning, attack path analysis, and integration capabilities.

**Native Tools:**
- AWS Security Hub CSPM with Config rules
- Microsoft Defender for Cloud CSPM
- Google Security Command Center Premium

**Commercial Platforms:**
- Wiz: Agentless, graph-based visibility, attack path analysis, highest market mindshare (20.2%)
- Prisma Cloud (now Cortex Cloud): CSPM + CWP + CIEM, 3,000+ built-in policies
- Orca Security: SideScanning technology, agentless full-stack visibility
- Lacework: Anomaly-based detection with behavioral analysis

```bash
# Example: Deploy Wiz connector for AWS using CloudFormation
aws cloudformation create-stack \
  --stack-name wiz-connector \
  --template-url https://wiz-advanced-security.s3.amazonaws.com/wiz-aws-connector.yaml \
  --parameters ParameterKey=ExternalId,ParameterValue=<wiz-external-id> \
  --capabilities CAPABILITY_NAMED_IAM

# Example: Configure Prisma Cloud AWS onboarding
# Prisma Cloud uses a cross-account IAM role for read-only access
aws iam create-role \
  --role-name PrismaCloudReadOnly \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::188619942792:root"},
      "Action": "sts:AssumeRole",
      "Condition": {"StringEquals": {"sts:ExternalId": "<prisma-external-id>"}}
    }]
  }'
```

### Step 3: Define Policy Baselines and Custom Rules

Map compliance framework controls to CSPM policies. Create custom rules for organization-specific requirements that go beyond standard benchmarks.

```yaml
# Example custom CSPM policy definitions
policies:
  - name: s3-bucket-encryption-required
    description: All S3 buckets must have AES-256 or KMS encryption enabled
    provider: aws
    resource_type: aws_s3_bucket
    severity: HIGH
    rule: |
      resource.encryption.rules[0].apply_server_side_encryption_by_default.sse_algorithm
      in ["aws:kms", "AES256"]
    remediation: Enable default encryption on the S3 bucket using AES-256 or AWS KMS
    compliance_mapping:
      - CIS_AWS_v5.0: "2.1.1"
      - PCI_DSS: "3.4"
      - SOC2: "CC6.1"

  - name: public-ip-not-attached-to-compute
    description: Production compute instances must not have public IP addresses
    provider: aws
    resource_type: aws_ec2_instance
    severity: CRITICAL
    rule: |
      resource.public_ip_address == null AND
      resource.tags["Environment"] == "production"
    remediation: Remove public IP and route traffic through a load balancer or NAT gateway

  - name: storage-account-private-endpoint
    description: Azure storage accounts must use private endpoints only
    provider: azure
    resource_type: azurerm_storage_account
    severity: HIGH
    rule: |
      resource.network_rules.default_action == "Deny" AND
      resource.private_endpoint_connections.length > 0
```

### Step 4: Automate Drift Detection and Alerting

Configure continuous scanning intervals, drift detection thresholds, and alert routing to ensure new misconfigurations are detected within minutes of resource creation or modification.

```bash
# AWS Config rule for drift detection on S3 public access
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    },
    "Scope": {"ComplianceResourceTypes": ["AWS::S3::Bucket"]}
  }'

# Auto-remediation using SSM Automation
aws configservice put-remediation-configurations \
  --remediation-configurations '[{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "TargetType": "SSM_DOCUMENT",
    "TargetId": "AWS-DisableS3BucketPublicReadWrite",
    "Automatic": true,
    "MaximumAutomaticAttempts": 3,
    "RetryAttemptSeconds": 60
  }]'
```

### Step 5: Prioritize Findings with Context-Aware Risk Scoring

Move beyond severity-only prioritization. Use attack path analysis, asset context, and exploitability data to focus remediation on findings that represent actual risk.

```
Risk Prioritization Matrix:
+----------------------------+----------+-----------+--------+-------------+
| Finding                    | Severity | Exposed   | Attack | Priority    |
|                            |          | Internet? | Path?  | Score       |
+----------------------------+----------+-----------+--------+-------------+
| S3 bucket public read      | HIGH     | Yes       | Yes    | CRITICAL    |
| RDS no encryption at rest  | HIGH     | No        | No     | MEDIUM      |
| SG allows 0.0.0.0/0:22    | HIGH     | Yes       | Yes    | CRITICAL    |
| CloudTrail not enabled     | MEDIUM   | No        | No     | HIGH        |
| EBS volume not encrypted   | MEDIUM   | No        | No     | LOW         |
+----------------------------+----------+-----------+--------+-------------+
```

### Step 6: Integrate with SOC Workflows and Reporting

Feed CSPM findings into SIEM platforms, create Jira tickets for remediation tracking, and build executive dashboards for posture trending.

```bash
# Export findings to Amazon Security Lake in OCSF format
aws securitylake create-subscriber \
  --subscriber-name cspm-siem-integration \
  --sources '[{"awsLogSource": {"sourceName": "SH_FINDINGS"}}]' \
  --subscriber-identity '{"principal": "arn:aws:iam::123456789012:role/SIEMIngestionRole", "externalId": "siem-ext-id"}'
```

## Key Concepts

| Term | Definition |
|------|------------|
| CSPM | Cloud Security Posture Management: continuous monitoring service that identifies cloud infrastructure misconfigurations and compliance violations |
| Configuration Drift | Deviation from a defined security baseline that occurs when resources are modified outside of approved change management processes |
| Attack Path | A multi-step chain of misconfigurations and vulnerabilities that an adversary could exploit to move from an entry point to a critical asset |
| Agentless Scanning | CSPM approach that uses cloud provider APIs and snapshot analysis to assess security posture without installing agents on workloads |
| Policy as Code | Defining security policies in machine-readable formats (Rego, YAML, JSON) that can be version-controlled and automatically enforced |
| Compliance Framework | Structured set of security controls and requirements such as CIS Benchmarks, NIST 800-53, PCI-DSS, or SOC 2 used to measure posture |
| Security Graph | Graph database representing relationships between cloud resources, identities, network paths, and vulnerabilities for contextual risk analysis |

## Tools & Systems

- **Wiz**: Agentless CNAPP providing graph-based CSPM, attack path analysis, and vulnerability management across all major cloud providers
- **Prisma Cloud / Cortex Cloud**: Palo Alto Networks CNAPP with 3,000+ built-in policies covering CSPM, CWP, CIEM, and IaC security
- **AWS Security Hub CSPM**: Native AWS posture management with automated checks against CIS v5.0 and AWS Foundational Security Best Practices
- **Prowler**: Open-source AWS/Azure/GCP security assessment tool with 300+ checks and CIS benchmark support
- **Steampipe**: Open-source SQL-based cloud configuration querying tool supporting 140+ plugins for multi-cloud posture queries

## Common Scenarios

### Scenario: Post-Acquisition Cloud Posture Assessment

**Context**: A company acquires a startup with 30 AWS accounts and 5 GCP projects. No CSPM tooling is in place and the security team needs to assess the inherited environment within two weeks.

**Approach**:
1. Deploy an agentless CSPM tool (Wiz or Orca) using read-only cross-account roles for immediate visibility without agent installation
2. Run initial scans against CIS Benchmarks for both AWS and GCP to establish a baseline posture score
3. Identify Critical findings: publicly exposed databases, unencrypted storage with sensitive data, overprivileged service accounts
4. Prioritize attack paths that connect internet-exposed resources to data stores containing customer PII
5. Deliver an executive summary with risk-ranked findings and a 90-day remediation roadmap
6. Integrate the acquired accounts into the existing CSPM platform with continuous monitoring

**Pitfalls**: Deploying agents for the initial assessment adds weeks of delay. Using only native tools for a multi-cloud assessment creates separate dashboards and makes cross-cloud comparison difficult.

## Output Format

```
Cloud Security Posture Assessment Report
==========================================
Organization: Acme Corp
Cloud Providers: AWS (57 accounts), Azure (8 subscriptions), GCP (3 projects)
CSPM Platform: Wiz
Assessment Date: 2025-02-23

OVERALL POSTURE SCORE: 68/100

FINDINGS BY SEVERITY:
  Critical: 47   (Internet-exposed + data access risk)
  High: 234      (Misconfiguration with limited exposure)
  Medium: 891    (Non-compliant but low immediate risk)
  Low: 1,567     (Informational or best practice)

TOP ATTACK PATHS:
  1. Internet -> Public S3 Bucket (PII data) -> No encryption
     Affected: 3 accounts | Risk: Critical | ETA to remediate: 1 day
  2. Internet -> EC2 (SSH open) -> IAM Role -> Cross-Account Admin
     Affected: 1 account | Risk: Critical | ETA to remediate: 2 days
  3. Internet -> Azure App Service -> SQL Server (public endpoint)
     Affected: 2 subscriptions | Risk: Critical | ETA to remediate: 3 days

COMPLIANCE STATUS:
  CIS AWS v5.0:         62% compliant (340/548 controls passing)
  CIS Azure v4.0:       71% compliant (189/266 controls passing)
  CIS GCP v4.0:         58% compliant (87/150 controls passing)
  SOC 2 Type II:        74% controls mapped and passing
```
