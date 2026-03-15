# Workflows - AWS Account Enumeration with ScoutSuite

## Standard Security Assessment Workflow

```
1. Preparation Phase
   ├── Define scope (accounts, regions, services)
   ├── Create read-only IAM role with SecurityAudit policy
   ├── Install and configure ScoutSuite
   └── Verify credentials and connectivity

2. Enumeration Phase
   ├── Run ScoutSuite against target AWS account
   ├── Monitor scan progress and address API errors
   ├── Collect results from all specified regions
   └── Generate HTML report

3. Analysis Phase
   ├── Review dashboard for severity distribution
   ├── Prioritize danger-level findings
   ├── Map findings to CIS Benchmarks
   ├── Identify patterns across services
   └── Document false positives

4. Reporting Phase
   ├── Create executive summary of findings
   ├── Detail remediation steps per finding
   ├── Assign priority and ownership
   └── Establish remediation timeline

5. Remediation Phase
   ├── Implement fixes per priority order
   ├── Re-scan to validate remediation
   ├── Update documentation
   └── Schedule recurring assessments
```

## Multi-Account Assessment Workflow

```
1. Setup Organization Scanning
   ├── Create cross-account IAM roles in each target account
   ├── Configure trust relationships to auditor account
   └── Prepare account list and scanning schedule

2. Execute Scans
   ├── Iterate through accounts using assume-role
   ├── Run ScoutSuite per account
   ├── Aggregate results into central location
   └── Generate per-account and aggregate reports

3. Consolidate Findings
   ├── Merge findings across accounts
   ├── Identify organization-wide patterns
   ├── Compare accounts against baseline
   └── Produce organization security scorecard
```

## CI/CD Integration Workflow

```
1. Pipeline Trigger
   ├── Infrastructure change detected (Terraform/CloudFormation)
   └── Scheduled nightly scan

2. Automated Scan
   ├── Run ScoutSuite with targeted service scope
   ├── Parse JSON results programmatically
   └── Evaluate against security baseline

3. Gate Decision
   ├── Danger findings → Block deployment, alert security team
   ├── Warning findings → Proceed with notification
   └── No findings → Continue pipeline
```
