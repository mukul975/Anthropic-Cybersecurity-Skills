# Workflows - Cloud Vulnerability Posture Management

## Workflow 1: Daily Cloud Posture Assessment
1. Prowler scans all cloud accounts (AWS, Azure, GCP) on daily schedule
2. Results exported as JSON-OCSF and uploaded to central SIEM
3. New critical/high findings trigger Slack notifications
4. Findings compared against previous day for delta analysis
5. New misconfigurations create Jira tickets for cloud team

## Workflow 2: Compliance Baseline Assessment
1. Select compliance framework (CIS, PCI DSS, NIST 800-53, SOC 2)
2. Run Prowler with compliance flag against each cloud account
3. Generate compliance-specific report with pass/fail per control
4. Map failed controls to remediation actions
5. Track compliance posture score over time

## Workflow 3: Remediation and Verification
1. Cloud engineer receives Jira ticket for misconfiguration
2. Engineer applies fix via Terraform/CloudFormation/ARM template
3. Targeted Prowler re-scan validates fix
4. Jira ticket auto-closed on pass
5. Infrastructure-as-code updated to prevent recurrence

## Workflow 4: Multi-Cloud Executive Report
1. Aggregate findings from all providers
2. Calculate posture scores by account, region, and service
3. Trend analysis showing improvement or degradation
4. Risk heat map by cloud service category
5. Present to security leadership monthly
