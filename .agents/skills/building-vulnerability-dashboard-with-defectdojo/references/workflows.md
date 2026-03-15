# Workflows - DefectDojo Vulnerability Dashboard

## Workflow 1: Initial Setup and Configuration

### Steps
1. Clone DefectDojo repository and deploy with Docker Compose
2. Configure admin account and change default password
3. Create Product Types aligned with business units
4. Create Products for each application/service
5. Configure Jira integration for ticket management
6. Configure Slack/Teams webhook for notifications
7. Set up SLA policies for each severity level
8. Create API keys for scanner integration

## Workflow 2: CI/CD Scanner Integration

### Steps
1. Add scan step to CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins)
2. Run security scanner (Semgrep, Trivy, ZAP, etc.)
3. Upload scan results to DefectDojo via reimport-scan API
4. DefectDojo deduplicates findings against existing data
5. New findings trigger Jira ticket creation
6. Closed findings auto-close associated Jira tickets
7. Pipeline receives pass/fail status based on finding severity

## Workflow 3: Vulnerability Triage

### Steps
1. Security analyst reviews new findings in DefectDojo dashboard
2. For each finding: verify, assign severity, set risk acceptance status
3. Valid findings: push to Jira for remediation tracking
4. False positives: mark as false positive with justification
5. Risk accepted: document compensating controls and set expiration
6. Track remediation progress through DefectDojo metrics

## Workflow 4: Executive Reporting

### Steps
1. Pull metrics via DefectDojo API for reporting period
2. Calculate: total findings, new vs closed, SLA compliance rate
3. Generate product-level and business-unit-level summaries
4. Track mean time to remediate by severity
5. Export dashboard data for executive presentation
