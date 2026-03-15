# Workflows - Vulnerability SLA Breach Alerting

## Workflow 1: SLA Assignment on New Findings

### Trigger
New vulnerability findings imported from scanner.

### Steps
1. Parse incoming vulnerability data (CVE ID, CVSS score, affected asset)
2. Look up asset criticality from CMDB to determine if SLA should be tightened
3. Calculate SLA tier based on CVSS score and asset criticality
4. Compute SLA deadline: `discovered_at + remediation_days`
5. Insert SLA record into tracking database
6. Assign finding owner based on asset ownership mapping
7. Send initial notification to asset owner with SLA deadline

## Workflow 2: Hourly SLA Breach Check

### Trigger
Cron job running every hour.

### Steps
1. Query all open vulnerability SLA records
2. For each record, calculate current SLA status:
   - **within_sla**: Less than 80% of SLA window elapsed
   - **approaching_breach**: 80-100% of SLA window elapsed
   - **breached**: Past SLA deadline
3. For approaching_breach findings (first notification):
   - Send Slack/Teams warning to asset owner
   - Send email notification to asset owner and team lead
4. For breached findings:
   - Send immediate Slack alert to security team channel
   - Trigger PagerDuty incident for critical/high severity
   - Send escalation email to management chain
   - Update escalation_level in database
5. For post-breach findings (already breached, escalation increase):
   - Every 12 hours, increase escalation level
   - Level 1: Team lead notification
   - Level 2: Director notification
   - Level 3: VP/CISO notification

## Workflow 3: Remediation Confirmation

### Trigger
Vulnerability scanner re-scan confirms finding resolved.

### Steps
1. Match resolved finding to SLA record
2. Record remediation timestamp
3. Calculate if remediation was within SLA
4. Update SLA record status to `remediated_within_sla` or `remediated_breach`
5. Close any associated PagerDuty incidents
6. Send confirmation notification to asset owner
7. Update metrics dashboard

## Workflow 4: Monthly SLA Compliance Report

### Trigger
First business day of each month.

### Steps
1. Query all SLA records for the previous month
2. Calculate metrics by severity tier:
   - Total findings per tier
   - SLA compliance rate per tier
   - Mean time to remediate per tier
   - Count of currently overdue findings
3. Identify top 10 assets with most SLA breaches
4. Identify teams with lowest compliance rates
5. Generate HTML report with charts
6. Email report to security leadership
7. Update executive dashboard
