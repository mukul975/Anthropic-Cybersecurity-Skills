---
name: implementing-security-monitoring-with-datadog
description: 'Implements security monitoring using Datadog Cloud SIEM, Cloud Security
  Management (CSM), and Workload Protection to detect threats, enforce compliance,
  and respond to security events across cloud and hybrid infrastructure. Covers Agent
  deployment, log source ingestion, detection rule creation, security dashboards,
  and automated notification workflows. Activates for requests involving Datadog security
  setup, Cloud SIEM configuration, CSM threat detection, or security monitoring dashboards.

  '
domain: cybersecurity
subdomain: security-operations
tags:
- siem
- security-monitoring
- datadog
- cloud-security
- log-analysis
- detection-rules
- CSM
- workload-protection
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.7
- MANAGE-3.1
- GOVERN-4.2
- MAP-2.3
d3fend_techniques:
- Restore Access
- Password Authentication
- Biometric Authentication
- Strong Password Policy
- Restore User Account Access
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
mitre_attack:
- T1078
- T1190
- T1059
- T1685.002
- T1685.005
---

# Implementing Security Monitoring with Datadog

## When to Use

- Deploying Cloud SIEM to detect real-time threats across cloud infrastructure (AWS, Azure, GCP)
- Creating custom detection rules for attacker techniques, credential abuse, or anomalous behavior
- Enabling Workload Protection (CSM Threats) to monitor file, process, and network activity on hosts and containers
- Meeting compliance requirements (PCI-DSS, SOC 2, HIPAA) that mandate centralized log monitoring and alerting
- Building security dashboards to provide SOC visibility into threat signals, investigation context, and response metrics

**Do not use** for endpoint-only monitoring without cloud infrastructure; use a dedicated EDR solution for purely on-premises endpoint detection.

## Prerequisites

- Datadog account with Security Monitoring (Cloud SIEM) and/or Cloud Security Management enabled
- Datadog API Key and Application Key from Organization Settings > API Keys
- Datadog Agent v7+ installed on hosts/containers that generate security-relevant logs
- Log sources configured for ingestion: AWS CloudTrail, VPC Flow Logs, GuardDuty, Azure Activity Logs, GCP Audit Logs, or on-host logs (auth.log, syslog, Windows Security Events)
- Python 3.9+ with `datadog-api-client` library for programmatic rule management
- Network access from monitored hosts to Datadog intake endpoints (port 443)

## Workflow

### Step 1: Deploy and Configure the Datadog Agent for Security

Install the Datadog Agent and enable security-related features in `datadog.yaml`:

```yaml
# /etc/datadog-agent/datadog.yaml

api_key: <YOUR_DATADOG_API_KEY>
site: datadoghq.com   # or datadoghq.eu, us3.datadoghq.com, etc.

# Enable log collection for Cloud SIEM
logs_enabled: true

# Enable security features
runtime_security_config:
  enabled: true          # Workload Protection (CSM Threats)
  activity_dump:
    enabled: true        # Record process activity for investigation

compliance_config:
  enabled: true          # CIS benchmark checks (CSM Misconfigurations)
  host_benchmarks:
    enabled: true
```

Configure log sources for security-relevant files on Linux:

```yaml
# /etc/datadog-agent/conf.d/auth.d/conf.yaml
logs:
  - type: file
    path: /var/log/auth.log
    source: auth
    service: linux-auth
    tags:
      - env:production
      - security:authentication

  - type: file
    path: /var/log/syslog
    source: syslog
    service: linux-syslog
```

For Windows Security Event Logs:

```yaml
# /etc/datadog-agent/conf.d/win32_event_log.d/conf.yaml
logs:
  - type: windows_event
    channel_path: Security
    source: windows.events
    service: windows-security
    filters:
      - id: [4624, 4625, 4648, 4672, 4688, 4720, 4726, 4740, 4767]
```

Enable the system-probe for Workload Protection (CSM Threats):

```yaml
# /etc/datadog-agent/system-probe.yaml
runtime_security_config:
  enabled: true
  fim_enabled: true        # File Integrity Monitoring
  network_enabled: true    # Network activity monitoring
```

Restart the Agent after configuration changes:

```bash
sudo systemctl restart datadog-agent
sudo datadog-agent status | grep -A5 "Security Agent"
```

### Step 2: Configure Cloud Log Sources for SIEM

Set up AWS CloudTrail, VPC Flow Logs, and GuardDuty ingestion for Cloud SIEM:

```
Datadog App > Security > Cloud SIEM > Configuration > Content Packs

AWS Content Pack:
  1. Enable the AWS integration in Datadog (Integrations > Amazon Web Services)
  2. Configure CloudTrail log forwarding via the Datadog Forwarder Lambda
  3. Enable VPC Flow Logs forwarding to Datadog
  4. Enable GuardDuty findings forwarding

Required IAM permissions for the Datadog role:
  - cloudtrail:LookupEvents
  - logs:FilterLogEvents
  - guardduty:ListDetectors, guardduty:GetFindings
  - s3:GetObject (for CloudTrail S3 bucket)

Azure Content Pack:
  1. Configure Azure Activity Logs via Event Hub to Datadog
  2. Forward Azure AD Sign-in Logs and Audit Logs
  3. Enable Microsoft Defender for Cloud alerts forwarding

GCP Content Pack:
  1. Configure GCP Audit Logs export via Pub/Sub to Datadog
  2. Forward Cloud Audit Logs (Admin Activity, Data Access)
```

Verify log ingestion is working:

```
Datadog App > Logs > Search
  Filter: source:(cloudtrail OR aws.guardduty OR azure.activitylogs)
  Verify: Logs appearing with correct source tags and parsed attributes
```

### Step 3: Enable and Customize Detection Rules

Datadog provides out-of-the-box detection rules that are automatically imported. Review and customize them:

```
Datadog App > Security > Detection Rules

Out-of-the-box rule categories:
  - AWS: IAM policy changes, root account usage, S3 public access
  - Azure: Suspicious sign-ins, resource group deletions
  - GCP: IAM policy modifications, firewall rule changes
  - Authentication: Brute force, impossible travel, credential stuffing
  - Network: Port scanning, DNS tunneling, C2 beaconing
  - Application: SQL injection attempts, XSS, SSRF patterns
```

Create a custom detection rule for brute force login detection:

```
Datadog App > Security > Detection Rules > New Rule

Rule Name: "Brute Force Login Detection - Custom"
Rule Type: Log Detection (Real-time)

Define Search Query:
  source:auth status:error @evt.name:authentication @evt.outcome:failure
  Group By: @usr.id

Set Rule Cases:
  Case 1: When count > 10 in 5 minutes
    Name: "High volume failed logins"
    Severity: HIGH
    Notification: @slack-security-alerts @pagerduty-soc

  Case 2: When count > 50 in 5 minutes
    Name: "Extreme brute force attempt"
    Severity: CRITICAL
    Notification: @slack-security-alerts @pagerduty-soc-critical

Signal Settings:
  Keep signal alive for: 10 minutes
  Maximum signal duration: 24 hours
  Evaluation window: 5 minutes
```

Create a detection rule for AWS root account usage:

```
Rule Name: "AWS Root Account Console Login"
Rule Type: Log Detection

Query:
  source:cloudtrail @evt.name:ConsoleLogin @userIdentity.type:Root

Severity: CRITICAL
Notification Message:
  "AWS Root account console login detected from IP {{@network.client.ip}}.
   Account: {{@usr.account_id}}
   Region: {{@cloud.region}}
   MFA Used: {{@additionalEventData.MFAUsed}}"

Tags: attack:initial-access, mitre:T1078
```

### Step 4: Configure Workload Protection (CSM Threats)

Set up runtime threat detection for hosts and containers:

```
Datadog App > Security > Cloud Security Management > Setup

Enable Workload Protection:
  1. Verify Agent has runtime_security_config.enabled: true
  2. Review default Agent rules (file integrity, process execution)
  3. Customize rules for your environment

Default detection categories:
  - Process Execution: Detect reverse shells, crypto miners, exploitation tools
  - File Integrity: Monitor changes to /etc/passwd, /etc/shadow, SSH keys
  - Network Activity: Detect unexpected outbound connections, DNS tunneling
  - Container Escape: Detect privileged container breakout attempts
  - Kernel Module: Detect rootkit or unauthorized kernel module loading
```

Create a custom CSM Threats Agent rule to detect unauthorized SSH key modifications:

```
Datadog App > Security > CSM > Agent Rules > New Agent Rule

Rule Expression:
  open.file.path == "/root/.ssh/authorized_keys" &&
  open.flags & (O_WRONLY | O_RDWR | O_CREAT) > 0 &&
  process.file.name != "sshd"

Rule Name: ssh_key_modification
Description: Detect non-sshd processes modifying root authorized_keys
Tags: attack:persistence, mitre:T1098.004
```

### Step 5: Build Security Dashboards

Create a Cloud SIEM overview dashboard:

```
Datadog App > Dashboards > New Dashboard > "Security Operations Overview"

Widgets:
  1. Signal Count Over Time (timeseries)
     Query: count:security_signal by {signal.rule.name}
     Display: Line chart, last 24 hours

  2. Top Triggered Rules (top list)
     Query: count:security_signal by {signal.rule.name}.as_count()
     Display: Top 10

  3. Critical Signals (query value)
     Query: count:security_signal{severity:critical}
     Conditional format: Red if > 0

  4. Signals by Source (pie chart)
     Query: count:security_signal by {source}

  5. Geographic Threat Map (geomap)
     Query: count:security_signal by {network.client.geoip.country.name}

  6. Top Targeted Users (top list)
     Query: count:security_signal by {usr.id}

  7. Mean Time to Triage (query value)
     Query: avg:security_signal.triage_time

  8. Open Signals by Severity (table)
     Query: count:security_signal{status:open} by {severity}
```

### Step 6: Configure Notification Workflows

Set up automated notification and response workflows:

```
Datadog App > Security > Notification Rules

Rule 1: Critical Signal Escalation
  Condition: severity:critical
  Recipients: @pagerduty-soc-critical @slack-security-incidents
  Message: "CRITICAL security signal: {{signal.rule.name}}
            Source: {{signal.attributes.network.client.ip}}
            Target: {{signal.attributes.usr.id}}
            Details: {{signal.message}}"

Rule 2: High Signal SOC Alert
  Condition: severity:high
  Recipients: @slack-security-alerts
  Suppress: After first notification, suppress for 15 minutes

Rule 3: Compliance Violation
  Condition: rule_type:compliance
  Recipients: @slack-compliance-team @jira-compliance-board

Workflow Automation (Datadog Workflows):
  Trigger: Security signal with severity:critical
  Steps:
    1. Enrich signal with threat intelligence lookup
    2. Create Jira incident ticket
    3. Send Slack notification with investigation context
    4. If source is AWS: Trigger Lambda to isolate resource
```

### Step 7: Validate and Tune Detection Coverage

Test detection rules and tune false positives:

```bash
# Generate a test security event (failed SSH login)
ssh -o StrictHostKeyChecking=no invalid_user@localhost 2>/dev/null

# Verify the event appears in Datadog Logs
# Datadog App > Logs > source:auth status:error

# Check that a security signal was generated
# Datadog App > Security > Signals > Filter by rule name

# Tune noisy rules by adding suppression queries:
# Datadog App > Security > Detection Rules > [Rule] > Edit
# Add suppression: Suppress signal when @usr.id:service-account-*
```

Use the Security Signals API to validate programmatically:

```python
from datadog_api_client import Configuration, ApiClient
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi

configuration = Configuration()
# Reads DD_API_KEY and DD_APP_KEY from environment

with ApiClient(configuration) as api_client:
    api = SecurityMonitoringApi(api_client)
    signals = api.search_security_monitoring_signals(
        body={
            "filter": {
                "query": "status:open severity:critical",
                "from": "now-24h",
                "to": "now",
            },
            "sort": {"field": "timestamp", "order": "desc"},
            "page": {"limit": 25},
        }
    )
    for signal in signals.data:
        attrs = signal.attributes
        print(f"[{attrs.severity}] {attrs.title}")
        print(f"  Rule: {attrs.custom.get('rule', {}).get('name', 'N/A')}")
        print(f"  Time: {attrs.timestamp}")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Cloud SIEM** | Datadog's security information and event management service that analyzes ingested logs in real-time to detect threats using detection rules |
| **Security Signal** | An alert generated when a detection rule matches incoming log data; signals have severity, status (open/triage/closed), and investigation context |
| **Detection Rule** | A query-based rule that evaluates logs or events against conditions (threshold, anomaly, new value, impossible travel) to generate security signals |
| **CSM (Cloud Security Management)** | Datadog platform for infrastructure security including Misconfigurations (compliance benchmarks), Threats (runtime detection), and Vulnerabilities |
| **Workload Protection** | CSM Threats component that monitors file, process, and network activity on hosts and containers using eBPF-based Agent rules |
| **Content Pack** | Pre-built collection of detection rules, dashboards, and log parsers for a specific integration (AWS, Azure, GCP, Okta, etc.) |
| **Agent Rule** | A kernel-level rule evaluated by the Datadog Agent on the host to collect security-relevant events before sending to Datadog for threat detection |
| **Suppression Query** | A filter applied to a detection rule to prevent signals from being generated for known-good activity (reduces false positives) |

## Verification

- [ ] Datadog Agent is installed and reporting on all target hosts (`datadog-agent status` shows security agent running)
- [ ] Security-relevant log sources are ingesting into Datadog (CloudTrail, auth.log, Windows Security Events visible in Log Explorer)
- [ ] Cloud SIEM Content Packs are enabled for all cloud providers in use (AWS, Azure, GCP)
- [ ] Out-of-the-box detection rules are active and generating signals for test events
- [ ] Custom detection rules trigger correctly (test with a simulated failed login burst)
- [ ] Workload Protection (CSM Threats) is enabled and Agent rules are evaluating on hosts
- [ ] Security dashboard displays signal counts, top rules, severity breakdown, and geographic data
- [ ] Notification workflows deliver alerts to Slack, PagerDuty, or Jira for critical and high signals
- [ ] Suppression queries are configured to reduce false positives on noisy rules
- [ ] Security Signals API returns results programmatically for automation integration
