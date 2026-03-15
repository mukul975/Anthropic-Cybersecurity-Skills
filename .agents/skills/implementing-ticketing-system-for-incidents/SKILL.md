---
name: implementing-ticketing-system-for-incidents
description: >
  Implements an integrated incident ticketing system connecting SIEM alerts to ServiceNow, Jira,
  or TheHive for structured incident tracking, SLA management, escalation workflows, and compliance
  documentation. Use when SOC teams need formalized incident lifecycle management with automated
  ticket creation, assignment routing, and resolution tracking.
domain: cybersecurity
subdomain: soc-operations
tags: [soc, ticketing, servicenow, jira, thehive, incident-management, sla, workflow]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Implementing Ticketing System for Incidents

## When to Use

Use this skill when:
- SOC teams need to formalize incident tracking beyond SIEM notable event management
- Compliance requirements mandate documented incident lifecycle with timestamps and audit trails
- Multi-team coordination requires ticket-based workflows with assignment and escalation
- SLA tracking needs automated measurement of response and resolution times
- Post-incident reviews require structured data for trend analysis and reporting

**Do not use** for individual alert triage — ticketing is for confirmed incidents requiring multi-step investigation and remediation, not every SIEM alert.

## Prerequisites

- Ticketing platform: ServiceNow ITSM, Jira Service Management, or TheHive
- SIEM integration capability (REST API, webhook, or SOAR connector)
- Incident classification taxonomy (categories, severity levels, escalation paths)
- On-call rotation schedule for analyst assignment
- SLA definitions aligned to incident severity

## Workflow

### Step 1: Define Incident Classification Taxonomy

Establish standardized incident categories and severity:

```yaml
incident_taxonomy:
  categories:
    - malware_infection
    - phishing_campaign
    - unauthorized_access
    - data_exfiltration
    - denial_of_service
    - ransomware
    - insider_threat
    - vulnerability_exploitation
    - account_compromise
    - policy_violation

  severity_levels:
    critical:
      definition: "Active data breach, ransomware, or business-critical system compromise"
      response_sla: 15 minutes
      resolution_sla: 4 hours
      escalation: immediate to Tier 3 + CISO notification
      examples: ["Active ransomware", "Domain admin compromise", "Customer data breach"]

    high:
      definition: "Confirmed compromise of business systems or multiple user accounts"
      response_sla: 30 minutes
      resolution_sla: 8 hours
      escalation: Tier 2 immediate, Tier 3 if unresolved in 2 hours
      examples: ["Malware with C2", "Lateral movement detected", "Phishing with credential theft"]

    medium:
      definition: "Confirmed security event requiring investigation and remediation"
      response_sla: 2 hours
      resolution_sla: 24 hours
      escalation: Tier 2 within 4 hours
      examples: ["Single phishing click", "Unauthorized software", "Policy violation"]

    low:
      definition: "Minor security event with limited impact"
      response_sla: 8 hours
      resolution_sla: 72 hours
      escalation: Tier 1 standard queue
      examples: ["Scan attempt", "Failed brute force (no compromise)", "Info disclosure"]
```

### Step 2: Automate Ticket Creation from SIEM

**ServiceNow Integration via REST API:**

```python
import requests
import json
from datetime import datetime

class IncidentTicketManager:
    def __init__(self, snow_url, snow_user, snow_password):
        self.snow_url = snow_url
        self.auth = (snow_user, snow_password)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def create_incident(self, alert_data):
        """Create ServiceNow incident from SIEM alert"""
        severity_map = {
            "critical": "1",
            "high": "2",
            "medium": "3",
            "low": "4"
        }

        payload = {
            "short_description": f"[SEC] {alert_data['rule_name']} — {alert_data['src']}",
            "description": self._build_description(alert_data),
            "category": "Security",
            "subcategory": alert_data.get("category", "Investigation"),
            "urgency": severity_map.get(alert_data["severity"], "3"),
            "impact": severity_map.get(alert_data["severity"], "3"),
            "assignment_group": self._get_assignment_group(alert_data["severity"]),
            "caller_id": "soc_automation",
            "u_siem_event_id": alert_data.get("notable_id", ""),
            "u_mitre_technique": alert_data.get("mitre_technique", ""),
            "u_affected_hosts": ", ".join(alert_data.get("affected_hosts", [])),
            "u_iocs": json.dumps(alert_data.get("iocs", {}))
        }

        response = requests.post(
            f"{self.snow_url}/api/now/table/incident",
            auth=self.auth,
            headers=self.headers,
            json=payload
        )
        result = response.json()["result"]
        return {
            "ticket_number": result["number"],
            "sys_id": result["sys_id"],
            "state": result["state"]
        }

    def _build_description(self, alert_data):
        return f"""
SECURITY INCIDENT — Auto-generated from SIEM
================================================
Alert Rule:       {alert_data['rule_name']}
SIEM Event ID:    {alert_data.get('notable_id', 'N/A')}
Detection Time:   {alert_data['detection_time']}
Severity:         {alert_data['severity'].upper()}
MITRE ATT&CK:    {alert_data.get('mitre_technique', 'N/A')}

Source:           {alert_data.get('src', 'N/A')}
Destination:      {alert_data.get('dest', 'N/A')}
User:             {alert_data.get('user', 'N/A')}

Initial Context:
{alert_data.get('description', 'See SIEM for details.')}

IOCs:
{json.dumps(alert_data.get('iocs', {}), indent=2)}
"""

    def _get_assignment_group(self, severity):
        if severity in ("critical", "high"):
            return "SOC Tier 2"
        return "SOC Tier 1"

    def update_incident(self, ticket_number, updates):
        """Update an existing incident"""
        # First get sys_id from ticket number
        response = requests.get(
            f"{self.snow_url}/api/now/table/incident",
            auth=self.auth,
            headers=self.headers,
            params={"sysparm_query": f"number={ticket_number}", "sysparm_limit": 1}
        )
        sys_id = response.json()["result"][0]["sys_id"]

        # Update
        response = requests.patch(
            f"{self.snow_url}/api/now/table/incident/{sys_id}",
            auth=self.auth,
            headers=self.headers,
            json=updates
        )
        return response.json()["result"]

    def add_work_note(self, ticket_number, note):
        """Add investigation note to incident"""
        self.update_incident(ticket_number, {"work_notes": note})

    def escalate_incident(self, ticket_number, reason):
        """Escalate to next tier"""
        self.update_incident(ticket_number, {
            "assignment_group": "SOC Tier 3",
            "urgency": "1",
            "work_notes": f"ESCALATED: {reason}"
        })

    def resolve_incident(self, ticket_number, resolution):
        """Resolve and close incident"""
        self.update_incident(ticket_number, {
            "state": "6",  # Resolved
            "close_code": "Resolved",
            "close_notes": resolution,
            "u_incident_disposition": resolution.split(":")[0] if ":" in resolution else "Resolved"
        })
```

### Step 3: Configure TheHive for Security-Focused Ticketing

**TheHive Case Creation (alternative to ServiceNow):**

```python
import requests

class TheHiveCaseManager:
    def __init__(self, thehive_url, api_key):
        self.url = thehive_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

    def create_case(self, alert_data):
        """Create case in TheHive from SIEM alert"""
        case = {
            "title": f"[{alert_data['severity'].upper()}] {alert_data['rule_name']}",
            "description": self._build_markdown_description(alert_data),
            "severity": {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                alert_data["severity"], 2
            ),
            "tlp": 2,  # TLP:AMBER
            "pap": 2,  # PAP:AMBER
            "tags": [
                alert_data.get("mitre_technique", ""),
                alert_data.get("category", ""),
                f"source:{alert_data.get('src', 'unknown')}"
            ],
            "tasks": self._generate_tasks(alert_data["severity"]),
            "customFields": {
                "siem-event-id": {"string": alert_data.get("notable_id", "")},
                "mitre-technique": {"string": alert_data.get("mitre_technique", "")},
                "detection-source": {"string": "Splunk ES"}
            }
        }

        response = requests.post(
            f"{self.url}/api/case",
            headers=self.headers,
            json=case
        )
        return response.json()

    def _generate_tasks(self, severity):
        """Generate investigation tasks based on severity"""
        tasks = [
            {"title": "Initial Triage", "group": "Phase 1", "description": "Review SIEM alert and validate findings"},
            {"title": "IOC Enrichment", "group": "Phase 1", "description": "Enrich all IOCs with VT, AbuseIPDB"},
            {"title": "Scope Assessment", "group": "Phase 2", "description": "Determine affected systems and users"},
        ]
        if severity in ("critical", "high"):
            tasks.extend([
                {"title": "Containment Actions", "group": "Phase 2", "description": "Isolate affected systems"},
                {"title": "Evidence Collection", "group": "Phase 3", "description": "Preserve forensic artifacts"},
                {"title": "Eradication", "group": "Phase 3", "description": "Remove threat from environment"},
                {"title": "Recovery", "group": "Phase 4", "description": "Restore systems to normal operations"},
                {"title": "Post-Incident Review", "group": "Phase 4", "description": "Document lessons learned"},
            ])
        else:
            tasks.append(
                {"title": "Resolution and Documentation", "group": "Phase 2", "description": "Document findings and close"}
            )
        return tasks

    def add_observable(self, case_id, ioc_type, ioc_value, description=""):
        """Add IOC observable to case"""
        observable = {
            "dataType": ioc_type,
            "data": ioc_value,
            "message": description,
            "tlp": 2,
            "ioc": True,
            "tags": ["auto-extracted"]
        }
        response = requests.post(
            f"{self.url}/api/case/{case_id}/artifact",
            headers=self.headers,
            json=observable
        )
        return response.json()
```

### Step 4: Implement SLA Tracking and Escalation

**Splunk SLA Monitoring Dashboard:**
```spl
--- Active incidents approaching SLA breach
index=servicenow sourcetype="snow:incident" category="Security" state IN ("New", "In Progress")
| eval sla_minutes = case(
    urgency="1", 15,
    urgency="2", 30,
    urgency="3", 120,
    urgency="4", 480
  )
| eval age_minutes = round((now() - strptime(opened_at, "%Y-%m-%d %H:%M:%S")) / 60, 0)
| eval sla_remaining = sla_minutes - age_minutes
| eval sla_status = case(
    sla_remaining < 0, "BREACHED",
    sla_remaining < sla_minutes * 0.25, "AT RISK",
    1=1, "ON TRACK"
  )
| where sla_status IN ("BREACHED", "AT RISK")
| sort sla_remaining
| table number, short_description, urgency, assignment_group, assigned_to,
        age_minutes, sla_minutes, sla_remaining, sla_status
```

**Auto-Escalation Logic:**
```python
def check_sla_breaches(ticket_manager):
    """Check for SLA breaches and auto-escalate"""
    open_incidents = ticket_manager.get_open_incidents()

    for incident in open_incidents:
        age_minutes = (datetime.utcnow() - incident["opened_at"]).total_seconds() / 60
        sla_minutes = {"1": 15, "2": 30, "3": 120, "4": 480}[incident["urgency"]]

        if age_minutes > sla_minutes and incident["state"] == "New":
            ticket_manager.escalate_incident(
                incident["number"],
                f"SLA BREACH: {int(age_minutes)}min elapsed, {sla_minutes}min SLA. Auto-escalating."
            )
```

### Step 5: Build Reporting and Metrics

```spl
--- Monthly incident metrics
index=servicenow sourcetype="snow:incident" category="Security"
opened_at > "2024-03-01" opened_at < "2024-04-01"
| stats count AS total,
        avg(eval((resolved_at - opened_at) / 3600)) AS avg_resolution_hours,
        sum(eval(if(urgency="1", 1, 0))) AS critical,
        sum(eval(if(urgency="2", 1, 0))) AS high,
        sum(eval(if(urgency="3", 1, 0))) AS medium,
        sum(eval(if(urgency="4", 1, 0))) AS low
| eval avg_resolution = round(avg_resolution_hours, 1)

--- SLA compliance rate
index=servicenow sourcetype="snow:incident" category="Security" state="Resolved"
| eval sla_target = case(urgency="1", 4, urgency="2", 8, urgency="3", 24, urgency="4", 72)
| eval resolution_hours = (resolved_at - opened_at) / 3600
| eval sla_met = if(resolution_hours <= sla_target, 1, 0)
| stats sum(sla_met) AS met, count AS total
| eval compliance_pct = round(met / total * 100, 1)
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Incident Ticket** | Formal tracking record for a confirmed security incident with lifecycle management |
| **SLA** | Service Level Agreement defining maximum response and resolution times by severity |
| **Escalation Path** | Defined routing from Tier 1 to Tier 2/3 based on severity, time elapsed, or analyst request |
| **Disposition** | Final classification of a closed incident (true positive, false positive, duplicate, policy violation) |
| **MTTR** | Mean Time to Resolve — average time from ticket creation to resolution across all incidents |
| **Case Management** | Structured approach to managing complex incidents with tasks, observables, and audit trails |

## Tools & Systems

- **ServiceNow ITSM**: Enterprise IT service management platform with security incident module and SLA tracking
- **Jira Service Management**: Atlassian's service management platform with customizable incident workflows
- **TheHive**: Open-source security incident response platform with case management and Cortex integration
- **PagerDuty**: On-call management and incident notification platform for SOC analyst alerting
- **Splunk ITSI**: IT Service Intelligence module for SLA tracking and service health dashboards

## Common Scenarios

- **SIEM-to-Ticket Automation**: Auto-create ServiceNow ticket for every critical/high notable event in Splunk ES
- **Multi-Team Coordination**: Route malware incidents to SOC for triage, IT for remediation, Legal for notification
- **Compliance Documentation**: Generate incident reports from ticket data for PCI DSS, HIPAA audit evidence
- **On-Call Alerting**: Page on-call analyst via PagerDuty when critical ticket created after hours
- **Post-Incident Review**: Query closed tickets to identify recurring incident types and systemic gaps

## Output Format

```
INCIDENT TICKET — INC0012567
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Title:        [SEC] Cobalt Strike C2 Beacon Detected — WORKSTATION-042
Category:     Security > Malware Infection
Severity:     Critical (P1)
SLA:          Response: 15 min | Resolution: 4 hours

Timeline:
  14:23  Ticket created (auto from Splunk ES NE-2024-08921)
  14:25  Assigned to analyst_jdoe (Tier 2)
  14:28  Work note: "VT confirms Cobalt Strike beacon, hash a1b2c3..."
  14:35  Work note: "Host isolated via CrowdStrike, C2 domain blocked"
  15:00  Work note: "Enterprise IOC scan — 2 additional hosts found"
  15:30  Escalated to Tier 3 for forensic analysis
  16:00  Work note: "All affected hosts contained and cleaned"
  18:00  Resolved: "Malware eradicated, systems restored, monitoring for 72h"

Metrics:
  Time to Acknowledge: 2 minutes
  Time to Contain:     12 minutes
  Time to Resolve:     3 hours 37 minutes
  SLA Status:          MET (within 4-hour resolution target)
```
