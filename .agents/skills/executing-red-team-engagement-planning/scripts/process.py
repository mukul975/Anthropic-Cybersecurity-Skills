#!/usr/bin/env python3
"""
Red Team Engagement Planning Automation Tool

Generates engagement planning documents including:
- Rules of Engagement (ROE) document
- Threat profile mapping from MITRE ATT&CK
- Attack plan timeline
- Deconfliction matrix
- Engagement metrics tracker

Usage:
    python process.py --org "Target Corp" --type full-scope --duration 20 --output ./engagement_plan
    python process.py --org "Target Corp" --threat-actor APT29 --generate-attack-plan
    python process.py --template roe --output ./documents

Requirements:
    pip install jinja2 requests pyyaml rich
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    import yaml
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("[!] Missing dependencies. Install with: pip install pyyaml rich")
    sys.exit(1)

console = Console()

# MITRE ATT&CK threat actor profiles with mapped TTPs
THREAT_ACTOR_PROFILES = {
    "APT29": {
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "targets": ["Government", "Defense", "Technology", "Think Tanks"],
        "techniques": {
            "Initial Access": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1566.002", "name": "Spearphishing Link"},
                {"id": "T1195.002", "name": "Compromise Software Supply Chain"},
            ],
            "Execution": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1059.005", "name": "Visual Basic"},
                {"id": "T1204.002", "name": "Malicious File"},
            ],
            "Persistence": [
                {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
                {"id": "T1053.005", "name": "Scheduled Task"},
                {"id": "T1543.003", "name": "Windows Service"},
            ],
            "Privilege Escalation": [
                {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
                {"id": "T1055", "name": "Process Injection"},
            ],
            "Defense Evasion": [
                {"id": "T1027", "name": "Obfuscated Files or Information"},
                {"id": "T1070.004", "name": "File Deletion"},
                {"id": "T1140", "name": "Deobfuscate/Decode Files"},
            ],
            "Credential Access": [
                {"id": "T1003.001", "name": "LSASS Memory"},
                {"id": "T1558.003", "name": "Kerberoasting"},
            ],
            "Lateral Movement": [
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
                {"id": "T1021.001", "name": "Remote Desktop Protocol"},
            ],
            "Collection": [
                {"id": "T1560.001", "name": "Archive via Utility"},
                {"id": "T1114.002", "name": "Remote Email Collection"},
            ],
            "Exfiltration": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
                {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"},
            ],
            "Command and Control": [
                {"id": "T1071.001", "name": "Web Protocols"},
                {"id": "T1573.002", "name": "Asymmetric Cryptography"},
                {"id": "T1090.003", "name": "Multi-hop Proxy"},
            ],
        },
    },
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM"],
        "targets": ["Government", "Military", "Journalists", "Political Organizations"],
        "techniques": {
            "Initial Access": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1078", "name": "Valid Accounts"},
            ],
            "Execution": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1059.003", "name": "Windows Command Shell"},
            ],
            "Persistence": [
                {"id": "T1547.001", "name": "Registry Run Keys"},
                {"id": "T1137.001", "name": "Office Template Macros"},
            ],
            "Credential Access": [
                {"id": "T1110.003", "name": "Password Spraying"},
                {"id": "T1556.001", "name": "Domain Controller Authentication"},
                {"id": "T1528", "name": "Steal Application Access Token"},
            ],
            "Lateral Movement": [
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
            ],
            "Collection": [
                {"id": "T1005", "name": "Data from Local System"},
                {"id": "T1114", "name": "Email Collection"},
            ],
            "Exfiltration": [
                {"id": "T1048.002", "name": "Exfiltration Over Asymmetric Encrypted Non-C2"},
            ],
            "Command and Control": [
                {"id": "T1071.001", "name": "Web Protocols"},
                {"id": "T1105", "name": "Ingress Tool Transfer"},
            ],
        },
    },
    "FIN7": {
        "aliases": ["Carbon Spider", "ELBRUS", "Sangria Tempest"],
        "targets": ["Retail", "Hospitality", "Financial", "Restaurant"],
        "techniques": {
            "Initial Access": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1566.002", "name": "Spearphishing Link"},
            ],
            "Execution": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1059.005", "name": "Visual Basic"},
                {"id": "T1059.007", "name": "JavaScript"},
            ],
            "Persistence": [
                {"id": "T1053.005", "name": "Scheduled Task"},
                {"id": "T1547.001", "name": "Registry Run Keys"},
            ],
            "Credential Access": [
                {"id": "T1003", "name": "OS Credential Dumping"},
                {"id": "T1555", "name": "Credentials from Password Stores"},
            ],
            "Lateral Movement": [
                {"id": "T1021.001", "name": "Remote Desktop Protocol"},
                {"id": "T1570", "name": "Lateral Tool Transfer"},
            ],
            "Collection": [
                {"id": "T1005", "name": "Data from Local System"},
                {"id": "T1113", "name": "Screen Capture"},
            ],
            "Exfiltration": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel"},
            ],
            "Command and Control": [
                {"id": "T1071.001", "name": "Web Protocols"},
                {"id": "T1573.001", "name": "Symmetric Cryptography"},
            ],
        },
    },
    "Lazarus": {
        "aliases": ["HIDDEN COBRA", "Zinc", "Diamond Sleet"],
        "targets": ["Financial", "Cryptocurrency", "Defense", "Media"],
        "techniques": {
            "Initial Access": [
                {"id": "T1566.001", "name": "Spearphishing Attachment"},
                {"id": "T1195.002", "name": "Compromise Software Supply Chain"},
                {"id": "T1189", "name": "Drive-by Compromise"},
            ],
            "Execution": [
                {"id": "T1059.001", "name": "PowerShell"},
                {"id": "T1059.006", "name": "Python"},
                {"id": "T1204.002", "name": "Malicious File"},
            ],
            "Persistence": [
                {"id": "T1543.003", "name": "Windows Service"},
                {"id": "T1547.001", "name": "Registry Run Keys"},
            ],
            "Defense Evasion": [
                {"id": "T1027", "name": "Obfuscated Files or Information"},
                {"id": "T1036.005", "name": "Match Legitimate Name or Location"},
                {"id": "T1070.004", "name": "File Deletion"},
            ],
            "Credential Access": [
                {"id": "T1003.001", "name": "LSASS Memory"},
                {"id": "T1552.001", "name": "Credentials In Files"},
            ],
            "Lateral Movement": [
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares"},
            ],
            "Impact": [
                {"id": "T1486", "name": "Data Encrypted for Impact"},
                {"id": "T1485", "name": "Data Destruction"},
                {"id": "T1496", "name": "Resource Hijacking"},
            ],
            "Command and Control": [
                {"id": "T1071.001", "name": "Web Protocols"},
                {"id": "T1090", "name": "Proxy"},
                {"id": "T1105", "name": "Ingress Tool Transfer"},
            ],
        },
    },
}

ENGAGEMENT_TYPES = {
    "full-scope": {
        "name": "Full Scope Red Team Engagement",
        "description": "Complete adversary simulation covering physical, social, and cyber vectors",
        "phases": [
            "Reconnaissance",
            "Initial Access",
            "Establish Persistence",
            "Lateral Movement",
            "Privilege Escalation",
            "Objective Completion",
            "Cleanup & Reporting",
        ],
        "vectors": ["Cyber", "Physical", "Social Engineering"],
    },
    "assumed-breach": {
        "name": "Assumed Breach Engagement",
        "description": "Starts from an initial foothold, focuses on internal post-exploitation",
        "phases": [
            "Internal Reconnaissance",
            "Establish Persistence",
            "Lateral Movement",
            "Privilege Escalation",
            "Objective Completion",
            "Cleanup & Reporting",
        ],
        "vectors": ["Cyber (Internal)"],
    },
    "objective-based": {
        "name": "Objective-Based Red Team Engagement",
        "description": "Focused on reaching specific crown jewels or objectives",
        "phases": [
            "Target Analysis",
            "Attack Path Planning",
            "Execution",
            "Objective Validation",
            "Cleanup & Reporting",
        ],
        "vectors": ["Defined per objective"],
    },
    "purple-team": {
        "name": "Purple Team Collaborative Engagement",
        "description": "Collaborative red/blue team exercise for detection improvement",
        "phases": [
            "TTP Selection",
            "Execute & Observe",
            "Detection Gap Analysis",
            "Tuning & Improvement",
            "Validation & Reporting",
        ],
        "vectors": ["Defined per detection scenario"],
    },
}


def generate_roe_document(
    org_name: str,
    engagement_type: str,
    duration_days: int,
    start_date: str | None = None,
    threat_actor: str | None = None,
) -> str:
    """Generate a Rules of Engagement document."""
    if start_date:
        start = datetime.strptime(start_date, "%Y-%m-%d")
    else:
        start = datetime.now() + timedelta(days=7)

    end = start + timedelta(days=duration_days)
    eng_type = ENGAGEMENT_TYPES.get(engagement_type, ENGAGEMENT_TYPES["full-scope"])

    roe = f"""
# RULES OF ENGAGEMENT
## {eng_type['name']}

### CONFIDENTIAL - {org_name}

---

## 1. EXECUTIVE SUMMARY

This document defines the Rules of Engagement for the {eng_type['name']} to be
conducted against {org_name}. This engagement will simulate realistic adversary
behavior to test the organization's detection and response capabilities.

**Engagement Type:** {eng_type['name']}
**Description:** {eng_type['description']}
**Duration:** {duration_days} days
**Start Date:** {start.strftime('%Y-%m-%d')}
**End Date:** {end.strftime('%Y-%m-%d')}
**Document Version:** 1.0
**Classification:** CONFIDENTIAL

---

## 2. ENGAGEMENT OBJECTIVES

### Primary Objectives
1. Assess the organization's ability to detect and respond to targeted attacks
2. Identify security gaps in people, process, and technology controls
3. Validate the effectiveness of existing security monitoring and alerting
4. Test incident response procedures and communication workflows

### Secondary Objectives
1. Provide actionable recommendations for security improvements
2. Establish baseline metrics for future red team assessments
3. Identify critical attack paths to sensitive data and systems
4. Evaluate security awareness among targeted personnel

### Success Criteria
- [ ] Initial access achieved through authorized attack vector
- [ ] Lateral movement to at least 3 network segments
- [ ] Privilege escalation to domain administrator equivalent
- [ ] Access to defined crown jewels demonstrated
- [ ] Complete engagement report delivered within agreed timeline

---

## 3. SCOPE DEFINITION

### 3.1 In-Scope Assets
| Category | Details | Notes |
|----------|---------|-------|
| External IP Ranges | [TO BE DEFINED] | All externally facing assets |
| Internal Networks | [TO BE DEFINED] | Corporate and server networks |
| Domains | [TO BE DEFINED] | Primary and subsidiary domains |
| Cloud Environments | [TO BE DEFINED] | AWS/Azure/GCP accounts |
| Physical Locations | [TO BE DEFINED] | Office locations for physical tests |
| Personnel | [TO BE DEFINED] | Approved social engineering targets |

### 3.2 Out-of-Scope Assets
| Category | Details | Reason |
|----------|---------|--------|
| Production Databases | [TO BE DEFINED] | Business continuity risk |
| Medical/Safety Systems | [TO BE DEFINED] | Safety critical systems |
| Third-Party Systems | [TO BE DEFINED] | Legal/contractual restrictions |
| Executive Leadership | [TO BE DEFINED] | Unless specifically authorized |

### 3.3 Authorized Attack Vectors
{chr(10).join(f'- {v}' for v in eng_type['vectors'])}

---

## 4. AUTHORIZED TECHNIQUES

### 4.1 Approved MITRE ATT&CK Techniques
"""

    if threat_actor and threat_actor in THREAT_ACTOR_PROFILES:
        profile = THREAT_ACTOR_PROFILES[threat_actor]
        roe += f"\n**Emulated Threat Actor:** {threat_actor} ({', '.join(profile['aliases'])})\n\n"
        for tactic, techniques in profile["techniques"].items():
            roe += f"\n#### {tactic}\n"
            for t in techniques:
                roe += f"- {t['id']}: {t['name']}\n"
    else:
        roe += "\n[Techniques to be defined based on threat profile selection]\n"

    roe += f"""
### 4.2 Prohibited Actions
- Denial of Service attacks against production systems
- Data destruction or modification of production data
- Exploitation of vulnerabilities that could cause system instability
- Social engineering of C-suite executives (unless authorized)
- Physical damage to any property or equipment
- Access to or exfiltration of actual sensitive data (demonstrate access only)
- Testing during defined blackout periods

---

## 5. COMMUNICATION PLAN

### 5.1 Points of Contact

| Role | Name | Phone | Email | Availability |
|------|------|-------|-------|--------------|
| Engagement Sponsor | [TBD] | [TBD] | [TBD] | Business hours |
| Technical POC | [TBD] | [TBD] | [TBD] | 24/7 during engagement |
| Red Team Lead | [TBD] | [TBD] | [TBD] | 24/7 during engagement |
| Legal Counsel | [TBD] | [TBD] | [TBD] | Business hours |
| SOC Manager | [TBD] | [TBD] | [TBD] | 24/7 during engagement |

### 5.2 Communication Channels
- **Primary:** Encrypted email (PGP/S-MIME)
- **Secondary:** Signal messenger group
- **Emergency:** Direct phone call to Technical POC
- **Deconfliction:** Dedicated Slack/Teams channel (invite-only)

### 5.3 Check-in Schedule
- **Daily:** Status update via encrypted email by 17:00
- **Weekly:** Video call progress review with engagement sponsor
- **Ad-hoc:** Immediate notification for critical findings or incidents

---

## 6. EMERGENCY PROCEDURES

### 6.1 Emergency Stop
- **Code Word:** [TO BE DEFINED - e.g., "LIGHTNING STRIKE"]
- **Activation:** Any authorized contact can invoke emergency stop
- **Response:** All red team activity ceases immediately
- **Notification:** Red team lead confirms cessation within 15 minutes

### 6.2 Escalation Matrix
| Severity | Description | Action | Timeline |
|----------|-------------|--------|----------|
| Critical | System outage or data breach suspected | Emergency stop + immediate call | Immediate |
| High | Unexpected system impact detected | Pause affected activity + notify | Within 1 hour |
| Medium | Blue team investigating red team activity | Continue with caution + monitor | Within 4 hours |
| Low | General questions or clarifications | Respond via normal channels | Within 24 hours |

### 6.3 Real Incident Overlap
If a real security incident is detected during the engagement:
1. Red team immediately pauses all operations
2. Red team lead notifies SOC manager via emergency channel
3. Red team provides deconfliction data to distinguish red team activity
4. Engagement resumes only after explicit authorization from sponsor

---

## 7. ENGAGEMENT TIMELINE

### Phase Schedule
"""

    days_per_phase = duration_days // len(eng_type["phases"])
    current_day = 0
    for i, phase in enumerate(eng_type["phases"]):
        phase_start = start + timedelta(days=current_day)
        if i == len(eng_type["phases"]) - 1:
            phase_end = end
        else:
            phase_end = phase_start + timedelta(days=days_per_phase - 1)
        roe += f"| {phase} | {phase_start.strftime('%Y-%m-%d')} | {phase_end.strftime('%Y-%m-%d')} |\n"
        current_day += days_per_phase

    roe += f"""
### Blackout Periods
- [TO BE DEFINED - e.g., Change freeze windows, major events]

---

## 8. DATA HANDLING

### 8.1 Sensitive Data Discovery
- If sensitive data (PII, PHI, financial) is discovered, document metadata only
- Do not copy, store, or exfiltrate actual sensitive data
- Take screenshots showing access capability without exposing data content
- Notify engagement sponsor of sensitive data exposure findings

### 8.2 Evidence Retention
- All evidence stored on encrypted drives (AES-256)
- Evidence retained for 90 days post-engagement
- Evidence destroyed via secure wipe after retention period
- Chain of custody maintained for all evidence items

### 8.3 Report Handling
- Final report classified as CONFIDENTIAL
- Distributed only to authorized recipients
- Stored in organization's secure document management system
- Red team retains no copies after final delivery confirmation

---

## 9. LEGAL AUTHORIZATION

### 9.1 Authorization Statement
I, [SPONSOR NAME], [TITLE], hereby authorize [RED TEAM COMPANY] to conduct
a {eng_type['name']} against {org_name} as described in this
Rules of Engagement document.

**Authorized Signature:** _________________________
**Print Name:** _________________________
**Title:** _________________________
**Date:** _________________________

### 9.2 Get-Out-of-Jail Letter
A separate authorization letter will be provided to each red team operator
for physical security testing activities. This letter authorizes the bearer
to conduct authorized security testing and provides emergency contact
information for verification.

---

## 10. DOCUMENT APPROVAL

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Engagement Sponsor | | | |
| CISO | | | |
| Legal Counsel | | | |
| Red Team Lead | | | |

---

*Document generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
*Engagement ID: RT-{org_name.replace(' ', '').upper()[:6]}-{start.strftime('%Y%m%d')}*
"""
    return roe


def generate_attack_plan(
    threat_actor: str, engagement_type: str, duration_days: int
) -> str:
    """Generate a phased attack plan based on threat actor profile."""
    if threat_actor not in THREAT_ACTOR_PROFILES:
        console.print(
            f"[red][-] Unknown threat actor: {threat_actor}[/red]"
        )
        console.print(
            f"[yellow]Available: {', '.join(THREAT_ACTOR_PROFILES.keys())}[/yellow]"
        )
        return ""

    profile = THREAT_ACTOR_PROFILES[threat_actor]
    eng_type = ENGAGEMENT_TYPES.get(engagement_type, ENGAGEMENT_TYPES["full-scope"])

    plan = f"""
# ATTACK PLAN
## Adversary Emulation: {threat_actor} ({', '.join(profile['aliases'])})

### Engagement Type: {eng_type['name']}
### Duration: {duration_days} days
### Target Sectors: {', '.join(profile['targets'])}

---

## Emulated Techniques by Phase

"""
    for i, phase in enumerate(eng_type["phases"], 1):
        plan += f"### Phase {i}: {phase}\n\n"
        plan += "| ATT&CK ID | Technique | Tool/Method | Detection Checkpoint |\n"
        plan += "|-----------|-----------|-------------|---------------------|\n"

        # Map phase to relevant tactics
        tactic_mapping = {
            "Reconnaissance": ["Initial Access"],
            "Initial Access": ["Initial Access", "Execution"],
            "Internal Reconnaissance": ["Credential Access", "Lateral Movement"],
            "Establish Persistence": ["Persistence", "Defense Evasion"],
            "Lateral Movement": ["Lateral Movement", "Credential Access"],
            "Privilege Escalation": ["Privilege Escalation", "Defense Evasion"],
            "Objective Completion": ["Collection", "Exfiltration"],
            "Cleanup & Reporting": [],
            "Target Analysis": ["Initial Access"],
            "Attack Path Planning": ["Initial Access"],
            "Execution": ["Execution", "Lateral Movement"],
            "Objective Validation": ["Collection", "Exfiltration"],
            "TTP Selection": ["Initial Access"],
            "Execute & Observe": ["Execution", "Lateral Movement"],
            "Detection Gap Analysis": [],
            "Tuning & Improvement": [],
            "Validation & Reporting": [],
        }

        relevant_tactics = tactic_mapping.get(phase, [])
        for tactic in relevant_tactics:
            if tactic in profile["techniques"]:
                for tech in profile["techniques"][tactic]:
                    plan += f"| {tech['id']} | {tech['name']} | [Operator Choice] | [Blue Team Check] |\n"

        if not relevant_tactics:
            plan += "| N/A | Administrative phase | N/A | N/A |\n"

        plan += "\n"

    plan += """
## Operational Security (OPSEC) Requirements

1. Use dedicated testing infrastructure only (no personal devices)
2. Route all traffic through authorized VPN/redirectors
3. Encrypt all communications between operators
4. Use separate credentials for each engagement
5. Clear browser history and cache after each session
6. Rotate C2 infrastructure on detection or at phase transitions
7. Use timestomping and log cleanup only on red team infrastructure

## Evidence Collection Requirements

For each technique executed, document:
- Timestamp (UTC)
- Source and destination IP/hostname
- User account used
- Tool/command executed
- Screenshot or log evidence
- Detection status (detected/undetected)
- Time to detection (if detected)
"""
    return plan


def generate_deconfliction_matrix(org_name: str, duration_days: int) -> str:
    """Generate a deconfliction tracking matrix."""
    matrix = f"""
# DECONFLICTION MATRIX
## {org_name} Red Team Engagement

### Purpose
This matrix tracks all red team activities for deconfliction with the SOC/IR team.
Entries should be updated in real-time during engagement execution.

---

## Red Team Infrastructure

| Asset Type | IP Address | Domain | Purpose | Active Period |
|-----------|------------|--------|---------|---------------|
| C2 Server | [TBD] | [TBD] | Primary C2 | Engagement duration |
| Redirector | [TBD] | [TBD] | HTTPS redirect | Engagement duration |
| Phishing Server | [TBD] | [TBD] | Email delivery | Phase 2 only |
| VPN Gateway | [TBD] | [TBD] | Operator access | Engagement duration |

## Red Team Accounts

| Account Name | Account Type | System | Purpose | Active Period |
|-------------|-------------|--------|---------|---------------|
| [TBD] | Local Admin | [TBD] | Persistence | Phase 3+ |
| [TBD] | Domain User | [TBD] | Lateral movement | Phase 4+ |

## Activity Log Template

| Date | Time (UTC) | Operator | Source IP | Destination | Action | Technique ID | Notes |
|------|-----------|----------|-----------|-------------|--------|-------------|-------|
| | | | | | | | |

## Deconfliction Contacts

| Time Period | Red Team Contact | SOC Contact | Channel |
|------------|-----------------|-------------|---------|
| 0800-1700 | [TBD] | [TBD] | Slack/Teams |
| 1700-0800 | [TBD] | [TBD] | Phone |
| Weekend | [TBD] | [TBD] | Phone |

## Escalation Procedures

1. SOC detects suspicious activity
2. SOC checks deconfliction matrix for matching red team activity
3. If match found: Log as red team activity, continue monitoring
4. If no match: Treat as potential real incident, notify red team lead
5. Red team lead confirms or denies activity within 30 minutes
6. If not red team activity: Initiate incident response procedures
"""
    return matrix


def generate_metrics_template(engagement_type: str) -> str:
    """Generate an engagement metrics tracking template."""
    template = """
# RED TEAM ENGAGEMENT METRICS

## Time-Based Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Time to Initial Access (TTIA) | | Hours from engagement start |
| Time to Privilege Escalation | | Hours from initial access |
| Time to Domain Admin (TTDA) | | Hours from initial access |
| Time to Crown Jewels (TTO) | | Hours from initial access |
| Total Engagement Duration | | Days |
| Active Testing Hours | | Hours |

## Detection Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Total Techniques Executed | | Count of unique ATT&CK techniques |
| Techniques Detected | | Count detected by blue team |
| Detection Rate | | Percentage |
| Mean Time to Detect (MTTD) | | Hours from execution to detection |
| Mean Time to Respond (MTTR) | | Hours from detection to containment |
| False Positive Rate | | Blue team alerts not related to red team |

## Access Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Hosts Compromised | | Unique hosts with access |
| Accounts Compromised | | Unique credentials obtained |
| Network Segments Reached | | Number of VLANs/subnets |
| Persistence Mechanisms | | Number of persistence methods established |
| Data Access Demonstrated | | Categories of data accessible |

## Technique Execution Log

| # | ATT&CK ID | Technique | Executed | Detected | Time to Detect | Tool Used |
|---|-----------|-----------|----------|----------|---------------|-----------|
| 1 | | | [ ] | [ ] | | |
| 2 | | | [ ] | [ ] | | |
| 3 | | | [ ] | [ ] | | |

## Phase Completion Tracking

| Phase | Start Date | End Date | Status | Key Findings |
|-------|-----------|----------|--------|-------------|
| | | | Not Started / In Progress / Complete | |
"""
    return template


def display_threat_actor_table():
    """Display available threat actor profiles."""
    table = Table(title="Available Threat Actor Profiles")
    table.add_column("Actor", style="red bold")
    table.add_column("Aliases", style="yellow")
    table.add_column("Target Sectors", style="cyan")
    table.add_column("Techniques", style="green")

    for actor, profile in THREAT_ACTOR_PROFILES.items():
        total_techniques = sum(
            len(techs) for techs in profile["techniques"].values()
        )
        table.add_row(
            actor,
            ", ".join(profile["aliases"]),
            ", ".join(profile["targets"]),
            str(total_techniques),
        )

    console.print(table)


def display_engagement_types():
    """Display available engagement types."""
    table = Table(title="Available Engagement Types")
    table.add_column("Type", style="red bold")
    table.add_column("Name", style="yellow")
    table.add_column("Description", style="cyan")
    table.add_column("Phases", style="green")

    for etype, details in ENGAGEMENT_TYPES.items():
        table.add_row(
            etype,
            details["name"],
            details["description"],
            str(len(details["phases"])),
        )

    console.print(table)


def export_attack_navigator_layer(threat_actor: str, output_path: str):
    """Export MITRE ATT&CK Navigator layer JSON for visualization."""
    if threat_actor not in THREAT_ACTOR_PROFILES:
        console.print(f"[red][-] Unknown threat actor: {threat_actor}[/red]")
        return

    profile = THREAT_ACTOR_PROFILES[threat_actor]
    techniques = []

    for tactic, techs in profile["techniques"].items():
        for tech in techs:
            techniques.append(
                {
                    "techniqueID": tech["id"],
                    "tactic": tactic.lower().replace(" ", "-"),
                    "color": "#ff6666",
                    "comment": f"Emulated by {threat_actor}",
                    "enabled": True,
                    "score": 1,
                }
            )

    layer = {
        "name": f"{threat_actor} Emulation Plan",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Red team emulation plan based on {threat_actor} ({', '.join(profile['aliases'])}) TTPs",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "Planned Technique", "color": "#ff6666"},
        ],
    }

    layer_path = Path(output_path) / f"{threat_actor.lower()}_navigator_layer.json"
    with open(layer_path, "w") as f:
        json.dump(layer, f, indent=2)

    console.print(f"[green][+] ATT&CK Navigator layer exported to: {layer_path}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="Red Team Engagement Planning Automation Tool"
    )
    parser.add_argument("--org", required=True, help="Target organization name")
    parser.add_argument(
        "--type",
        choices=ENGAGEMENT_TYPES.keys(),
        default="full-scope",
        help="Engagement type",
    )
    parser.add_argument(
        "--duration", type=int, default=20, help="Engagement duration in days"
    )
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--threat-actor", help="Threat actor to emulate")
    parser.add_argument("--output", default="./engagement_plan", help="Output directory")
    parser.add_argument(
        "--generate-attack-plan", action="store_true", help="Generate attack plan"
    )
    parser.add_argument(
        "--generate-roe", action="store_true", help="Generate ROE document"
    )
    parser.add_argument(
        "--generate-all", action="store_true", help="Generate all documents"
    )
    parser.add_argument(
        "--list-actors", action="store_true", help="List available threat actors"
    )
    parser.add_argument(
        "--list-types", action="store_true", help="List engagement types"
    )
    parser.add_argument(
        "--export-navigator",
        action="store_true",
        help="Export ATT&CK Navigator layer",
    )

    args = parser.parse_args()

    if args.list_actors:
        display_threat_actor_table()
        return

    if args.list_types:
        display_engagement_types()
        return

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(
        Panel(
            f"[bold red]Red Team Engagement Planner[/bold red]\n"
            f"Organization: {args.org}\n"
            f"Type: {args.type}\n"
            f"Duration: {args.duration} days\n"
            f"Threat Actor: {args.threat_actor or 'Not specified'}",
            title="Configuration",
        )
    )

    if args.generate_roe or args.generate_all:
        console.print("[yellow][*] Generating Rules of Engagement...[/yellow]")
        roe = generate_roe_document(
            args.org, args.type, args.duration, args.start_date, args.threat_actor
        )
        roe_path = output_dir / "rules_of_engagement.md"
        with open(roe_path, "w") as f:
            f.write(roe)
        console.print(f"[green][+] ROE document saved to: {roe_path}[/green]")

    if args.generate_attack_plan or args.generate_all:
        if args.threat_actor:
            console.print("[yellow][*] Generating Attack Plan...[/yellow]")
            plan = generate_attack_plan(
                args.threat_actor, args.type, args.duration
            )
            plan_path = output_dir / "attack_plan.md"
            with open(plan_path, "w") as f:
                f.write(plan)
            console.print(f"[green][+] Attack plan saved to: {plan_path}[/green]")
        else:
            console.print(
                "[red][-] --threat-actor required for attack plan generation[/red]"
            )

    if args.generate_all:
        console.print("[yellow][*] Generating Deconfliction Matrix...[/yellow]")
        matrix = generate_deconfliction_matrix(args.org, args.duration)
        matrix_path = output_dir / "deconfliction_matrix.md"
        with open(matrix_path, "w") as f:
            f.write(matrix)
        console.print(f"[green][+] Deconfliction matrix saved to: {matrix_path}[/green]")

        console.print("[yellow][*] Generating Metrics Template...[/yellow]")
        metrics = generate_metrics_template(args.type)
        metrics_path = output_dir / "engagement_metrics.md"
        with open(metrics_path, "w") as f:
            f.write(metrics)
        console.print(f"[green][+] Metrics template saved to: {metrics_path}[/green]")

    if args.export_navigator and args.threat_actor:
        export_attack_navigator_layer(args.threat_actor, str(output_dir))

    console.print("\n[bold green][+] Engagement planning documents generated successfully![/bold green]")


if __name__ == "__main__":
    main()
