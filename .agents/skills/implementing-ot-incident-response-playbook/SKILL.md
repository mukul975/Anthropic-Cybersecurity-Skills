---
name: implementing-ot-incident-response-playbook
description: >
  Develop and implement OT-specific incident response playbooks aligned with
  SANS PICERL framework, IEC 62443, and NIST SP 800-82 that address unique ICS
  challenges including safety-critical systems, limited downtime tolerance, and
  coordination between IT SOC, OT engineering, and plant operations teams.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, incident-response, playbook, sans, iec62443, nist, safety-critical]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing OT Incident Response Playbook

## When to Use

- When building OT-specific incident response procedures for the first time
- When existing IT IR playbooks do not address ICS/SCADA-specific requirements
- When preparing for OT ransomware scenarios like EKANS or LockerGoga
- When aligning IR procedures with IEC 62443 and NERC CIP incident reporting requirements
- When conducting post-incident reviews to improve OT IR capabilities

**Do not use** for IT-only incident response without OT components (use standard NIST 800-61 playbooks), for day-to-day OT security monitoring (see implementing-dragos-platform-for-ot-monitoring), or for tabletop exercise design (see performing-ics-tabletop-exercise).

## Prerequisites

- OT asset inventory with criticality ratings and safety system identification
- Defined roles: OT IR Lead, IT SOC Analyst, Plant Operations Manager, Process Safety Engineer
- Communication plan including out-of-band channels (OT incidents may compromise IT communications)
- Known-good backups of PLC programs, HMI configurations, and historian data
- Contact information for ICS vendors, Dragos/Claroty support, and CISA ICS-CERT

## Workflow

### Step 1: Define OT-Specific Incident Classification and Response Procedures

```python
#!/usr/bin/env python3
"""OT Incident Response Playbook Engine.

Implements structured OT incident response procedures following
SANS PICERL lifecycle with ICS-specific considerations for safety,
availability, and cross-team coordination.
"""

import json
import sys
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class OTIncidentSeverity(Enum):
    SEV1_SAFETY = "SEV1-SAFETY"  # Safety system compromise
    SEV2_PROCESS = "SEV2-PROCESS"  # Active process manipulation
    SEV3_ACCESS = "SEV3-ACCESS"  # Unauthorized OT access
    SEV4_RECON = "SEV4-RECON"  # Reconnaissance in OT network
    SEV5_IT_SPILLOVER = "SEV5-IT-SPILLOVER"  # IT incident with OT exposure


class OTIncidentCategory(Enum):
    RANSOMWARE = "ransomware"
    MALWARE_ICS = "malware_ics_specific"
    UNAUTHORIZED_ACCESS = "unauthorized_ot_access"
    PROCESS_MANIPULATION = "process_manipulation"
    SIS_COMPROMISE = "safety_system_compromise"
    DATA_EXFILTRATION = "ot_data_exfiltration"
    SUPPLY_CHAIN = "supply_chain_compromise"
    INSIDER_THREAT = "insider_threat"


# PICERL phase definitions for OT
PICERL_PHASES = {
    "preparation": {
        "description": "Readiness activities before an incident occurs",
        "ot_specific": [
            "Maintain offline backups of all PLC programs and HMI configurations",
            "Document safe shutdown procedures for each process area",
            "Establish out-of-band communication (satellite phone, analog radio)",
            "Pre-stage forensic tools that work in air-gapped OT networks",
            "Maintain spare PLCs and engineering workstations",
            "Conduct quarterly OT tabletop exercises",
        ],
    },
    "identification": {
        "description": "Detect and confirm the OT security incident",
        "ot_specific": [
            "Correlate OT IDS alerts with process anomalies from historian data",
            "Verify if process deviations are cyber-caused vs operational",
            "Check Safety Instrumented Systems (SIS) status and integrity",
            "Review engineering workstation logs for unauthorized access",
            "Examine PLC mode changes (RUN/STOP/PROGRAM transitions)",
            "Assess whether the incident is IT-only or has crossed into OT",
        ],
    },
    "containment": {
        "description": "Limit the spread and impact of the incident",
        "ot_specific": [
            "NEVER shut down OT systems without plant operations approval",
            "Isolate affected segments at the industrial firewall (not by powering off)",
            "Switch PLCs to LOCAL/MANUAL mode if remote manipulation is suspected",
            "Disconnect IT-OT conduits at the DMZ while maintaining intra-OT communication",
            "Preserve forensic evidence before any remediation actions",
            "Maintain safety system operation throughout containment",
        ],
    },
    "eradication": {
        "description": "Remove the threat from OT systems",
        "ot_specific": [
            "Compare running PLC programs against known-good backups",
            "Rebuild compromised engineering workstations from golden images",
            "Verify historian data integrity for evidence of manipulation",
            "Check for persistence mechanisms in OT-specific locations (startup scripts, scheduled tasks on HMIs)",
            "Validate firmware integrity on PLCs and RTUs",
            "Coordinate with ICS vendor for rootkit-level remediation if needed",
        ],
    },
    "recovery": {
        "description": "Restore OT operations to normal",
        "ot_specific": [
            "Restore PLC programs from verified offline backups",
            "Bring processes back online in stages with engineering oversight",
            "Monitor process variables closely during restart for anomalies",
            "Validate safety system functionality before resuming automatic operation",
            "Re-enable IT-OT connectivity only after OT is verified clean",
            "Document any process variable drift during the incident",
        ],
    },
    "lessons_learned": {
        "description": "Post-incident review and improvement",
        "ot_specific": [
            "Conduct joint IT/OT post-incident review within 2 weeks",
            "Update detection rules based on observed attack techniques",
            "Revise network segmentation if lateral movement was successful",
            "Update PLC backup schedules based on recovery time experienced",
            "Report to CISA ICS-CERT and sector ISAC as required",
            "Test updated playbook within 90 days",
        ],
    },
}


class OTIncident:
    """Represents an active OT security incident."""

    def __init__(self, title: str, severity: OTIncidentSeverity,
                 category: OTIncidentCategory, affected_systems: List[str]):
        self.id = f"OT-IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.title = title
        self.severity = severity
        self.category = category
        self.affected_systems = affected_systems
        self.created = datetime.now().isoformat()
        self.current_phase = "identification"
        self.timeline = []
        self.decisions = []
        self.containment_actions = []

    def log_event(self, phase: str, action: str, actor: str, notes: str = ""):
        """Log an incident response action."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "action": action,
            "actor": actor,
            "notes": notes,
        }
        self.timeline.append(entry)
        return entry

    def log_decision(self, decision: str, rationale: str, approved_by: str):
        """Log a critical decision during incident response."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "decision": decision,
            "rationale": rationale,
            "approved_by": approved_by,
        }
        self.decisions.append(entry)
        return entry


class OTPlaybookEngine:
    """Executes OT incident response playbooks."""

    def __init__(self):
        self.playbooks = self._build_playbooks()

    def _build_playbooks(self) -> Dict:
        """Build category-specific OT IR playbooks."""
        return {
            OTIncidentCategory.RANSOMWARE: {
                "name": "OT Ransomware Response",
                "reference": "SANS ICS Ransomware Defense Playbook",
                "immediate_actions": [
                    "DO NOT pay ransom without executive and legal approval",
                    "Disconnect IT-OT conduit at DMZ firewalls immediately",
                    "Verify SIS/safety systems are operating independently",
                    "Switch critical processes to manual/local control",
                    "Preserve ransom note and encrypted file samples for forensics",
                    "Assess if ransomware has reached Level 2 or below",
                ],
                "containment_steps": [
                    "Block lateral movement by disabling SMB/RDP between OT hosts",
                    "Isolate affected VLANs while maintaining critical process communication",
                    "Disable remote access VPN to OT environment",
                    "Check if backup infrastructure is intact (ransomware targets backups)",
                    "Inventory which OT systems are encrypted vs still operational",
                ],
                "recovery_priority": [
                    "1. Safety Instrumented Systems (SIS)",
                    "2. Critical process controllers (PLCs in continuous process)",
                    "3. HMIs for operator visibility",
                    "4. Historian for data continuity",
                    "5. Engineering workstations",
                    "6. IT-OT connectivity (last)",
                ],
                "reporting": [
                    "CISA: report within 72 hours per CIRCIA",
                    "Sector ISAC: share IOCs within 24 hours",
                    "NERC (if applicable): report within 1 hour for BES impact",
                ],
            },
            OTIncidentCategory.SIS_COMPROMISE: {
                "name": "Safety System Compromise Response",
                "reference": "TRITON/TRISIS Incident Lessons Learned",
                "immediate_actions": [
                    "IMMEDIATELY alert Process Safety team",
                    "Verify physical safety devices are functional (relief valves, rupture discs)",
                    "Consider controlled process shutdown if SIS integrity is uncertain",
                    "Isolate SIS network from all other networks",
                    "Check if SIS is in bypass mode or has been disarmed",
                    "Engage SIS vendor emergency support (Schneider Triconex, HIMA, etc)",
                ],
                "containment_steps": [
                    "Physically disconnect the SIS engineering workstation from network",
                    "Capture forensic image of SIS engineering workstation",
                    "Verify SIS controller firmware and logic against factory baseline",
                    "Check for unauthorized TriStation/safety protocol connections",
                    "Inspect all engineering workstations for TRITON indicators",
                ],
                "recovery_priority": [
                    "1. Verify all physical safety barriers are intact",
                    "2. Reload SIS logic from offline backup (verified against vendor baseline)",
                    "3. Full SIS proof test before returning to service",
                    "4. Independent verification by process safety engineer",
                ],
                "reporting": [
                    "CISA ICS-CERT: immediate notification for SIS-targeting attack",
                    "Process safety regulator (OSHA, HSE): as required by jurisdiction",
                    "SIS vendor: engage for root cause analysis",
                ],
            },
        }

    def execute_playbook(self, incident: OTIncident):
        """Execute the appropriate playbook for an incident."""
        playbook = self.playbooks.get(incident.category)
        if not playbook:
            print(f"[!] No specific playbook for {incident.category.value}. Using generic OT IR procedures.")
            return

        print(f"\n{'='*70}")
        print(f"OT INCIDENT RESPONSE PLAYBOOK ACTIVATED")
        print(f"{'='*70}")
        print(f"Incident ID: {incident.id}")
        print(f"Title: {incident.title}")
        print(f"Severity: {incident.severity.value}")
        print(f"Category: {incident.category.value}")
        print(f"Playbook: {playbook['name']}")
        print(f"Reference: {playbook['reference']}")
        print(f"Activated: {incident.created}")
        print(f"Affected Systems: {', '.join(incident.affected_systems)}")

        print(f"\n--- IMMEDIATE ACTIONS (Execute within first 15 minutes) ---")
        for i, action in enumerate(playbook["immediate_actions"], 1):
            print(f"  {i}. {action}")

        print(f"\n--- CONTAINMENT STEPS ---")
        for i, step in enumerate(playbook["containment_steps"], 1):
            print(f"  {i}. {step}")

        print(f"\n--- RECOVERY PRIORITY ORDER ---")
        for item in playbook["recovery_priority"]:
            print(f"  {item}")

        print(f"\n--- REPORTING REQUIREMENTS ---")
        for req in playbook["reporting"]:
            print(f"  - {req}")

        # Print PICERL phase guidance
        print(f"\n--- PICERL PHASE CHECKLIST ---")
        for phase, info in PICERL_PHASES.items():
            print(f"\n  [{phase.upper()}] {info['description']}")
            for item in info["ot_specific"][:3]:
                print(f"    - {item}")


if __name__ == "__main__":
    engine = OTPlaybookEngine()

    # Example: OT Ransomware incident
    incident = OTIncident(
        title="Ransomware detected on Level 3 historian servers",
        severity=OTIncidentSeverity.SEV2_PROCESS,
        category=OTIncidentCategory.RANSOMWARE,
        affected_systems=["HIST-01", "HIST-02", "ENG-WS-03", "HMI-AREA1"],
    )

    engine.execute_playbook(incident)
```

## Key Concepts

| Term | Definition |
|------|------------|
| PICERL | SANS incident response lifecycle: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned |
| ICS4ICS | Incident Command System for Industrial Control Systems -- adapts FEMA ICS to OT cybersecurity response |
| Safety Instrumented System (SIS) | Independent safety controller that prevents hazardous conditions; compromising SIS can cause physical harm |
| Manual/Local Mode | Operating PLCs with local panel controls instead of remote SCADA; used when remote access is compromised |
| CIRCIA | Cyber Incident Reporting for Critical Infrastructure Act requiring reporting to CISA within 72 hours |
| Known-Good Backup | Verified, offline copy of PLC programs and configurations used as the trusted baseline for recovery |

## Common Scenarios

### Scenario: Ransomware Spreads from IT to OT Level 3

**Context**: Ransomware encrypts enterprise IT systems and spreads through an inadequately protected IT/OT conduit to Level 3 historian servers. HMIs at Level 2 begin showing connectivity errors.

**Approach**:
1. Activate the OT IR playbook for ransomware immediately
2. Sever IT-OT connectivity at the DMZ firewall (both north and south firewalls)
3. Verify PLCs are still running and process is stable (PLCs run independently of IT)
4. Switch operators to local HMI panels if networked HMIs are affected
5. Assess which Level 2/3 systems are encrypted vs operational
6. Prioritize restoring HMI visibility, then historian, then engineering workstations
7. Restore from offline backups -- never attempt to decrypt using attacker-provided tools without sandbox testing
8. Report to CISA within 72 hours per CIRCIA requirements

**Pitfalls**: Do not shut down PLCs to "protect" them from ransomware -- PLCs run firmware, not Windows, and are typically unaffected by ransomware. Shutting down PLCs disrupts the physical process. Never reconnect IT-OT conduit until the IT side is fully remediated.

## Output Format

```
OT INCIDENT RESPONSE REPORT
==============================
Incident ID: OT-IR-YYYYMMDD-HHMMSS
Severity: SEV[1-5]
Category: [category]
Status: [Active/Contained/Eradicated/Recovered/Closed]

TIMELINE:
  [timestamp] - [phase] - [action] - [actor]

AFFECTED SYSTEMS:
  Safety Systems: [status]
  Process Controllers: [status]
  HMI/SCADA: [status]
  Historian: [status]

DECISIONS LOG:
  [timestamp] - [decision] - [rationale] - [approver]

CONTAINMENT ACTIONS TAKEN:
  1. [action and timestamp]

RECOVERY STATUS:
  [system] - [restored/pending] - [ETA]
```
