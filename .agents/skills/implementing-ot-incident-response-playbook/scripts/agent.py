#!/usr/bin/env python3
"""OT Incident Response Playbook Agent - executes ICS/SCADA incident response procedures."""

import json
import argparse
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

OT_INCIDENT_TYPES = {
    "unauthorized_plc_access": {"severity": "critical", "safety_impact": True},
    "hmi_compromise": {"severity": "critical", "safety_impact": True},
    "historian_breach": {"severity": "high", "safety_impact": False},
    "engineering_workstation_malware": {"severity": "critical", "safety_impact": True},
    "network_anomaly": {"severity": "medium", "safety_impact": False},
    "firmware_tampering": {"severity": "critical", "safety_impact": True},
    "ransomware_ot": {"severity": "critical", "safety_impact": True},
    "dos_scada": {"severity": "high", "safety_impact": True},
}


def assess_incident(incident_type, affected_assets):
    incident_info = OT_INCIDENT_TYPES.get(incident_type, {"severity": "medium", "safety_impact": False})
    has_safety_system = any(a.get("type") in ("SIS", "safety_plc", "emergency_shutdown") for a in affected_assets)
    return {
        "incident_type": incident_type,
        "base_severity": incident_info["severity"],
        "safety_impact": incident_info["safety_impact"] or has_safety_system,
        "affected_assets": len(affected_assets),
        "escalated_severity": "critical" if has_safety_system else incident_info["severity"],
        "requires_plant_shutdown": has_safety_system and incident_info["safety_impact"],
    }


def generate_containment_steps(incident_type, assessment):
    steps = [
        {"step": 1, "action": "Notify OT operations and plant safety manager", "priority": "immediate"},
        {"step": 2, "action": "Verify safety instrumented systems (SIS) are operational", "priority": "immediate"},
        {"step": 3, "action": "Document current process state and control values", "priority": "immediate"},
    ]
    if incident_type in ("unauthorized_plc_access", "firmware_tampering"):
        steps.extend([
            {"step": 4, "action": "Isolate affected PLCs from network (do NOT power off)", "priority": "high"},
            {"step": 5, "action": "Switch affected processes to manual control", "priority": "high"},
            {"step": 6, "action": "Verify PLC program integrity against known-good backup", "priority": "high"},
        ])
    elif incident_type == "ransomware_ot":
        steps.extend([
            {"step": 4, "action": "Isolate IT/OT boundary immediately", "priority": "immediate"},
            {"step": 5, "action": "Verify Level 0-1 devices are unaffected", "priority": "immediate"},
            {"step": 6, "action": "Preserve forensic evidence from affected HMIs", "priority": "high"},
        ])
    elif incident_type == "hmi_compromise":
        steps.extend([
            {"step": 4, "action": "Disconnect compromised HMI from control network", "priority": "immediate"},
            {"step": 5, "action": "Activate backup HMI or manual operations", "priority": "high"},
        ])
    else:
        steps.extend([
            {"step": 4, "action": "Isolate affected network segment", "priority": "high"},
            {"step": 5, "action": "Enable enhanced monitoring on OT network", "priority": "medium"},
        ])
    return steps


def generate_recovery_plan(incident_type, affected_assets):
    return {
        "pre_recovery_checks": [
            "Verify all safety systems are functional",
            "Confirm process is in safe state",
            "Validate backup integrity before restoration",
        ],
        "recovery_steps": [
            "Restore from known-good configuration backups",
            "Re-validate PLC programs against engineering documentation",
            "Perform staged restart with operator verification",
            "Monitor process values against baseline for 24 hours",
        ],
        "post_recovery_validation": [
            "Compare process parameters to pre-incident baseline",
            "Run safety system functional tests",
            "Verify all control loops are operating correctly",
        ],
    }


def generate_report(assessment, containment, recovery):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "playbook": "OT Incident Response",
        "incident_assessment": assessment,
        "containment_steps": containment,
        "recovery_plan": recovery,
        "regulatory_notifications": [
            "CISA ICS-CERT (within 72 hours for critical infrastructure)",
            "Sector-specific ISAC notification",
        ] if assessment["safety_impact"] else [],
    }


def main():
    parser = argparse.ArgumentParser(description="OT Incident Response Playbook Agent")
    parser.add_argument("--incident-type", required=True, choices=list(OT_INCIDENT_TYPES.keys()))
    parser.add_argument("--affected-assets", help="JSON file listing affected assets")
    parser.add_argument("--output", default="ot_ir_playbook.json")
    args = parser.parse_args()

    assets = []
    if args.affected_assets:
        with open(args.affected_assets) as f:
            assets = json.load(f)

    assessment = assess_incident(args.incident_type, assets)
    containment = generate_containment_steps(args.incident_type, assessment)
    recovery = generate_recovery_plan(args.incident_type, assets)
    report = generate_report(assessment, containment, recovery)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("OT IR: %s, severity %s, safety impact: %s",
                args.incident_type, assessment["escalated_severity"], assessment["safety_impact"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
