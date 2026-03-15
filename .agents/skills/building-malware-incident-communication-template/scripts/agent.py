#!/usr/bin/env python3
"""Malware Incident Communication Template Agent - Generates structured incident communications."""

import json
import logging
import argparse
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {
    "critical": {"response_time": "15 minutes", "escalation": "CISO + Legal + CEO", "update_freq": "1 hour"},
    "high": {"response_time": "1 hour", "escalation": "CISO + SOC Manager", "update_freq": "2 hours"},
    "medium": {"response_time": "4 hours", "escalation": "SOC Manager", "update_freq": "4 hours"},
    "low": {"response_time": "24 hours", "escalation": "SOC Analyst", "update_freq": "daily"},
}

MALWARE_CATEGORIES = {
    "ransomware": {"impact": "Data encryption, operational disruption", "containment": "Isolate affected hosts, disable network shares",
                    "recovery": "Restore from backups, rebuild affected systems"},
    "trojan": {"impact": "Unauthorized access, data exfiltration", "containment": "Block C2 IPs, isolate hosts",
               "recovery": "Full malware removal, credential reset"},
    "wiper": {"impact": "Data destruction, system damage", "containment": "Isolate immediately, preserve evidence",
              "recovery": "Rebuild from known-good images"},
    "infostealer": {"impact": "Credential theft, PII exposure", "containment": "Block exfiltration channels, isolate hosts",
                    "recovery": "Force password resets, monitor for abuse"},
    "worm": {"impact": "Lateral spread, network disruption", "containment": "Segment network, block propagation vectors",
             "recovery": "Patch vulnerability, clean all hosts"},
}


def generate_initial_notification(incident_id, severity, malware_type, affected_systems, detected_by):
    """Generate initial incident notification."""
    sev_info = SEVERITY_LEVELS.get(severity, SEVERITY_LEVELS["medium"])
    mal_info = MALWARE_CATEGORIES.get(malware_type, {"impact": "Under investigation", "containment": "Isolate affected systems"})
    notification = {
        "type": "initial_notification",
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "subject": f"[{severity.upper()}] Malware Incident {incident_id} - {malware_type.title()} Detected",
        "severity": severity,
        "escalation_to": sev_info["escalation"],
        "response_deadline": sev_info["response_time"],
        "body": {
            "summary": f"A {malware_type} infection has been detected on {len(affected_systems)} system(s).",
            "detection_source": detected_by,
            "affected_systems": affected_systems,
            "potential_impact": mal_info["impact"],
            "immediate_actions": mal_info["containment"],
            "next_update": sev_info["update_freq"],
        },
    }
    return notification


def generate_status_update(incident_id, severity, phase, containment_status, iocs_found, actions_taken):
    """Generate incident status update communication."""
    update = {
        "type": "status_update",
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "subject": f"[UPDATE] Incident {incident_id} - {phase.replace('_', ' ').title()}",
        "phase": phase,
        "body": {
            "current_status": containment_status,
            "actions_completed": actions_taken,
            "indicators_discovered": iocs_found,
            "next_steps": [],
        },
    }
    if phase == "containment":
        update["body"]["next_steps"] = ["Complete host isolation", "Collect forensic evidence", "Begin malware analysis"]
    elif phase == "eradication":
        update["body"]["next_steps"] = ["Remove all malware artifacts", "Patch exploited vulnerabilities", "Verify clean state"]
    elif phase == "recovery":
        update["body"]["next_steps"] = ["Restore services from backups", "Monitor for reinfection", "Validate system integrity"]
    return update


def generate_executive_summary(incident_id, severity, malware_type, affected_count, timeline_events, business_impact):
    """Generate executive-level incident summary."""
    summary = {
        "type": "executive_summary",
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "subject": f"Executive Briefing: Malware Incident {incident_id}",
        "body": {
            "overview": f"On {datetime.utcnow().strftime('%B %d, %Y')}, a {malware_type} incident affecting "
                        f"{affected_count} systems was detected and classified as {severity} severity.",
            "business_impact": business_impact,
            "timeline": timeline_events,
            "response_effectiveness": {
                "detection_to_containment": "Under assessment",
                "systems_recovered": 0,
                "data_loss": "Under investigation",
            },
            "recommendations": [
                "Conduct post-incident review within 5 business days",
                "Update incident response playbook based on lessons learned",
                "Review and enhance detection capabilities for similar threats",
                "Schedule tabletop exercise for similar scenarios",
            ],
        },
    }
    return summary


def generate_regulatory_notification(incident_id, data_types_affected, record_count, jurisdiction):
    """Generate regulatory breach notification template."""
    notification = {
        "type": "regulatory_notification",
        "incident_id": incident_id,
        "timestamp": datetime.utcnow().isoformat(),
        "subject": f"Data Breach Notification - Incident {incident_id}",
        "jurisdiction": jurisdiction,
        "body": {
            "nature_of_breach": "Malware-related unauthorized access to personal data",
            "data_categories": data_types_affected,
            "approximate_records": record_count,
            "date_of_awareness": datetime.utcnow().isoformat(),
            "notification_deadline": (datetime.utcnow() + timedelta(hours=72)).isoformat() if jurisdiction == "GDPR"
                                     else (datetime.utcnow() + timedelta(days=30)).isoformat(),
            "measures_taken": ["Contained the incident", "Engaged forensic investigators",
                               "Notified law enforcement", "Implementing additional safeguards"],
            "contact_dpo": "dpo@organization.com",
        },
    }
    return notification


def generate_full_template_set(incident_id, severity, malware_type, affected_systems, detected_by):
    """Generate complete set of communication templates."""
    templates = {
        "initial_notification": generate_initial_notification(incident_id, severity, malware_type, affected_systems, detected_by),
        "containment_update": generate_status_update(incident_id, severity, "containment", "In progress", [], ["Hosts isolated"]),
        "eradication_update": generate_status_update(incident_id, severity, "eradication", "Pending", [], []),
        "recovery_update": generate_status_update(incident_id, severity, "recovery", "Pending", [], []),
        "executive_summary": generate_executive_summary(incident_id, severity, malware_type, len(affected_systems), [], "Under assessment"),
    }
    return templates


def generate_report(templates):
    """Generate communication template report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "template_count": len(templates),
        "template_types": list(templates.keys()),
        "templates": templates,
    }
    print(f"COMMUNICATION REPORT: {len(templates)} templates generated")
    return report


def main():
    parser = argparse.ArgumentParser(description="Malware Incident Communication Template Generator")
    parser.add_argument("--incident-id", required=True, help="Incident identifier")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], required=True)
    parser.add_argument("--malware-type", choices=list(MALWARE_CATEGORIES.keys()), required=True)
    parser.add_argument("--affected-systems", nargs="+", required=True)
    parser.add_argument("--detected-by", default="EDR Alert")
    parser.add_argument("--output", default="incident_comms_report.json")
    args = parser.parse_args()

    templates = generate_full_template_set(args.incident_id, args.severity, args.malware_type,
                                           args.affected_systems, args.detected_by)
    report = generate_report(templates)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
