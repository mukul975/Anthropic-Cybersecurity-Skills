#!/usr/bin/env python3
"""SOC Escalation Matrix Agent - Builds and validates SOC escalation paths and response workflows."""

import json
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SEVERITY_TIERS = {
    "P1": {"name": "Critical", "response_sla": 15, "update_sla": 60, "resolution_sla": 240,
            "escalation_path": ["SOC Analyst", "SOC Lead", "IR Manager", "CISO"],
            "notification": ["Slack #critical-alerts", "PagerDuty", "Email CISO", "SMS Exec Team"]},
    "P2": {"name": "High", "response_sla": 30, "update_sla": 120, "resolution_sla": 480,
            "escalation_path": ["SOC Analyst", "SOC Lead", "IR Manager"],
            "notification": ["Slack #soc-alerts", "PagerDuty", "Email IR Manager"]},
    "P3": {"name": "Medium", "response_sla": 60, "update_sla": 240, "resolution_sla": 1440,
            "escalation_path": ["SOC Analyst", "SOC Lead"],
            "notification": ["Slack #soc-alerts", "Email SOC Lead"]},
    "P4": {"name": "Low", "response_sla": 240, "update_sla": 480, "resolution_sla": 4320,
            "escalation_path": ["SOC Analyst"],
            "notification": ["Slack #soc-triage"]},
}

ALERT_CATEGORIES = {
    "malware": {"default_priority": "P2", "auto_escalate_if": ["ransomware", "wiper", "apt"]},
    "phishing": {"default_priority": "P3", "auto_escalate_if": ["executive_target", "credential_harvested"]},
    "unauthorized_access": {"default_priority": "P2", "auto_escalate_if": ["admin_account", "domain_controller"]},
    "data_exfiltration": {"default_priority": "P1", "auto_escalate_if": ["pii", "financial", "classified"]},
    "denial_of_service": {"default_priority": "P2", "auto_escalate_if": ["customer_facing", "revenue_impacting"]},
    "insider_threat": {"default_priority": "P2", "auto_escalate_if": ["privileged_user", "data_staging"]},
    "vulnerability_exploit": {"default_priority": "P2", "auto_escalate_if": ["zero_day", "active_exploitation"]},
}


def classify_alert(category, tags, affected_asset_criticality="medium"):
    """Classify alert priority based on category, tags, and asset criticality."""
    cat_info = ALERT_CATEGORIES.get(category, {"default_priority": "P3", "auto_escalate_if": []})
    priority = cat_info["default_priority"]
    escalation_reasons = []
    for tag in tags:
        if tag in cat_info["auto_escalate_if"]:
            escalation_reasons.append(f"Tag '{tag}' triggers auto-escalation")
    if affected_asset_criticality == "critical":
        escalation_reasons.append("Critical asset affected")
    if escalation_reasons:
        priority_num = int(priority[1])
        new_priority = f"P{max(1, priority_num - 1)}"
        if new_priority != priority:
            escalation_reasons.append(f"Escalated from {priority} to {new_priority}")
            priority = new_priority
    return {"priority": priority, "category": category, "escalation_reasons": escalation_reasons,
            "sla": SEVERITY_TIERS[priority]}


def build_escalation_matrix():
    """Build complete escalation matrix structure."""
    matrix = {"tiers": {}, "categories": {}, "auto_escalation_rules": []}
    for tier_id, tier_info in SEVERITY_TIERS.items():
        matrix["tiers"][tier_id] = {
            "name": tier_info["name"],
            "response_sla_minutes": tier_info["response_sla"],
            "update_sla_minutes": tier_info["update_sla"],
            "resolution_sla_minutes": tier_info["resolution_sla"],
            "escalation_chain": tier_info["escalation_path"],
            "notification_channels": tier_info["notification"],
        }
    for cat_name, cat_info in ALERT_CATEGORIES.items():
        matrix["categories"][cat_name] = {
            "default_priority": cat_info["default_priority"],
            "auto_escalation_triggers": cat_info["auto_escalate_if"],
        }
    matrix["auto_escalation_rules"] = [
        {"rule": "SLA breach: response", "action": "Escalate to next tier in chain", "condition": "Response SLA exceeded"},
        {"rule": "SLA breach: update", "action": "Notify SOC Lead", "condition": "Update SLA exceeded"},
        {"rule": "SLA breach: resolution", "action": "Escalate to IR Manager", "condition": "Resolution SLA exceeded"},
        {"rule": "Multiple related alerts", "action": "Escalate priority by 1", "condition": ">= 3 correlated alerts"},
        {"rule": "VIP user affected", "action": "Auto-escalate to P1", "condition": "Executive or board member"},
    ]
    return matrix


def validate_escalation_matrix(matrix):
    """Validate the escalation matrix for completeness and consistency."""
    issues = []
    for tier_id, tier in matrix["tiers"].items():
        if not tier.get("escalation_chain"):
            issues.append({"tier": tier_id, "issue": "Empty escalation chain", "severity": "critical"})
        if tier.get("response_sla_minutes", 0) >= tier.get("update_sla_minutes", 0):
            issues.append({"tier": tier_id, "issue": "Response SLA >= Update SLA", "severity": "warning"})
        if not tier.get("notification_channels"):
            issues.append({"tier": tier_id, "issue": "No notification channels", "severity": "high"})
    for cat, info in matrix["categories"].items():
        if info["default_priority"] not in matrix["tiers"]:
            issues.append({"category": cat, "issue": f"Invalid priority {info['default_priority']}", "severity": "critical"})
    valid = not any(i["severity"] == "critical" for i in issues)
    return {"valid": valid, "issues": issues, "tier_count": len(matrix["tiers"]),
            "category_count": len(matrix["categories"])}


def simulate_alerts(matrix, alerts):
    """Simulate alert classification through the escalation matrix."""
    results = []
    for alert in alerts:
        classification = classify_alert(alert.get("category", ""), alert.get("tags", []),
                                        alert.get("asset_criticality", "medium"))
        results.append({"alert": alert, "classification": classification})
    return results


def generate_report(matrix, validation, simulation_results=None):
    """Generate escalation matrix report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "escalation_matrix": matrix,
        "validation": validation,
        "simulation_results": simulation_results or [],
    }
    status = "VALID" if validation["valid"] else "INVALID"
    print(f"ESCALATION MATRIX: {status}, {validation['tier_count']} tiers, "
          f"{validation['category_count']} categories, {len(validation['issues'])} issues")
    return report


def main():
    parser = argparse.ArgumentParser(description="SOC Escalation Matrix Builder")
    parser.add_argument("--validate", action="store_true", help="Validate matrix")
    parser.add_argument("--simulate", help="JSON file with test alerts for simulation")
    parser.add_argument("--output", default="escalation_matrix_report.json")
    args = parser.parse_args()

    matrix = build_escalation_matrix()
    validation = validate_escalation_matrix(matrix)
    simulation_results = None
    if args.simulate:
        with open(args.simulate) as f:
            alerts = json.load(f)
        simulation_results = simulate_alerts(matrix, alerts)

    report = generate_report(matrix, validation, simulation_results)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
