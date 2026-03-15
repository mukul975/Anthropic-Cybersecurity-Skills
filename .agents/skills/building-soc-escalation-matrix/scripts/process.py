#!/usr/bin/env python3
"""
SOC Escalation Matrix Builder and Simulator

Builds escalation matrices, simulates incident routing,
and tracks SLA compliance for SOC operations.
"""

import json
from datetime import datetime, timedelta


SEVERITY_CONFIG = {
    "P1": {
        "name": "Critical",
        "initial_response_min": 15,
        "escalation_to_tier2_min": 0,
        "escalation_to_tier3_min": 0,
        "escalation_to_mgmt_min": 30,
        "resolution_target_hours": 4,
        "update_interval_min": 30,
        "assigned_tier": 3,
    },
    "P2": {
        "name": "High",
        "initial_response_min": 30,
        "escalation_to_tier2_min": 30,
        "escalation_to_tier3_min": 240,
        "escalation_to_mgmt_min": 120,
        "resolution_target_hours": 8,
        "update_interval_min": 120,
        "assigned_tier": 2,
    },
    "P3": {
        "name": "Medium",
        "initial_response_min": 240,
        "escalation_to_tier2_min": 480,
        "escalation_to_tier3_min": None,
        "escalation_to_mgmt_min": None,
        "resolution_target_hours": 24,
        "update_interval_min": 1440,
        "assigned_tier": 1,
    },
    "P4": {
        "name": "Low",
        "initial_response_min": 480,
        "escalation_to_tier2_min": None,
        "escalation_to_tier3_min": None,
        "escalation_to_mgmt_min": None,
        "resolution_target_hours": 72,
        "update_interval_min": 10080,
        "assigned_tier": 1,
    },
}

ASSET_CRITICALITY_MAP = {
    ("critical", "critical"): "P1",
    ("critical", "high"): "P1",
    ("critical", "medium"): "P1",
    ("critical", "low"): "P2",
    ("high", "critical"): "P1",
    ("high", "high"): "P2",
    ("high", "medium"): "P2",
    ("high", "low"): "P3",
    ("medium", "critical"): "P2",
    ("medium", "high"): "P2",
    ("medium", "medium"): "P3",
    ("medium", "low"): "P4",
    ("low", "critical"): "P3",
    ("low", "high"): "P3",
    ("low", "medium"): "P4",
    ("low", "low"): "P4",
}

AUTO_ESCALATION_TRIGGERS = {
    "ransomware_detected": "P1",
    "domain_admin_compromise": "P1",
    "active_data_exfiltration": "P1",
    "multiple_hosts_malware": "P1",
    "critical_infrastructure_alert": "P1",
    "executive_account_anomaly": "P2",
    "insider_threat_indicator": "P2",
    "brute_force_success": "P2",
}


class Incident:
    """Represents a security incident with escalation tracking."""

    def __init__(self, incident_id: str, title: str, severity_score: str,
                 asset_criticality: str, incident_type: str):
        self.incident_id = incident_id
        self.title = title
        self.incident_type = incident_type
        self.created = datetime.utcnow()

        # Calculate priority
        if incident_type in AUTO_ESCALATION_TRIGGERS:
            self.priority = AUTO_ESCALATION_TRIGGERS[incident_type]
        else:
            self.priority = ASSET_CRITICALITY_MAP.get(
                (severity_score, asset_criticality), "P3"
            )

        self.config = SEVERITY_CONFIG[self.priority]
        self.current_tier = self.config["assigned_tier"]
        self.status = "open"
        self.escalation_history = []
        self.resolved_at = None

    def check_sla_compliance(self) -> dict:
        now = datetime.utcnow()
        elapsed_min = (now - self.created).total_seconds() / 60

        response_sla_met = elapsed_min <= self.config["initial_response_min"] or self.status != "open"
        resolution_target_min = self.config["resolution_target_hours"] * 60

        if self.resolved_at:
            resolution_min = (self.resolved_at - self.created).total_seconds() / 60
            resolution_sla_met = resolution_min <= resolution_target_min
        else:
            resolution_sla_met = elapsed_min <= resolution_target_min

        return {
            "incident_id": self.incident_id,
            "priority": self.priority,
            "elapsed_minutes": round(elapsed_min, 1),
            "response_sla_met": response_sla_met,
            "resolution_sla_met": resolution_sla_met,
            "response_sla_min": self.config["initial_response_min"],
            "resolution_sla_min": resolution_target_min,
            "needs_escalation": not resolution_sla_met and self.status == "open",
        }

    def escalate(self, to_tier: int, reason: str):
        self.escalation_history.append({
            "from_tier": self.current_tier,
            "to_tier": to_tier,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.current_tier = to_tier

    def resolve(self):
        self.status = "resolved"
        self.resolved_at = datetime.utcnow()


class EscalationMatrix:
    """Manages the SOC escalation matrix and tracks incidents."""

    def __init__(self):
        self.incidents = []

    def create_incident(self, incident_id: str, title: str, severity: str,
                        asset_criticality: str, incident_type: str) -> Incident:
        incident = Incident(incident_id, title, severity, asset_criticality, incident_type)
        self.incidents.append(incident)
        return incident

    def get_sla_report(self) -> dict:
        report = {"total": len(self.incidents), "by_priority": {}, "sla_breaches": 0}
        for priority in ["P1", "P2", "P3", "P4"]:
            priority_incidents = [i for i in self.incidents if i.priority == priority]
            breaches = sum(1 for i in priority_incidents if not i.check_sla_compliance()["resolution_sla_met"])
            report["by_priority"][priority] = {
                "count": len(priority_incidents),
                "resolved": sum(1 for i in priority_incidents if i.status == "resolved"),
                "open": sum(1 for i in priority_incidents if i.status == "open"),
                "sla_breaches": breaches,
            }
            report["sla_breaches"] += breaches
        return report

    def get_escalation_summary(self) -> dict:
        total_escalations = sum(len(i.escalation_history) for i in self.incidents)
        tier_distribution = {1: 0, 2: 0, 3: 0}
        for i in self.incidents:
            if i.current_tier in tier_distribution:
                tier_distribution[i.current_tier] += 1
        return {
            "total_incidents": len(self.incidents),
            "total_escalations": total_escalations,
            "current_tier_distribution": tier_distribution,
        }


if __name__ == "__main__":
    matrix = EscalationMatrix()

    inc1 = matrix.create_incident("INC-001", "Ransomware on Finance Server", "critical", "critical", "ransomware_detected")
    inc2 = matrix.create_incident("INC-002", "Failed Brute Force on VPN", "medium", "high", "brute_force_attempt")
    inc3 = matrix.create_incident("INC-003", "Suspicious PowerShell on Workstation", "high", "medium", "suspicious_execution")
    inc4 = matrix.create_incident("INC-004", "Expired SSL Certificate", "low", "low", "certificate_expiry")
    inc5 = matrix.create_incident("INC-005", "Executive Email Compromise Attempt", "high", "critical", "executive_account_anomaly")

    # Simulate escalations
    inc1.escalate(3, "Ransomware auto-escalation to Tier 3")
    inc3.escalate(2, "Analyst escalation - needs deeper investigation")
    inc4.resolve()

    print("=" * 70)
    print("SOC ESCALATION MATRIX REPORT")
    print("=" * 70)

    for inc in matrix.incidents:
        sla = inc.check_sla_compliance()
        print(f"\n[{inc.priority}] {inc.incident_id}: {inc.title}")
        print(f"  Status: {inc.status} | Tier: {inc.current_tier} | Type: {inc.incident_type}")
        print(f"  Response SLA: {'MET' if sla['response_sla_met'] else 'BREACHED'} ({sla['response_sla_min']}min)")
        print(f"  Resolution SLA: {'MET' if sla['resolution_sla_met'] else 'AT RISK'} ({sla['resolution_sla_min']}min)")
        if inc.escalation_history:
            print(f"  Escalations: {len(inc.escalation_history)}")

    print(f"\n{'=' * 70}")
    print("SLA COMPLIANCE REPORT")
    print("=" * 70)
    report = matrix.get_sla_report()
    for priority, data in report["by_priority"].items():
        if data["count"] > 0:
            print(f"  {priority}: {data['count']} incidents, {data['resolved']} resolved, {data['sla_breaches']} SLA breaches")
