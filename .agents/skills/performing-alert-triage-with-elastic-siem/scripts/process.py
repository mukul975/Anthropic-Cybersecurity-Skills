#!/usr/bin/env python3
"""
Elastic SIEM Alert Triage Automation

Provides alert triage scoring, classification assistance,
and triage workflow management for Elastic Security alerts.
"""

import json
from datetime import datetime, timedelta
from typing import Optional


SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "informational": 10,
}

ASSET_CRITICALITY = {
    "critical": 1.5,
    "high": 1.3,
    "medium": 1.0,
    "low": 0.7,
}

MITRE_TACTIC_PRIORITY = {
    "Impact": 95,
    "Exfiltration": 90,
    "Lateral Movement": 85,
    "Credential Access": 80,
    "Command and Control": 75,
    "Defense Evasion": 70,
    "Privilege Escalation": 65,
    "Persistence": 60,
    "Execution": 55,
    "Collection": 50,
    "Discovery": 40,
    "Initial Access": 35,
    "Reconnaissance": 20,
    "Resource Development": 15,
}


class TriageAlert:
    """Represents a security alert for triage processing."""

    def __init__(
        self,
        alert_id: str,
        rule_name: str,
        severity: str,
        risk_score: int,
        host_name: str,
        user_name: str,
        source_ip: str,
        mitre_tactic: str,
        mitre_technique: str,
        timestamp: str,
        asset_criticality: str = "medium",
        related_alert_count: int = 0,
        threat_intel_match: bool = False,
    ):
        self.alert_id = alert_id
        self.rule_name = rule_name
        self.severity = severity
        self.risk_score = risk_score
        self.host_name = host_name
        self.user_name = user_name
        self.source_ip = source_ip
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.timestamp = timestamp
        self.asset_criticality = asset_criticality
        self.related_alert_count = related_alert_count
        self.threat_intel_match = threat_intel_match
        self.classification = None
        self.triage_notes = []
        self.triage_timestamp = None

    def calculate_triage_priority(self) -> dict:
        """Calculate composite triage priority score."""
        base_score = SEVERITY_WEIGHTS.get(self.severity, 50)
        asset_multiplier = ASSET_CRITICALITY.get(self.asset_criticality, 1.0)
        tactic_score = MITRE_TACTIC_PRIORITY.get(self.mitre_tactic, 50)

        # Boost for related alerts (potential attack chain)
        chain_boost = min(self.related_alert_count * 5, 25)

        # Boost for threat intelligence match
        ti_boost = 20 if self.threat_intel_match else 0

        composite_score = min(100, (base_score * asset_multiplier * 0.4)
                             + (tactic_score * 0.3)
                             + chain_boost
                             + ti_boost)

        if composite_score >= 85:
            priority = "P1-CRITICAL"
            sla = "15 minutes"
        elif composite_score >= 70:
            priority = "P2-HIGH"
            sla = "30 minutes"
        elif composite_score >= 50:
            priority = "P3-MEDIUM"
            sla = "4 hours"
        elif composite_score >= 30:
            priority = "P4-LOW"
            sla = "8 hours"
        else:
            priority = "P5-INFO"
            sla = "24 hours"

        return {
            "composite_score": round(composite_score, 1),
            "priority": priority,
            "response_sla": sla,
            "score_breakdown": {
                "severity_component": round(base_score * asset_multiplier * 0.4, 1),
                "tactic_component": round(tactic_score * 0.3, 1),
                "chain_boost": chain_boost,
                "threat_intel_boost": ti_boost,
            },
        }

    def classify(self, classification: str, notes: str):
        """Classify the alert after triage."""
        valid_classifications = [
            "true_positive",
            "false_positive",
            "benign_true_positive",
            "needs_investigation",
        ]
        if classification not in valid_classifications:
            raise ValueError(f"Invalid classification. Must be one of: {valid_classifications}")
        self.classification = classification
        self.triage_notes.append(notes)
        self.triage_timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        priority = self.calculate_triage_priority()
        return {
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "host_name": self.host_name,
            "user_name": self.user_name,
            "source_ip": self.source_ip,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "timestamp": self.timestamp,
            "triage_priority": priority,
            "classification": self.classification,
            "triage_notes": self.triage_notes,
            "triage_timestamp": self.triage_timestamp,
        }


class TriageQueue:
    """Manages a queue of alerts for SOC triage."""

    def __init__(self):
        self.alerts = []
        self.triaged = []
        self.metrics = {
            "total_received": 0,
            "total_triaged": 0,
            "true_positives": 0,
            "false_positives": 0,
            "benign_true_positives": 0,
            "pending_investigation": 0,
            "triage_times": [],
        }

    def add_alert(self, alert: TriageAlert):
        self.alerts.append(alert)
        self.metrics["total_received"] += 1

    def get_prioritized_queue(self) -> list:
        """Return alerts sorted by triage priority score (highest first)."""
        return sorted(
            self.alerts,
            key=lambda a: a.calculate_triage_priority()["composite_score"],
            reverse=True,
        )

    def triage_alert(self, alert_id: str, classification: str, notes: str, triage_duration_seconds: int):
        for i, alert in enumerate(self.alerts):
            if alert.alert_id == alert_id:
                alert.classify(classification, notes)
                self.triaged.append(alert)
                self.alerts.pop(i)
                self.metrics["total_triaged"] += 1
                self.metrics["triage_times"].append(triage_duration_seconds)
                if classification == "true_positive":
                    self.metrics["true_positives"] += 1
                elif classification == "false_positive":
                    self.metrics["false_positives"] += 1
                elif classification == "benign_true_positive":
                    self.metrics["benign_true_positives"] += 1
                elif classification == "needs_investigation":
                    self.metrics["pending_investigation"] += 1
                return alert
        return None

    def get_triage_metrics(self) -> dict:
        times = self.metrics["triage_times"]
        total = self.metrics["total_triaged"]
        return {
            "total_received": self.metrics["total_received"],
            "total_triaged": total,
            "pending": len(self.alerts),
            "true_positive_count": self.metrics["true_positives"],
            "false_positive_count": self.metrics["false_positives"],
            "false_positive_rate": round(self.metrics["false_positives"] / total * 100, 1) if total > 0 else 0,
            "mean_triage_time_seconds": round(sum(times) / len(times), 1) if times else 0,
            "max_triage_time_seconds": max(times) if times else 0,
            "min_triage_time_seconds": min(times) if times else 0,
        }


def generate_esql_queries(alert: TriageAlert) -> dict:
    """Generate ES|QL queries for investigating an alert."""
    return {
        "related_host_activity": (
            f'FROM logs-*\n'
            f'| WHERE host.name == "{alert.host_name}" '
            f'AND @timestamp > NOW() - 1 HOUR\n'
            f'| STATS count = COUNT(*) BY event.category, event.action\n'
            f'| SORT count DESC'
        ),
        "user_activity": (
            f'FROM logs-*\n'
            f'| WHERE user.name == "{alert.user_name}" '
            f'AND @timestamp > NOW() - 24 HOURS\n'
            f'| STATS count = COUNT(*), '
            f'unique_hosts = COUNT_DISTINCT(host.name) BY event.category\n'
            f'| SORT count DESC'
        ),
        "source_ip_alerts": (
            f'FROM .alerts-security.alerts-default\n'
            f'| WHERE source.ip == "{alert.source_ip}" '
            f'AND @timestamp > NOW() - 24 HOURS\n'
            f'| STATS alert_count = COUNT(*) '
            f'BY kibana.alert.rule.name, kibana.alert.severity\n'
            f'| SORT alert_count DESC'
        ),
        "network_connections": (
            f'FROM logs-endpoint.events.network-*\n'
            f'| WHERE host.name == "{alert.host_name}" '
            f'AND @timestamp > NOW() - 1 HOUR\n'
            f'| STATS conn_count = COUNT(*) BY destination.ip, destination.port\n'
            f'| SORT conn_count DESC\n'
            f'| LIMIT 20'
        ),
    }


if __name__ == "__main__":
    queue = TriageQueue()

    sample_alerts = [
        TriageAlert("ALT-001", "Multiple Failed Logins Followed by Success", "high", 73,
                    "DC01", "admin", "10.0.0.50", "Credential Access", "T1110",
                    "2025-01-15T10:30:00Z", "critical", 3, False),
        TriageAlert("ALT-002", "Suspicious PowerShell Execution", "critical", 91,
                    "WS-042", "jsmith", "10.0.1.42", "Execution", "T1059.001",
                    "2025-01-15T10:32:00Z", "high", 5, True),
        TriageAlert("ALT-003", "Unusual DNS Query Volume", "medium", 47,
                    "WS-108", "mwilson", "10.0.2.108", "Command and Control", "T1071",
                    "2025-01-15T10:35:00Z", "medium", 0, False),
        TriageAlert("ALT-004", "New Windows Service Created", "low", 21,
                    "SRV-DB01", "svc-deploy", "10.0.3.10", "Persistence", "T1543.003",
                    "2025-01-15T10:37:00Z", "low", 0, False),
    ]

    for alert in sample_alerts:
        queue.add_alert(alert)

    print("=" * 70)
    print("ELASTIC SIEM ALERT TRIAGE QUEUE")
    print("=" * 70)

    prioritized = queue.get_prioritized_queue()
    for i, alert in enumerate(prioritized, 1):
        p = alert.calculate_triage_priority()
        print(f"\n{i}. [{p['priority']}] {alert.rule_name}")
        print(f"   Score: {p['composite_score']} | SLA: {p['response_sla']}")
        print(f"   Host: {alert.host_name} | User: {alert.user_name} | Tactic: {alert.mitre_tactic}")

    # Simulate triage
    queue.triage_alert("ALT-002", "true_positive", "Confirmed Mimikatz execution via encoded PS", 180)
    queue.triage_alert("ALT-001", "true_positive", "Brute force followed by successful admin login", 300)
    queue.triage_alert("ALT-003", "false_positive", "DNS queries to known CDN - normal behavior", 120)
    queue.triage_alert("ALT-004", "benign_true_positive", "SCCM deployment creating expected service", 90)

    print(f"\n{'=' * 70}")
    print("TRIAGE METRICS")
    print("=" * 70)
    metrics = queue.get_triage_metrics()
    for key, value in metrics.items():
        print(f"  {key}: {value}")

    # Show investigation queries
    print(f"\n{'=' * 70}")
    print("ES|QL INVESTIGATION QUERIES FOR ALT-002")
    print("=" * 70)
    queries = generate_esql_queries(sample_alerts[1])
    for name, query in queries.items():
        print(f"\n--- {name} ---")
        print(query)
