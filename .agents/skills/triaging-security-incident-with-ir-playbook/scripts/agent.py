#!/usr/bin/env python3
"""Agent for triaging security incidents with IR playbooks.

Classifies alerts by incident type, assigns severity using a
structured matrix, selects the appropriate IR playbook, and
generates triage decisions with escalation recommendations.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


INCIDENT_TYPES = {
    "malware": {
        "keywords": ["malware", "trojan", "ransomware", "virus", "worm", "dropper", "c2", "beacon"],
        "default_severity": Severity.HIGH,
        "playbook": "malware-infection-playbook",
        "escalation": "SOC Tier 2 + IR Team",
    },
    "phishing": {
        "keywords": ["phishing", "credential harvest", "suspicious email", "spear-phishing", "bec"],
        "default_severity": Severity.MEDIUM,
        "playbook": "phishing-response-playbook",
        "escalation": "SOC Tier 2",
    },
    "data_exfiltration": {
        "keywords": ["exfiltration", "data leak", "dlp", "large upload", "dns tunnel", "unusual transfer"],
        "default_severity": Severity.CRITICAL,
        "playbook": "data-exfiltration-playbook",
        "escalation": "IR Team + CISO",
    },
    "unauthorized_access": {
        "keywords": ["brute force", "credential stuffing", "privilege escalation", "lateral movement",
                      "pass-the-hash", "kerberoasting", "golden ticket"],
        "default_severity": Severity.HIGH,
        "playbook": "unauthorized-access-playbook",
        "escalation": "SOC Tier 2 + AD Team",
    },
    "denial_of_service": {
        "keywords": ["ddos", "dos", "syn flood", "amplification", "volumetric", "resource exhaustion"],
        "default_severity": Severity.HIGH,
        "playbook": "ddos-response-playbook",
        "escalation": "NOC + SOC Tier 2",
    },
    "insider_threat": {
        "keywords": ["insider", "policy violation", "unauthorized copy", "after hours", "terminated user"],
        "default_severity": Severity.HIGH,
        "playbook": "insider-threat-playbook",
        "escalation": "IR Team + HR + Legal",
    },
    "web_attack": {
        "keywords": ["sqli", "xss", "rce", "web shell", "injection", "traversal", "deserialization"],
        "default_severity": Severity.HIGH,
        "playbook": "web-attack-playbook",
        "escalation": "SOC Tier 2 + AppSec",
    },
}

SEVERITY_MATRIX = {
    "crown_jewel_affected": Severity.CRITICAL,
    "active_exploitation": Severity.CRITICAL,
    "multiple_systems": Severity.HIGH,
    "single_system": Severity.MEDIUM,
    "reconnaissance_only": Severity.LOW,
    "policy_violation_minor": Severity.INFO,
}


class IncidentTriageAgent:
    """Triages security incidents using structured IR playbooks."""

    def __init__(self, output_dir="./incident_triage"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.triage_results = []

    def classify_incident(self, alert_text):
        """Classify alert into incident type based on keyword matching."""
        alert_lower = alert_text.lower()
        scores = {}
        for inc_type, config in INCIDENT_TYPES.items():
            score = sum(1 for kw in config["keywords"] if kw in alert_lower)
            if score > 0:
                scores[inc_type] = score
        if not scores:
            return {"type": "unknown", "confidence": 0}
        best = max(scores, key=scores.get)
        return {"type": best, "confidence": scores[best], "all_matches": scores}

    def assess_severity(self, classification, context=None):
        """Determine severity using classification and contextual factors."""
        ctx = context or {}
        inc_type = classification.get("type", "unknown")
        config = INCIDENT_TYPES.get(inc_type, {})
        base_severity = config.get("default_severity", Severity.MEDIUM)

        if ctx.get("crown_jewel_affected"):
            return Severity.CRITICAL
        if ctx.get("active_exploitation"):
            return Severity.CRITICAL
        if ctx.get("systems_affected", 1) > 5:
            return Severity.HIGH if base_severity != Severity.CRITICAL else Severity.CRITICAL
        return base_severity

    def select_playbook(self, classification):
        """Select appropriate IR playbook for the incident type."""
        inc_type = classification.get("type", "unknown")
        config = INCIDENT_TYPES.get(inc_type)
        if not config:
            return {"playbook": "generic-incident-playbook", "escalation": "SOC Tier 1"}
        return {"playbook": config["playbook"], "escalation": config["escalation"]}

    def build_triage_decision(self, alert_text, context=None):
        """Complete triage: classify, assess, assign playbook."""
        classification = self.classify_incident(alert_text)
        severity = self.assess_severity(classification, context)
        playbook = self.select_playbook(classification)

        decision = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_summary": alert_text[:200],
            "classification": classification,
            "severity": severity.value,
            "playbook": playbook["playbook"],
            "escalation_to": playbook["escalation"],
            "immediate_actions": self._get_immediate_actions(classification["type"], severity),
            "containment_needed": severity in (Severity.CRITICAL, Severity.HIGH),
        }
        self.triage_results.append(decision)
        return decision

    def _get_immediate_actions(self, inc_type, severity):
        actions = {
            "malware": ["Isolate affected host from network", "Collect memory dump",
                        "Block C2 indicators at firewall", "Preserve disk image"],
            "phishing": ["Block sender domain at email gateway", "Search for other recipients",
                         "Reset credentials if clicked", "Report to anti-phishing service"],
            "data_exfiltration": ["Block destination IPs/domains", "Disable compromised account",
                                  "Preserve DLP logs", "Notify legal/compliance"],
            "unauthorized_access": ["Disable compromised account", "Reset credentials",
                                    "Review authentication logs", "Check for persistence"],
            "denial_of_service": ["Enable DDoS mitigation", "Contact ISP/CDN",
                                  "Capture traffic sample", "Identify attack vector"],
            "insider_threat": ["Preserve evidence chain of custody", "Restrict account access",
                               "Monitor user activity", "Coordinate with HR"],
            "web_attack": ["Enable WAF blocking mode", "Capture attack payloads",
                           "Check for web shells", "Review application logs"],
        }
        return actions.get(inc_type, ["Acknowledge and investigate", "Escalate to Tier 2"])

    def prioritize_queue(self, alerts):
        """Prioritize multiple alerts by severity and type."""
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
                          Severity.LOW: 3, Severity.INFO: 4}
        decisions = [self.build_triage_decision(a["text"], a.get("context")) for a in alerts]
        decisions.sort(key=lambda d: severity_order.get(Severity(d["severity"]), 5))
        return decisions

    def generate_report(self, alerts=None):
        if alerts:
            self.prioritize_queue(alerts)
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "total_triaged": len(self.triage_results),
            "by_severity": {},
            "triage_decisions": self.triage_results,
        }
        for d in self.triage_results:
            sev = d["severity"]
            report["by_severity"][sev] = report["by_severity"].get(sev, 0) + 1

        out = self.output_dir / "incident_triage_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py '<alert_text>' [--crown-jewel] [--active-exploit]")
        sys.exit(1)
    alert = sys.argv[1]
    context = {}
    if "--crown-jewel" in sys.argv:
        context["crown_jewel_affected"] = True
    if "--active-exploit" in sys.argv:
        context["active_exploitation"] = True
    agent = IncidentTriageAgent()
    agent.build_triage_decision(alert, context)
    agent.generate_report()


if __name__ == "__main__":
    main()
