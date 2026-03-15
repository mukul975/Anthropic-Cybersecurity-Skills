#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Mapping Tool

Builds and analyzes detection coverage maps against the
MITRE ATT&CK framework for SOC detection gap analysis.
"""

import json
from datetime import datetime


ATTACK_TACTICS = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

ENTERPRISE_TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactic": "TA0006", "subtechniques": 4},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "subtechniques": 9},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0005", "subtechniques": 4},
    "T1055": {"name": "Process Injection", "tactic": "TA0005", "subtechniques": 15},
    "T1021": {"name": "Remote Services", "tactic": "TA0008", "subtechniques": 7},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003", "subtechniques": 6},
    "T1566": {"name": "Phishing", "tactic": "TA0001", "subtechniques": 4},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006", "subtechniques": 8},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011", "subtechniques": 4},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010", "subtechniques": 3},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011", "subtechniques": 0},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003", "subtechniques": 15},
    "T1036": {"name": "Masquerading", "tactic": "TA0005", "subtechniques": 9},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "TA0005", "subtechniques": 14},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005", "subtechniques": 12},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040", "subtechniques": 0},
    "T1098": {"name": "Account Manipulation", "tactic": "TA0003", "subtechniques": 6},
    "T1070": {"name": "Indicator Removal", "tactic": "TA0005", "subtechniques": 9},
    "T1543": {"name": "Create or Modify System Process", "tactic": "TA0003", "subtechniques": 4},
    "T1136": {"name": "Create Account", "tactic": "TA0003", "subtechniques": 3},
}


class DetectionRule:
    """Represents a SIEM detection rule with MITRE mapping."""

    def __init__(self, name: str, techniques: list, score: int,
                 data_sources: list, validated: bool = False):
        self.name = name
        self.techniques = techniques
        self.score = score
        self.data_sources = data_sources
        self.validated = validated


class CoverageMap:
    """MITRE ATT&CK coverage map for detection gap analysis."""

    def __init__(self, organization: str):
        self.organization = organization
        self.rules = []
        self.technique_scores = {}
        self.generated = datetime.utcnow().isoformat()

    def add_rule(self, rule: DetectionRule):
        self.rules.append(rule)
        for tech_id in rule.techniques:
            if tech_id not in self.technique_scores:
                self.technique_scores[tech_id] = {"rules": [], "max_score": 0}
            self.technique_scores[tech_id]["rules"].append(rule.name)
            self.technique_scores[tech_id]["max_score"] = max(
                self.technique_scores[tech_id]["max_score"], rule.score
            )

    def get_coverage_summary(self) -> dict:
        total_techniques = len(ENTERPRISE_TECHNIQUES)
        covered = sum(1 for t in ENTERPRISE_TECHNIQUES if t in self.technique_scores and self.technique_scores[t]["max_score"] > 0)
        no_coverage = total_techniques - covered

        scores = [self.technique_scores.get(t, {}).get("max_score", 0) for t in ENTERPRISE_TECHNIQUES]
        avg_score = round(sum(scores) / max(1, len(scores)), 1)

        return {
            "organization": self.organization,
            "total_techniques": total_techniques,
            "covered": covered,
            "no_coverage": no_coverage,
            "coverage_pct": round(covered / total_techniques * 100, 1),
            "avg_score": avg_score,
            "total_rules": len(self.rules),
            "generated": self.generated,
        }

    def get_tactic_coverage(self) -> dict:
        tactic_data = {}
        for tactic_id, tactic_name in ATTACK_TACTICS.items():
            techniques_in_tactic = [
                t for t, info in ENTERPRISE_TECHNIQUES.items()
                if info["tactic"] == tactic_id
            ]
            covered = sum(1 for t in techniques_in_tactic if t in self.technique_scores and self.technique_scores[t]["max_score"] > 0)
            total = len(techniques_in_tactic)
            tactic_data[tactic_name] = {
                "total": total,
                "covered": covered,
                "pct": round(covered / max(1, total) * 100, 1),
            }
        return tactic_data

    def get_gaps(self, min_priority: int = 0) -> list:
        gaps = []
        for tech_id, info in ENTERPRISE_TECHNIQUES.items():
            score = self.technique_scores.get(tech_id, {}).get("max_score", 0)
            if score < 50:
                gaps.append({
                    "technique_id": tech_id,
                    "technique_name": info["name"],
                    "tactic": ATTACK_TACTICS.get(info["tactic"], "Unknown"),
                    "current_score": score,
                    "subtechniques": info["subtechniques"],
                    "rules_count": len(self.technique_scores.get(tech_id, {}).get("rules", [])),
                })
        return sorted(gaps, key=lambda x: x["current_score"])

    def generate_navigator_layer(self) -> dict:
        techniques = []
        for tech_id, info in ENTERPRISE_TECHNIQUES.items():
            score = self.technique_scores.get(tech_id, {}).get("max_score", 0)
            rules = self.technique_scores.get(tech_id, {}).get("rules", [])
            color = "#ff0000" if score == 0 else "#ffff00" if score < 50 else "#90ee90" if score < 75 else "#00ff00"
            techniques.append({
                "techniqueID": tech_id,
                "color": color,
                "score": score,
                "comment": f"{len(rules)} rules: {', '.join(rules[:3])}" if rules else "NO DETECTION",
            })
        return {
            "name": f"{self.organization} - Detection Coverage",
            "versions": {"attack": "16", "navigator": "5.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": techniques,
            "gradient": {"colors": ["#ff0000", "#ffff00", "#00ff00"], "minValue": 0, "maxValue": 100},
        }


if __name__ == "__main__":
    cmap = CoverageMap("Example Corp SOC")

    rules = [
        DetectionRule("Brute Force Detection", ["T1110"], 85, ["Windows Security Log"], True),
        DetectionRule("Suspicious PowerShell", ["T1059"], 75, ["PowerShell Script Block"], True),
        DetectionRule("New Account Created", ["T1136"], 60, ["Windows Security Log"], False),
        DetectionRule("Lateral Movement RDP", ["T1021"], 70, ["Windows Security Log", "Firewall"], True),
        DetectionRule("Phishing Email Detected", ["T1566"], 80, ["Email Gateway"], True),
        DetectionRule("Credential Dumping", ["T1003"], 50, ["Sysmon"], False),
        DetectionRule("Scheduled Task Created", ["T1053"], 65, ["Windows Security Log"], True),
        DetectionRule("C2 Beaconing", ["T1071"], 45, ["Firewall", "DNS"], False),
        DetectionRule("Data Exfiltration", ["T1048"], 30, ["Firewall"], False),
        DetectionRule("Ransomware Encryption", ["T1486"], 40, ["EDR"], False),
    ]

    for rule in rules:
        cmap.add_rule(rule)

    print("=" * 70)
    print("MITRE ATT&CK COVERAGE MAP")
    print("=" * 70)

    summary = cmap.get_coverage_summary()
    print(f"\nOrganization: {summary['organization']}")
    print(f"Coverage: {summary['covered']}/{summary['total_techniques']} techniques ({summary['coverage_pct']}%)")
    print(f"Average Score: {summary['avg_score']}/100")
    print(f"Total Rules: {summary['total_rules']}")

    print(f"\n{'Tactic':<30} {'Covered':<10} {'Total':<8} {'Coverage'}")
    print("-" * 60)
    for tactic, data in cmap.get_tactic_coverage().items():
        if data["total"] > 0:
            bar = "#" * int(data["pct"] / 5) + "." * (20 - int(data["pct"] / 5))
            print(f"{tactic:<30} {data['covered']:<10} {data['total']:<8} [{bar}] {data['pct']}%")

    print(f"\nDetection Gaps (Score < 50):")
    for gap in cmap.get_gaps():
        print(f"  [{gap['current_score']:>3}] {gap['technique_id']} - {gap['technique_name']} ({gap['tactic']})")

    # Export Navigator layer
    layer = cmap.generate_navigator_layer()
    print(f"\nATT&CK Navigator Layer exported ({len(layer['techniques'])} techniques)")
