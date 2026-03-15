#!/usr/bin/env python3
"""
Red Team Engagement Tracker and Reporter

Tracks red team activities, maps them to MITRE ATT&CK techniques,
and generates engagement reports with detection gap analysis.
"""

import json
import csv
import os
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, field, asdict


@dataclass
class RedTeamAction:
    """Represents a single red team action during an engagement."""
    timestamp: str
    phase: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    description: str
    target_host: str
    tool_used: str
    outcome: str  # success, failure, partial
    detected: bool = False
    detection_time: Optional[str] = None
    detection_source: Optional[str] = None
    evidence_path: Optional[str] = None
    operator: str = ""
    notes: str = ""


@dataclass
class EngagementConfig:
    """Configuration for a red team engagement."""
    engagement_id: str
    client_name: str
    start_date: str
    end_date: str
    scope: list = field(default_factory=list)
    out_of_scope: list = field(default_factory=list)
    objectives: list = field(default_factory=list)
    threat_profile: str = ""
    emergency_contact: str = ""
    roe_version: str = ""


MITRE_TACTICS = {
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
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

COMMON_TECHNIQUES = {
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "TA0001"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "TA0001"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "TA0001"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0001"},
    "T1059.001": {"name": "PowerShell", "tactic": "TA0002"},
    "T1059.003": {"name": "Windows Command Shell", "tactic": "TA0002"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "TA0002"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "TA0003"},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "TA0003"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004"},
    "T1548.002": {"name": "Bypass User Account Control", "tactic": "TA0004"},
    "T1055": {"name": "Process Injection", "tactic": "TA0005"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "TA0005"},
    "T1562.001": {"name": "Disable or Modify Tools", "tactic": "TA0005"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "TA0006"},
    "T1003.006": {"name": "DCSync", "tactic": "TA0006"},
    "T1558.003": {"name": "Kerberoasting", "tactic": "TA0006"},
    "T1087.002": {"name": "Domain Account Discovery", "tactic": "TA0007"},
    "T1018": {"name": "Remote System Discovery", "tactic": "TA0007"},
    "T1082": {"name": "System Information Discovery", "tactic": "TA0007"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "TA0008"},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "TA0008"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "TA0008"},
    "T1560": {"name": "Archive Collected Data", "tactic": "TA0009"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0010"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "TA0010"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
}


class RedTeamEngagementTracker:
    """Tracks and reports on red team engagement activities."""

    def __init__(self, config: EngagementConfig, output_dir: str = "./engagement_output"):
        self.config = config
        self.actions: list[RedTeamAction] = []
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def log_action(self, action: RedTeamAction) -> None:
        """Log a red team action."""
        self.actions.append(action)
        self._append_to_log(action)
        print(f"[+] Logged: {action.mitre_technique_id} - {action.description}")

    def _append_to_log(self, action: RedTeamAction) -> None:
        """Append action to engagement log file."""
        log_path = os.path.join(self.output_dir, f"{self.config.engagement_id}_log.jsonl")
        with open(log_path, "a") as f:
            f.write(json.dumps(asdict(action)) + "\n")

    def calculate_metrics(self) -> dict:
        """Calculate engagement metrics including MTTD, MTTR, and detection coverage."""
        total_actions = len(self.actions)
        detected_actions = [a for a in self.actions if a.detected]
        successful_actions = [a for a in self.actions if a.outcome == "success"]

        # Calculate Mean Time to Detect (MTTD)
        detection_deltas = []
        for action in detected_actions:
            if action.detection_time and action.timestamp:
                action_time = datetime.fromisoformat(action.timestamp)
                detect_time = datetime.fromisoformat(action.detection_time)
                delta = (detect_time - action_time).total_seconds() / 3600  # hours
                detection_deltas.append(delta)

        mttd_hours = sum(detection_deltas) / len(detection_deltas) if detection_deltas else None

        # Calculate TTP coverage
        unique_techniques = set(a.mitre_technique_id for a in self.actions)
        detected_techniques = set(a.mitre_technique_id for a in detected_actions)
        ttp_coverage = (
            len(detected_techniques) / len(unique_techniques) * 100
            if unique_techniques
            else 0
        )

        # Tactic-level detection rates
        tactic_stats = {}
        for tactic_id, tactic_name in MITRE_TACTICS.items():
            tactic_actions = [a for a in self.actions if a.mitre_tactic == tactic_id]
            tactic_detected = [a for a in tactic_actions if a.detected]
            if tactic_actions:
                tactic_stats[tactic_name] = {
                    "total": len(tactic_actions),
                    "detected": len(tactic_detected),
                    "rate": len(tactic_detected) / len(tactic_actions) * 100,
                }

        # Objective completion
        objectives_achieved = sum(
            1 for obj in self.config.objectives if obj.get("achieved", False)
        )

        return {
            "engagement_id": self.config.engagement_id,
            "total_actions": total_actions,
            "successful_actions": len(successful_actions),
            "success_rate": len(successful_actions) / total_actions * 100 if total_actions else 0,
            "detected_actions": len(detected_actions),
            "detection_rate": len(detected_actions) / total_actions * 100 if total_actions else 0,
            "mttd_hours": mttd_hours,
            "unique_techniques_used": len(unique_techniques),
            "unique_techniques_detected": len(detected_techniques),
            "ttp_coverage_pct": ttp_coverage,
            "tactic_detection_rates": tactic_stats,
            "objectives_total": len(self.config.objectives),
            "objectives_achieved": objectives_achieved,
            "undetected_techniques": list(unique_techniques - detected_techniques),
        }

    def generate_attack_heatmap(self) -> dict:
        """Generate MITRE ATT&CK heatmap data for Navigator."""
        techniques = {}
        for action in self.actions:
            tid = action.mitre_technique_id
            if tid not in techniques:
                techniques[tid] = {
                    "techniqueID": tid,
                    "score": 0,
                    "color": "",
                    "comment": "",
                    "metadata": [],
                }
            techniques[tid]["score"] += 1
            if action.detected:
                techniques[tid]["color"] = "#ff6666"  # Red for detected
                techniques[tid]["comment"] += f"DETECTED by {action.detection_source}; "
            else:
                techniques[tid]["color"] = "#66ff66"  # Green for undetected
                techniques[tid]["comment"] += f"UNDETECTED: {action.description}; "

        navigator_layer = {
            "name": f"Red Team - {self.config.engagement_id}",
            "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Red team engagement for {self.config.client_name}",
            "techniques": list(techniques.values()),
            "gradient": {
                "colors": ["#66ff66", "#ffff66", "#ff6666"],
                "minValue": 0,
                "maxValue": 5,
            },
        }

        output_path = os.path.join(
            self.output_dir, f"{self.config.engagement_id}_navigator.json"
        )
        with open(output_path, "w") as f:
            json.dump(navigator_layer, f, indent=2)

        print(f"[+] ATT&CK Navigator layer saved to: {output_path}")
        return navigator_layer

    def generate_detection_gap_report(self) -> str:
        """Generate a detection gap analysis report."""
        metrics = self.calculate_metrics()
        lines = []
        lines.append("=" * 70)
        lines.append("DETECTION GAP ANALYSIS REPORT")
        lines.append(f"Engagement: {self.config.engagement_id}")
        lines.append(f"Client: {self.config.client_name}")
        lines.append(f"Period: {self.config.start_date} to {self.config.end_date}")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Overall Detection Rate: {metrics['detection_rate']:.1f}%")
        lines.append(f"TTP Coverage: {metrics['ttp_coverage_pct']:.1f}%")
        if metrics["mttd_hours"]:
            lines.append(f"Mean Time to Detect: {metrics['mttd_hours']:.1f} hours")
        lines.append("")
        lines.append("-" * 70)
        lines.append("TACTIC-LEVEL DETECTION RATES")
        lines.append("-" * 70)

        for tactic_name, stats in metrics.get("tactic_detection_rates", {}).items():
            bar = "#" * int(stats["rate"] / 5) + "-" * (20 - int(stats["rate"] / 5))
            lines.append(
                f"  {tactic_name:<25} [{bar}] {stats['rate']:.0f}% "
                f"({stats['detected']}/{stats['total']})"
            )

        lines.append("")
        lines.append("-" * 70)
        lines.append("UNDETECTED TECHNIQUES (GAPS)")
        lines.append("-" * 70)

        for tid in metrics.get("undetected_techniques", []):
            tech_info = COMMON_TECHNIQUES.get(tid, {})
            name = tech_info.get("name", "Unknown")
            lines.append(f"  [!] {tid} - {name}")
            relevant_actions = [
                a for a in self.actions if a.mitre_technique_id == tid and not a.detected
            ]
            for action in relevant_actions:
                lines.append(f"      Tool: {action.tool_used} | Target: {action.target_host}")

        lines.append("")
        lines.append("-" * 70)
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 70)

        for tid in metrics.get("undetected_techniques", []):
            tech_info = COMMON_TECHNIQUES.get(tid, {})
            name = tech_info.get("name", "Unknown")
            lines.append(f"  [{tid}] {name}")
            if tid == "T1003.001":
                lines.append("    -> Enable Credential Guard and LSASS protection")
                lines.append("    -> Deploy Sysmon with EventID 10 (ProcessAccess) rules")
            elif tid == "T1558.003":
                lines.append("    -> Use Group Managed Service Accounts (gMSA)")
                lines.append("    -> Monitor EventID 4769 for RC4 ticket requests")
            elif tid == "T1055":
                lines.append("    -> Deploy EDR with memory scanning capabilities")
                lines.append("    -> Monitor for cross-process injection (Sysmon EventID 8)")
            elif tid == "T1021.002":
                lines.append("    -> Restrict lateral movement with Windows Firewall")
                lines.append("    -> Monitor for EventID 5140/5145 (network share access)")
            elif tid == "T1550.002":
                lines.append("    -> Enable Restricted Admin Mode for RDP")
                lines.append("    -> Deploy Windows Defender Credential Guard")
            else:
                lines.append("    -> Review MITRE ATT&CK mitigations for this technique")
                lines.append("    -> Create detection rule in SIEM for related events")

        report_text = "\n".join(lines)

        report_path = os.path.join(
            self.output_dir, f"{self.config.engagement_id}_gap_report.txt"
        )
        with open(report_path, "w") as f:
            f.write(report_text)

        print(f"[+] Gap report saved to: {report_path}")
        return report_text

    def export_timeline_csv(self) -> str:
        """Export engagement timeline as CSV for analysis."""
        csv_path = os.path.join(
            self.output_dir, f"{self.config.engagement_id}_timeline.csv"
        )
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp", "Phase", "Tactic", "Technique ID", "Technique Name",
                "Description", "Target", "Tool", "Outcome", "Detected",
                "Detection Time", "Detection Source", "Operator",
            ])
            for action in sorted(self.actions, key=lambda a: a.timestamp):
                writer.writerow([
                    action.timestamp, action.phase, action.mitre_tactic,
                    action.mitre_technique_id, action.mitre_technique_name,
                    action.description, action.target_host, action.tool_used,
                    action.outcome, action.detected, action.detection_time,
                    action.detection_source, action.operator,
                ])

        print(f"[+] Timeline CSV saved to: {csv_path}")
        return csv_path

    def generate_executive_summary(self) -> str:
        """Generate executive summary for leadership."""
        metrics = self.calculate_metrics()
        summary = f"""
EXECUTIVE SUMMARY - RED TEAM ENGAGEMENT
========================================
Engagement ID: {self.config.engagement_id}
Client: {self.config.client_name}
Period: {self.config.start_date} to {self.config.end_date}
Threat Profile: {self.config.threat_profile}

KEY FINDINGS:
- {metrics['unique_techniques_used']} unique ATT&CK techniques were executed
- {metrics['detection_rate']:.0f}% of red team actions were detected by the SOC
- {metrics['ttp_coverage_pct']:.0f}% of techniques used had at least one detection
- {len(metrics.get('undetected_techniques', []))} technique(s) had ZERO detection coverage
- {metrics['objectives_achieved']}/{metrics['objectives_total']} engagement objectives achieved

RISK RATING: {'CRITICAL' if metrics['detection_rate'] < 30 else 'HIGH' if metrics['detection_rate'] < 50 else 'MEDIUM' if metrics['detection_rate'] < 70 else 'LOW'}

The red team {'successfully' if metrics['success_rate'] > 50 else 'partially'} achieved the defined objectives,
demonstrating that the organization's current security posture requires
{'immediate remediation' if metrics['detection_rate'] < 30 else 'significant improvement' if metrics['detection_rate'] < 50 else 'targeted improvements' if metrics['detection_rate'] < 70 else 'minor tuning'}.
"""
        return summary


def main():
    """Demonstrate the engagement tracker with sample data."""
    config = EngagementConfig(
        engagement_id="RT-2025-001",
        client_name="Example Corp",
        start_date="2025-01-15",
        end_date="2025-02-15",
        scope=["10.0.0.0/8", "*.example.com"],
        out_of_scope=["10.0.99.0/24", "production-db.example.com"],
        objectives=[
            {"name": "Achieve Domain Admin", "achieved": True},
            {"name": "Exfiltrate PII data", "achieved": True},
            {"name": "Access SCADA network", "achieved": False},
        ],
        threat_profile="APT29 (Cozy Bear)",
        emergency_contact="CISO: +1-555-0100",
    )

    tracker = RedTeamEngagementTracker(config)

    sample_actions = [
        RedTeamAction(
            timestamp="2025-01-16T09:00:00",
            phase="reconnaissance",
            mitre_tactic="TA0043",
            mitre_technique_id="T1593",
            mitre_technique_name="Search Open Websites/Domains",
            description="Subdomain enumeration using Amass",
            target_host="example.com",
            tool_used="Amass",
            outcome="success",
            detected=False,
            operator="operator1",
        ),
        RedTeamAction(
            timestamp="2025-01-20T14:30:00",
            phase="initial_access",
            mitre_tactic="TA0001",
            mitre_technique_id="T1566.001",
            mitre_technique_name="Spearphishing Attachment",
            description="Sent phishing email with macro-enabled document to HR team",
            target_host="mail.example.com",
            tool_used="GoPhish",
            outcome="success",
            detected=True,
            detection_time="2025-01-20T15:45:00",
            detection_source="Proofpoint Email Gateway",
            operator="operator1",
        ),
        RedTeamAction(
            timestamp="2025-01-22T10:00:00",
            phase="execution",
            mitre_tactic="TA0002",
            mitre_technique_id="T1059.001",
            mitre_technique_name="PowerShell",
            description="Executed PowerShell stager on workstation WS-042",
            target_host="WS-042.example.com",
            tool_used="Havoc C2",
            outcome="success",
            detected=False,
            operator="operator2",
        ),
        RedTeamAction(
            timestamp="2025-01-23T08:15:00",
            phase="credential_access",
            mitre_tactic="TA0006",
            mitre_technique_id="T1003.001",
            mitre_technique_name="LSASS Memory",
            description="Dumped LSASS process memory using SafetyKatz",
            target_host="WS-042.example.com",
            tool_used="SafetyKatz",
            outcome="success",
            detected=True,
            detection_time="2025-01-23T08:20:00",
            detection_source="CrowdStrike Falcon",
            operator="operator2",
        ),
        RedTeamAction(
            timestamp="2025-01-24T11:00:00",
            phase="credential_access",
            mitre_tactic="TA0006",
            mitre_technique_id="T1558.003",
            mitre_technique_name="Kerberoasting",
            description="Kerberoasted 15 service accounts using Rubeus",
            target_host="DC01.example.com",
            tool_used="Rubeus",
            outcome="success",
            detected=False,
            operator="operator1",
        ),
        RedTeamAction(
            timestamp="2025-01-25T14:00:00",
            phase="lateral_movement",
            mitre_tactic="TA0008",
            mitre_technique_id="T1021.002",
            mitre_technique_name="SMB/Windows Admin Shares",
            description="Lateral movement to file server via PsExec",
            target_host="FS01.example.com",
            tool_used="Impacket PsExec",
            outcome="success",
            detected=False,
            operator="operator2",
        ),
        RedTeamAction(
            timestamp="2025-01-28T09:30:00",
            phase="credential_access",
            mitre_tactic="TA0006",
            mitre_technique_id="T1003.006",
            mitre_technique_name="DCSync",
            description="DCSync to extract all domain password hashes",
            target_host="DC01.example.com",
            tool_used="Impacket secretsdump",
            outcome="success",
            detected=True,
            detection_time="2025-01-28T10:15:00",
            detection_source="Microsoft Defender for Identity",
            operator="operator1",
        ),
        RedTeamAction(
            timestamp="2025-01-30T16:00:00",
            phase="exfiltration",
            mitre_tactic="TA0010",
            mitre_technique_id="T1041",
            mitre_technique_name="Exfiltration Over C2 Channel",
            description="Exfiltrated 50MB of staged PII data over C2 HTTPS",
            target_host="FS01.example.com",
            tool_used="Havoc C2",
            outcome="success",
            detected=False,
            operator="operator2",
        ),
    ]

    for action in sample_actions:
        tracker.log_action(action)

    print("\n" + "=" * 70)
    print("GENERATING REPORTS")
    print("=" * 70)

    tracker.generate_attack_heatmap()
    tracker.export_timeline_csv()
    print(tracker.generate_detection_gap_report())
    print(tracker.generate_executive_summary())

    metrics = tracker.calculate_metrics()
    metrics_path = os.path.join(
        tracker.output_dir, f"{config.engagement_id}_metrics.json"
    )
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"[+] Metrics saved to: {metrics_path}")


if __name__ == "__main__":
    main()
