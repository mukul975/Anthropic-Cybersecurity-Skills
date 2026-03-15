#!/usr/bin/env python3
"""
Social Engineering Campaign Tracker

Tracks vishing (pretext call) campaign results, calculates susceptibility
metrics, and generates reports for security awareness improvement.
"""

import json
import os
import csv
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field, asdict


@dataclass
class VishingCall:
    """Represents a single vishing call attempt."""
    call_id: str
    timestamp: str
    target_name: str
    target_department: str
    target_role: str
    pretext_used: str
    call_duration_seconds: int
    call_answered: bool
    credential_disclosed: bool
    sensitive_info_disclosed: bool
    info_type_disclosed: str = ""  # password, username, badge_number, etc.
    verification_attempted: bool = False
    reported_to_security: bool = False
    susceptibility_score: int = 0  # 1-5
    notes: str = ""
    operator: str = ""


class VishingCampaignTracker:
    """Track and analyze vishing campaign results."""

    def __init__(self, campaign_id: str, client_name: str):
        self.campaign_id = campaign_id
        self.client_name = client_name
        self.calls: list[VishingCall] = []

    def log_call(self, call: VishingCall) -> None:
        """Log a vishing call result."""
        self.calls.append(call)

    def calculate_metrics(self) -> dict:
        """Calculate campaign metrics."""
        answered = [c for c in self.calls if c.call_answered]
        total_answered = len(answered)
        if total_answered == 0:
            return {"error": "No answered calls to analyze"}

        cred_disclosed = [c for c in answered if c.credential_disclosed]
        info_disclosed = [c for c in answered if c.sensitive_info_disclosed]
        verified = [c for c in answered if c.verification_attempted]
        reported = [c for c in answered if c.reported_to_security]

        # Per-department breakdown
        dept_stats = defaultdict(lambda: {
            "total": 0, "cred_disclosed": 0, "info_disclosed": 0,
            "verified": 0, "reported": 0,
        })
        for call in answered:
            dept = call.target_department
            dept_stats[dept]["total"] += 1
            if call.credential_disclosed:
                dept_stats[dept]["cred_disclosed"] += 1
            if call.sensitive_info_disclosed:
                dept_stats[dept]["info_disclosed"] += 1
            if call.verification_attempted:
                dept_stats[dept]["verified"] += 1
            if call.reported_to_security:
                dept_stats[dept]["reported"] += 1

        # Per-pretext breakdown
        pretext_stats = defaultdict(lambda: {"total": 0, "success": 0})
        for call in answered:
            pretext_stats[call.pretext_used]["total"] += 1
            if call.credential_disclosed or call.sensitive_info_disclosed:
                pretext_stats[call.pretext_used]["success"] += 1

        avg_duration = sum(c.call_duration_seconds for c in answered) / total_answered
        avg_susceptibility = sum(c.susceptibility_score for c in answered) / total_answered

        return {
            "campaign_id": self.campaign_id,
            "total_calls": len(self.calls),
            "calls_answered": total_answered,
            "answer_rate": total_answered / len(self.calls) * 100,
            "credential_disclosure_rate": len(cred_disclosed) / total_answered * 100,
            "sensitive_info_disclosure_rate": len(info_disclosed) / total_answered * 100,
            "verification_rate": len(verified) / total_answered * 100,
            "security_reporting_rate": len(reported) / total_answered * 100,
            "avg_call_duration_seconds": avg_duration,
            "avg_susceptibility_score": avg_susceptibility,
            "department_breakdown": dict(dept_stats),
            "pretext_effectiveness": dict(pretext_stats),
        }

    def generate_report(self) -> str:
        """Generate campaign report."""
        metrics = self.calculate_metrics()
        if "error" in metrics:
            return metrics["error"]

        lines = []
        lines.append("=" * 70)
        lines.append("VISHING CAMPAIGN ASSESSMENT REPORT")
        lines.append(f"Campaign: {self.campaign_id}")
        lines.append(f"Client: {self.client_name}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        lines.append("=" * 70)

        lines.append(f"\nOVERALL METRICS:")
        lines.append(f"  Total Calls Made:           {metrics['total_calls']}")
        lines.append(f"  Calls Answered:              {metrics['calls_answered']}")
        lines.append(f"  Answer Rate:                 {metrics['answer_rate']:.1f}%")
        lines.append(f"  Credential Disclosure Rate:  {metrics['credential_disclosure_rate']:.1f}%")
        lines.append(f"  Info Disclosure Rate:         {metrics['sensitive_info_disclosure_rate']:.1f}%")
        lines.append(f"  Verification Rate:           {metrics['verification_rate']:.1f}%")
        lines.append(f"  Security Reporting Rate:     {metrics['security_reporting_rate']:.1f}%")
        lines.append(f"  Avg Call Duration:           {metrics['avg_call_duration_seconds']:.0f}s")
        lines.append(f"  Avg Susceptibility (1-5):    {metrics['avg_susceptibility_score']:.1f}")

        # Risk assessment
        cred_rate = metrics['credential_disclosure_rate']
        risk = "CRITICAL" if cred_rate > 30 else "HIGH" if cred_rate > 15 else "MEDIUM" if cred_rate > 5 else "LOW"
        lines.append(f"\n  OVERALL RISK RATING: {risk}")

        # Department breakdown
        lines.append(f"\nDEPARTMENT BREAKDOWN:")
        lines.append("-" * 70)
        for dept, stats in metrics["department_breakdown"].items():
            total = stats["total"]
            cred_pct = stats["cred_disclosed"] / total * 100 if total else 0
            verify_pct = stats["verified"] / total * 100 if total else 0
            lines.append(
                f"  {dept:<20} Calls: {total:>3} | "
                f"Cred Disclosed: {cred_pct:>5.1f}% | "
                f"Verified: {verify_pct:>5.1f}%"
            )

        # Pretext effectiveness
        lines.append(f"\nPRETEXT EFFECTIVENESS:")
        lines.append("-" * 70)
        for pretext, stats in metrics["pretext_effectiveness"].items():
            success_rate = stats["success"] / stats["total"] * 100 if stats["total"] else 0
            lines.append(f"  {pretext:<30} Success: {success_rate:.1f}% ({stats['success']}/{stats['total']})")

        # Recommendations
        lines.append(f"\nRECOMMENDATIONS:")
        lines.append("-" * 70)
        if metrics["credential_disclosure_rate"] > 10:
            lines.append("  [CRITICAL] Implement mandatory caller verification procedures")
        if metrics["verification_rate"] < 50:
            lines.append("  [HIGH] Enhance security awareness training on verification")
        if metrics["security_reporting_rate"] < 30:
            lines.append("  [HIGH] Establish easy-to-use suspicious call reporting process")
        lines.append("  [MEDIUM] Conduct quarterly vishing simulations")
        lines.append("  [MEDIUM] Implement callback verification for sensitive requests")

        return "\n".join(lines)

    def export_csv(self, output_path: str) -> None:
        """Export results to CSV."""
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Call ID", "Timestamp", "Target", "Department", "Role",
                "Pretext", "Duration(s)", "Answered", "Cred Disclosed",
                "Info Disclosed", "Verified", "Reported", "Score",
            ])
            for call in self.calls:
                writer.writerow([
                    call.call_id, call.timestamp, call.target_name,
                    call.target_department, call.target_role, call.pretext_used,
                    call.call_duration_seconds, call.call_answered,
                    call.credential_disclosed, call.sensitive_info_disclosed,
                    call.verification_attempted, call.reported_to_security,
                    call.susceptibility_score,
                ])


def main():
    """Demonstrate vishing campaign tracking."""
    tracker = VishingCampaignTracker("VISH-2025-001", "Example Corp")

    sample_calls = [
        VishingCall("V001", "2025-02-01T09:00:00", "Alice Johnson", "Finance",
                    "Accountant", "IT Helpdesk - VPN Update", 180, True, True,
                    True, "password", False, False, 5),
        VishingCall("V002", "2025-02-01T09:30:00", "Bob Smith", "IT",
                    "Sysadmin", "Vendor Support Call", 45, True, False,
                    False, "", True, True, 1),
        VishingCall("V003", "2025-02-01T10:00:00", "Carol Davis", "HR",
                    "HR Manager", "Benefits Verification", 120, True, False,
                    True, "employee_id", False, False, 3),
        VishingCall("V004", "2025-02-01T10:30:00", "Dan Wilson", "Finance",
                    "Controller", "Wire Transfer Request", 60, True, False,
                    False, "", True, True, 1),
        VishingCall("V005", "2025-02-01T11:00:00", "Eve Brown", "Marketing",
                    "Manager", "IT Helpdesk - Password Reset", 150, True, True,
                    True, "password", False, False, 4),
        VishingCall("V006", "2025-02-01T11:30:00", "Frank Lee", "Engineering",
                    "Developer", "IT Helpdesk - VPN Update", 30, True, False,
                    False, "", True, False, 2),
        VishingCall("V007", "2025-02-01T13:00:00", "Grace Kim", "Reception",
                    "Front Desk", "Delivery Confirmation", 90, True, False,
                    True, "employee_directory", False, False, 3),
        VishingCall("V008", "2025-02-01T13:30:00", "Henry Chen", "IT",
                    "Help Desk", "New Employee Onboarding", 20, True, False,
                    False, "", True, True, 1),
    ]

    for call in sample_calls:
        tracker.log_call(call)

    print(tracker.generate_report())
    tracker.export_csv("vishing_results.csv")
    print(f"\n[+] Results exported to vishing_results.csv")


if __name__ == "__main__":
    main()
