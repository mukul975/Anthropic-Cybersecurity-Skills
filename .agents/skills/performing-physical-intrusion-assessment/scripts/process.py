#!/usr/bin/env python3
"""
Physical Security Assessment Tracker

Tracks physical intrusion testing attempts, documents findings,
and generates assessment reports with remediation recommendations.
"""

import json
import os
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field, asdict


@dataclass
class PhysicalAccessAttempt:
    """A single physical access test attempt."""
    attempt_id: str
    timestamp: str
    location: str
    entry_point: str  # main_entrance, side_door, loading_dock, etc.
    technique: str  # tailgating, badge_clone, lock_pick, social_engineering
    target_area: str  # lobby, server_room, executive_floor, data_center
    successful: bool
    detected: bool
    challenged: bool  # was tester confronted/questioned
    security_notified: bool
    time_inside_minutes: int = 0
    device_deployed: bool = False
    device_type: str = ""
    evidence_collected: str = ""
    notes: str = ""
    severity: str = ""  # critical, high, medium, low


class PhysicalAssessmentTracker:
    """Track physical security assessment results."""

    def __init__(self, assessment_id: str, facility_name: str):
        self.assessment_id = assessment_id
        self.facility_name = facility_name
        self.attempts: list[PhysicalAccessAttempt] = []

    def log_attempt(self, attempt: PhysicalAccessAttempt) -> None:
        """Log an access attempt."""
        # Auto-assign severity
        if not attempt.severity:
            if attempt.target_area in ("server_room", "data_center") and attempt.successful:
                attempt.severity = "critical"
            elif attempt.successful and not attempt.detected:
                attempt.severity = "high"
            elif attempt.successful and attempt.detected:
                attempt.severity = "medium"
            else:
                attempt.severity = "low"
        self.attempts.append(attempt)

    def calculate_metrics(self) -> dict:
        """Calculate assessment metrics."""
        total = len(self.attempts)
        if total == 0:
            return {}

        successful = [a for a in self.attempts if a.successful]
        detected = [a for a in self.attempts if a.detected]
        challenged = [a for a in self.attempts if a.challenged]
        devices = [a for a in self.attempts if a.device_deployed]

        # By technique
        technique_stats = defaultdict(lambda: {"total": 0, "success": 0})
        for a in self.attempts:
            technique_stats[a.technique]["total"] += 1
            if a.successful:
                technique_stats[a.technique]["success"] += 1

        # By area
        area_stats = defaultdict(lambda: {"total": 0, "success": 0})
        for a in self.attempts:
            area_stats[a.target_area]["total"] += 1
            if a.successful:
                area_stats[a.target_area]["success"] += 1

        return {
            "total_attempts": total,
            "successful_entries": len(successful),
            "success_rate": len(successful) / total * 100,
            "detection_rate": len(detected) / total * 100,
            "challenge_rate": len(challenged) / total * 100,
            "devices_deployed": len(devices),
            "technique_breakdown": dict(technique_stats),
            "area_breakdown": dict(area_stats),
            "avg_time_inside": (
                sum(a.time_inside_minutes for a in successful) / len(successful)
                if successful else 0
            ),
        }

    def generate_report(self) -> str:
        """Generate assessment report."""
        metrics = self.calculate_metrics()
        if not metrics:
            return "No attempts logged."

        lines = []
        lines.append("=" * 70)
        lines.append("PHYSICAL SECURITY ASSESSMENT REPORT")
        lines.append(f"Assessment ID: {self.assessment_id}")
        lines.append(f"Facility: {self.facility_name}")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        lines.append("=" * 70)

        lines.append(f"\nSUMMARY:")
        lines.append(f"  Total Attempts:       {metrics['total_attempts']}")
        lines.append(f"  Successful Entries:    {metrics['successful_entries']}")
        lines.append(f"  Success Rate:          {metrics['success_rate']:.1f}%")
        lines.append(f"  Detection Rate:        {metrics['detection_rate']:.1f}%")
        lines.append(f"  Challenge Rate:        {metrics['challenge_rate']:.1f}%")
        lines.append(f"  Devices Deployed:      {metrics['devices_deployed']}")
        lines.append(f"  Avg Time Inside:       {metrics['avg_time_inside']:.0f} minutes")

        risk = (
            "CRITICAL" if metrics['success_rate'] > 60
            else "HIGH" if metrics['success_rate'] > 40
            else "MEDIUM" if metrics['success_rate'] > 20
            else "LOW"
        )
        lines.append(f"\n  OVERALL RISK: {risk}")

        lines.append(f"\nTECHNIQUE EFFECTIVENESS:")
        lines.append("-" * 70)
        for tech, stats in metrics["technique_breakdown"].items():
            rate = stats["success"] / stats["total"] * 100 if stats["total"] else 0
            lines.append(f"  {tech:<25} {rate:>5.1f}% ({stats['success']}/{stats['total']})")

        lines.append(f"\nAREA ACCESS:")
        lines.append("-" * 70)
        for area, stats in metrics["area_breakdown"].items():
            rate = stats["success"] / stats["total"] * 100 if stats["total"] else 0
            lines.append(f"  {area:<25} {rate:>5.1f}% ({stats['success']}/{stats['total']})")

        lines.append(f"\nDETAILED FINDINGS:")
        lines.append("-" * 70)
        for a in sorted(self.attempts, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 4)):
            status = "SUCCESS" if a.successful else "FAILED"
            lines.append(f"\n  [{a.severity.upper()}] {a.location} - {a.entry_point}")
            lines.append(f"    Technique: {a.technique} | Result: {status}")
            lines.append(f"    Detected: {'Yes' if a.detected else 'No'} | "
                        f"Challenged: {'Yes' if a.challenged else 'No'}")
            if a.device_deployed:
                lines.append(f"    Device Deployed: {a.device_type}")
            if a.notes:
                lines.append(f"    Notes: {a.notes}")

        lines.append(f"\nREMEDIATIONS:")
        lines.append("-" * 70)
        if metrics["success_rate"] > 50:
            lines.append("  [CRITICAL] Physical access controls require immediate review")
        if any(a.technique == "tailgating" and a.successful for a in self.attempts):
            lines.append("  [HIGH] Install mantraps or anti-tailgating turnstiles")
            lines.append("  [HIGH] Implement security awareness training on tailgating")
        if any(a.technique == "badge_clone" and a.successful for a in self.attempts):
            lines.append("  [HIGH] Upgrade to encrypted RFID (SEOS, DESFire EV2)")
        if metrics["challenge_rate"] < 50:
            lines.append("  [HIGH] Improve guard challenge procedures")
        if any(a.device_deployed for a in self.attempts):
            lines.append("  [CRITICAL] Implement physical port security controls")

        return "\n".join(lines)


def main():
    """Demonstrate physical assessment tracking."""
    tracker = PhysicalAssessmentTracker("PHYS-2025-001", "Example Corp HQ")

    attempts = [
        PhysicalAccessAttempt("P001", "2025-02-10T08:45:00", "Main Building",
            "main_entrance", "tailgating", "lobby", True, False, False, False, 45,
            notes="Followed group during morning rush"),
        PhysicalAccessAttempt("P002", "2025-02-10T10:00:00", "Main Building",
            "side_door", "badge_clone", "office_floor", True, False, False, False, 30,
            notes="Cloned badge from elevator reading"),
        PhysicalAccessAttempt("P003", "2025-02-10T14:00:00", "Data Center Wing",
            "secured_door", "badge_clone", "server_room", True, True, True, True, 5,
            device_deployed=True, device_type="LAN Turtle",
            notes="Guard challenged but accepted fake contractor story"),
        PhysicalAccessAttempt("P004", "2025-02-11T07:30:00", "Loading Dock",
            "loading_dock", "social_engineering", "warehouse", True, False, False, False, 20,
            notes="Posed as delivery driver with empty boxes"),
        PhysicalAccessAttempt("P005", "2025-02-11T12:00:00", "Executive Floor",
            "elevator", "tailgating", "executive_office", False, True, True, True, 0,
            notes="Security escort required, access denied"),
    ]

    for attempt in attempts:
        tracker.log_attempt(attempt)

    print(tracker.generate_report())


if __name__ == "__main__":
    main()
