#!/usr/bin/env python3
"""
Zerologon (CVE-2020-1472) Vulnerability Scanner and Detector

Checks domain controllers for Zerologon vulnerability status
and detects exploitation attempts from Windows Event Logs.
NOTE: This is a detection/scanning tool, not an exploit.
"""

import json
import os
import struct
import socket
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional


@dataclass
class DCTarget:
    """A domain controller to check."""
    hostname: str
    ip: str
    domain: str
    os_version: str = ""
    patch_status: str = "unknown"  # patched, vulnerable, unknown
    enforcement_mode: bool = False


@dataclass
class ZerologonEvent:
    """An event related to Zerologon activity."""
    timestamp: str
    event_id: int
    source_ip: str
    target_dc: str
    account_name: str
    event_type: str = ""
    details: str = ""


@dataclass
class DetectionAlert:
    """Alert for detected Zerologon activity."""
    severity: str
    timestamp: str
    source_ip: str
    target_dc: str
    indicator: str
    description: str
    confidence: str = "high"


class ZerologonScanner:
    """Scan and detect Zerologon vulnerability and exploitation."""

    def __init__(self):
        self.targets: list[DCTarget] = []
        self.events: list[ZerologonEvent] = []
        self.alerts: list[DetectionAlert] = []

    def add_target(self, target: DCTarget) -> None:
        """Add a DC to scan."""
        self.targets.append(target)

    def check_port_open(self, ip: str, port: int, timeout: float = 3.0) -> bool:
        """Check if RPC port is accessible."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except socket.error:
            return False

    def scan_targets(self) -> list[dict]:
        """Scan targets for vulnerability indicators."""
        results = []
        for target in self.targets:
            result = {
                "hostname": target.hostname,
                "ip": target.ip,
                "domain": target.domain,
                "rpc_accessible": False,
                "netlogon_accessible": False,
                "risk_level": "unknown",
                "recommendations": [],
            }

            # Check RPC port
            result["rpc_accessible"] = self.check_port_open(target.ip, 135)
            if not result["rpc_accessible"]:
                result["risk_level"] = "info"
                result["recommendations"].append("RPC port 135 not accessible from scan source")
                results.append(result)
                continue

            # Check if Netlogon is accessible
            result["netlogon_accessible"] = self.check_port_open(target.ip, 445)

            # Assess risk based on available information
            if target.patch_status == "vulnerable":
                result["risk_level"] = "critical"
                result["recommendations"] = [
                    "IMMEDIATELY apply KB4571694 (August 2020 patch)",
                    "Enable enforcement mode via registry",
                    "Monitor Event ID 5805 for exploitation attempts",
                    "Restrict network access to DC from non-essential systems",
                ]
            elif target.patch_status == "patched" and not target.enforcement_mode:
                result["risk_level"] = "medium"
                result["recommendations"] = [
                    "Enable Netlogon enforcement mode",
                    "Verify February 2021 update is installed",
                    "Monitor for non-compliant Netlogon connections",
                ]
            elif target.patch_status == "patched" and target.enforcement_mode:
                result["risk_level"] = "low"
                result["recommendations"] = [
                    "Continue monitoring Event ID 5805",
                    "Ensure all DCs have enforcement mode enabled",
                ]
            else:
                result["risk_level"] = "high"
                result["recommendations"] = [
                    "Verify patch status of this domain controller",
                    "Check for KB4571694 installation",
                    "Enable enforcement mode if patched",
                ]

            results.append(result)

        return results

    def parse_windows_events(self, events: list[dict]) -> None:
        """Parse Windows Security Event Logs for Zerologon indicators."""
        for event in events:
            event_id = event.get("EventID", 0)
            if event_id in (4742, 5805, 4624, 4625):
                ze = ZerologonEvent(
                    timestamp=event.get("TimeCreated", ""),
                    event_id=event_id,
                    source_ip=event.get("EventData", {}).get("IpAddress", ""),
                    target_dc=event.get("Computer", ""),
                    account_name=event.get("EventData", {}).get("TargetUserName", ""),
                    details=json.dumps(event.get("EventData", {})),
                )
                self.events.append(ze)

    def detect_exploitation(self) -> list[DetectionAlert]:
        """Analyze events for Zerologon exploitation patterns."""
        self.alerts = []

        # Pattern 1: Multiple Netlogon failures (Event 5805) in short window
        netlogon_failures = [e for e in self.events if e.event_id == 5805]
        failure_by_source = defaultdict(list)
        for event in netlogon_failures:
            failure_by_source[event.source_ip].append(event)

        for source_ip, failures in failure_by_source.items():
            if len(failures) >= 100:  # Zerologon requires ~256 attempts
                self.alerts.append(DetectionAlert(
                    severity="critical",
                    timestamp=failures[0].timestamp,
                    source_ip=source_ip,
                    target_dc=failures[0].target_dc,
                    indicator="Multiple Netlogon authentication failures",
                    description=(
                        f"Detected {len(failures)} Netlogon failures from {source_ip} "
                        f"targeting {failures[0].target_dc}. This pattern is consistent "
                        f"with Zerologon (CVE-2020-1472) exploitation attempts."
                    ),
                    confidence="high",
                ))

        # Pattern 2: DC machine account password change (Event 4742)
        dc_password_changes = [
            e for e in self.events
            if e.event_id == 4742 and e.account_name.endswith("$")
        ]
        for event in dc_password_changes:
            self.alerts.append(DetectionAlert(
                severity="critical",
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                target_dc=event.target_dc,
                indicator="DC machine account password changed",
                description=(
                    f"Domain controller machine account {event.account_name} "
                    f"password was changed. If unexpected, this may indicate "
                    f"successful Zerologon exploitation."
                ),
                confidence="medium",
            ))

        # Pattern 3: Suspicious logon following Netlogon failures
        success_after_failure = []
        for source_ip, failures in failure_by_source.items():
            successful_logons = [
                e for e in self.events
                if e.event_id == 4624 and e.source_ip == source_ip
                and e.account_name.endswith("$")
            ]
            if successful_logons and len(failures) > 50:
                self.alerts.append(DetectionAlert(
                    severity="critical",
                    timestamp=successful_logons[0].timestamp,
                    source_ip=source_ip,
                    target_dc=successful_logons[0].target_dc,
                    indicator="Successful logon after mass Netlogon failures",
                    description=(
                        f"Successful logon from {source_ip} as {successful_logons[0].account_name} "
                        f"following {len(failures)} Netlogon failures. "
                        f"Strong indicator of Zerologon exploitation."
                    ),
                    confidence="high",
                ))

        return self.alerts

    def generate_report(self) -> str:
        """Generate vulnerability and detection report."""
        scan_results = self.scan_targets()
        lines = []
        lines.append("=" * 70)
        lines.append("ZEROLOGON (CVE-2020-1472) ASSESSMENT REPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 70)

        lines.append("\nVULNERABILITY SCAN RESULTS:")
        lines.append("-" * 70)
        for result in scan_results:
            icon = {"critical": "[!!!]", "high": "[!!]", "medium": "[!]",
                    "low": "[+]", "info": "[i]", "unknown": "[?]"}.get(result["risk_level"], "[?]")
            lines.append(f"\n  {icon} {result['hostname']} ({result['ip']})")
            lines.append(f"      Risk: {result['risk_level'].upper()}")
            lines.append(f"      RPC Access: {'Yes' if result['rpc_accessible'] else 'No'}")
            for rec in result["recommendations"]:
                lines.append(f"      -> {rec}")

        if self.alerts:
            lines.append(f"\nEXPLOITATION DETECTION ALERTS: {len(self.alerts)}")
            lines.append("-" * 70)
            for alert in self.alerts:
                lines.append(f"\n  [{alert.severity.upper()}] {alert.indicator}")
                lines.append(f"    Source: {alert.source_ip} -> {alert.target_dc}")
                lines.append(f"    Time: {alert.timestamp}")
                lines.append(f"    Confidence: {alert.confidence}")
                lines.append(f"    Details: {alert.description}")

        return "\n".join(lines)


def main():
    """Demonstrate Zerologon scanning and detection."""
    scanner = ZerologonScanner()

    # Add DC targets
    scanner.add_target(DCTarget("DC01", "10.10.10.1", "corp.local",
                                "Windows Server 2019", "vulnerable", False))
    scanner.add_target(DCTarget("DC02", "10.10.10.2", "corp.local",
                                "Windows Server 2022", "patched", True))

    # Simulate exploitation event logs
    sample_events = []
    # 200 Netlogon failures (Zerologon attempt)
    for i in range(200):
        sample_events.append({
            "EventID": 5805,
            "TimeCreated": f"2025-01-15T10:30:{i % 60:02d}",
            "Computer": "DC01.corp.local",
            "EventData": {"IpAddress": "10.10.10.50", "TargetUserName": "ATTACKER$"},
        })
    # Followed by machine account password change
    sample_events.append({
        "EventID": 4742,
        "TimeCreated": "2025-01-15T10:31:00",
        "Computer": "DC01.corp.local",
        "EventData": {"IpAddress": "10.10.10.50", "TargetUserName": "DC01$"},
    })
    # Followed by successful logon
    sample_events.append({
        "EventID": 4624,
        "TimeCreated": "2025-01-15T10:31:05",
        "Computer": "DC01.corp.local",
        "EventData": {"IpAddress": "10.10.10.50", "TargetUserName": "DC01$"},
    })

    scanner.parse_windows_events(sample_events)
    scanner.detect_exploitation()
    print(scanner.generate_report())


if __name__ == "__main__":
    main()
