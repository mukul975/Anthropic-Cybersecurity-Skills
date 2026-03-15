#!/usr/bin/env python3
"""
Kerberoasting Analysis and Detection Tool

Parses Kerberos TGS request logs (Event ID 4769) to detect potential
Kerberoasting activity and analyzes extracted hashes for weak passwords.
"""

import json
import os
import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TGSRequest:
    """Represents a Kerberos TGS ticket request (Event ID 4769)."""
    timestamp: str
    source_ip: str
    source_user: str
    target_service: str
    encryption_type: str  # 0x17=RC4, 0x11=AES128, 0x12=AES256
    result_code: str
    ticket_options: str = ""


@dataclass
class KerberoastTarget:
    """A user account vulnerable to Kerberoasting."""
    username: str
    spn: str
    domain: str
    password_last_set: str = ""
    admin_count: bool = False
    member_of: list = field(default_factory=list)
    risk_score: int = 0


@dataclass
class KerberoastAlert:
    """Alert for detected Kerberoasting activity."""
    severity: str
    timestamp: str
    source_ip: str
    source_user: str
    target_count: int
    targets: list = field(default_factory=list)
    encryption_types: list = field(default_factory=list)
    description: str = ""


class KerberoastDetector:
    """Detect Kerberoasting activity from Windows Event Logs."""

    # Detection thresholds
    TGS_REQUEST_THRESHOLD = 5  # requests in window
    TIME_WINDOW_SECONDS = 300  # 5 minutes
    RC4_ETYPE = "0x17"

    def __init__(self):
        self.tgs_requests: list[TGSRequest] = []
        self.alerts: list[KerberoastAlert] = []
        self.targets: list[KerberoastTarget] = []

    def parse_event_log(self, log_entries: list[dict]) -> None:
        """Parse Windows Event ID 4769 entries."""
        for entry in log_entries:
            if entry.get("EventID") != 4769:
                continue

            event_data = entry.get("EventData", {})
            req = TGSRequest(
                timestamp=entry.get("TimeCreated", ""),
                source_ip=event_data.get("IpAddress", ""),
                source_user=event_data.get("TargetUserName", ""),
                target_service=event_data.get("ServiceName", ""),
                encryption_type=event_data.get("TicketEncryptionType", ""),
                result_code=event_data.get("Status", ""),
                ticket_options=event_data.get("TicketOptions", ""),
            )
            self.tgs_requests.append(req)

    def detect_kerberoasting(self) -> list[KerberoastAlert]:
        """Analyze TGS requests for Kerberoasting indicators."""
        self.alerts = []

        # Group requests by source user and time window
        user_requests = defaultdict(list)
        for req in self.tgs_requests:
            user_requests[req.source_user].append(req)

        for user, requests in user_requests.items():
            # Sort by timestamp
            requests.sort(key=lambda r: r.timestamp)

            # Sliding window detection
            for i, req in enumerate(requests):
                window_reqs = []
                try:
                    req_time = datetime.fromisoformat(req.timestamp.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    continue

                for j in range(i, len(requests)):
                    try:
                        other_time = datetime.fromisoformat(
                            requests[j].timestamp.replace("Z", "+00:00")
                        )
                    except (ValueError, AttributeError):
                        continue
                    if (other_time - req_time).total_seconds() <= self.TIME_WINDOW_SECONDS:
                        window_reqs.append(requests[j])
                    else:
                        break

                # Check threshold
                if len(window_reqs) >= self.TGS_REQUEST_THRESHOLD:
                    rc4_reqs = [r for r in window_reqs if r.encryption_type == self.RC4_ETYPE]
                    unique_services = set(r.target_service for r in window_reqs)

                    severity = "critical" if len(rc4_reqs) > 0 else "high"
                    if len(unique_services) > 10:
                        severity = "critical"

                    alert = KerberoastAlert(
                        severity=severity,
                        timestamp=req.timestamp,
                        source_ip=req.source_ip,
                        source_user=user,
                        target_count=len(unique_services),
                        targets=list(unique_services),
                        encryption_types=list(set(r.encryption_type for r in window_reqs)),
                        description=(
                            f"User {user} from {req.source_ip} requested "
                            f"{len(window_reqs)} TGS tickets for {len(unique_services)} "
                            f"unique services within {self.TIME_WINDOW_SECONDS}s window. "
                            f"RC4 requests: {len(rc4_reqs)}/{len(window_reqs)}."
                        ),
                    )
                    self.alerts.append(alert)
                    break  # One alert per user

        return self.alerts

    def analyze_kerberoast_targets(self, targets: list[KerberoastTarget]) -> list[dict]:
        """Analyze and risk-score Kerberoastable accounts."""
        self.targets = targets
        scored_targets = []

        for target in targets:
            score = 0
            risk_factors = []

            # Check if privileged
            if target.admin_count:
                score += 40
                risk_factors.append("AdminCount=1 (privileged account)")

            privileged_groups = [
                "domain admins", "enterprise admins", "schema admins",
                "backup operators", "server operators", "account operators",
            ]
            for group in target.member_of:
                if group.lower() in privileged_groups:
                    score += 30
                    risk_factors.append(f"Member of {group}")

            # Check password age
            if target.password_last_set:
                try:
                    pwd_date = datetime.fromisoformat(target.password_last_set)
                    age_days = (datetime.now() - pwd_date).days
                    if age_days > 730:  # 2 years
                        score += 25
                        risk_factors.append(f"Password age: {age_days} days (>2 years)")
                    elif age_days > 365:
                        score += 15
                        risk_factors.append(f"Password age: {age_days} days (>1 year)")
                    elif age_days > 180:
                        score += 10
                        risk_factors.append(f"Password age: {age_days} days (>6 months)")
                except ValueError:
                    pass

            # Check SPN type
            high_value_spns = ["MSSQLSvc", "HTTP", "exchangeMDB", "ldap"]
            for spn_prefix in high_value_spns:
                if target.spn.startswith(spn_prefix):
                    score += 10
                    risk_factors.append(f"High-value SPN type: {spn_prefix}")
                    break

            target.risk_score = min(score, 100)

            scored_targets.append({
                "username": target.username,
                "spn": target.spn,
                "domain": target.domain,
                "risk_score": target.risk_score,
                "risk_level": (
                    "critical" if score >= 60
                    else "high" if score >= 40
                    else "medium" if score >= 20
                    else "low"
                ),
                "risk_factors": risk_factors,
                "password_last_set": target.password_last_set,
                "admin_count": target.admin_count,
            })

        scored_targets.sort(key=lambda t: t["risk_score"], reverse=True)
        return scored_targets

    def generate_report(self) -> str:
        """Generate Kerberoasting analysis report."""
        lines = []
        lines.append("=" * 70)
        lines.append("KERBEROASTING ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 70)

        # Detection results
        if self.alerts:
            lines.append(f"\nDETECTED KERBEROASTING ACTIVITY: {len(self.alerts)} alert(s)")
            lines.append("-" * 70)
            for i, alert in enumerate(self.alerts, 1):
                lines.append(f"\n  Alert #{i} [{alert.severity.upper()}]")
                lines.append(f"  Source: {alert.source_user} @ {alert.source_ip}")
                lines.append(f"  Time: {alert.timestamp}")
                lines.append(f"  Targets: {alert.target_count} services")
                lines.append(f"  Encryption: {', '.join(alert.encryption_types)}")
                lines.append(f"  Details: {alert.description}")
        else:
            lines.append("\nNo Kerberoasting activity detected in analyzed logs.")

        # Target analysis
        if self.targets:
            lines.append(f"\nKERBEROASTABLE ACCOUNTS: {len(self.targets)}")
            lines.append("-" * 70)
            for target in sorted(self.targets, key=lambda t: t.risk_score, reverse=True):
                level = (
                    "CRITICAL" if target.risk_score >= 60
                    else "HIGH" if target.risk_score >= 40
                    else "MEDIUM" if target.risk_score >= 20
                    else "LOW"
                )
                lines.append(
                    f"  [{level}] {target.username} "
                    f"(Score: {target.risk_score}/100) "
                    f"SPN: {target.spn}"
                )

        lines.append("\nREMEDIATION RECOMMENDATIONS:")
        lines.append("-" * 70)
        lines.append("  1. Convert service accounts to Group Managed Service Accounts (gMSA)")
        lines.append("  2. Enforce 25+ character passwords on remaining service accounts")
        lines.append("  3. Disable RC4 encryption via Group Policy")
        lines.append("  4. Add sensitive accounts to Protected Users group")
        lines.append("  5. Deploy SIEM rule for Event ID 4769 with RC4 encryption type")
        lines.append("  6. Create honeypot SPN accounts for early detection")

        return "\n".join(lines)


def main():
    """Demonstrate Kerberoasting detection and analysis."""
    detector = KerberoastDetector()

    # Simulate Event ID 4769 logs (Kerberoasting pattern)
    sample_events = []
    base_time = datetime(2025, 1, 15, 10, 30, 0)
    services = [
        "MSSQLSvc/SQL01", "HTTP/WEB01", "HOST/BACKUP01",
        "MSSQLSvc/SQL02", "exchangeMDB/EX01", "HTTP/APP01",
        "ldap/DC02", "HOST/FILE01",
    ]
    for i, svc in enumerate(services):
        sample_events.append({
            "EventID": 4769,
            "TimeCreated": (base_time + timedelta(seconds=i * 5)).isoformat(),
            "EventData": {
                "TargetUserName": "jsmith",
                "ServiceName": svc,
                "IpAddress": "10.10.10.50",
                "TicketEncryptionType": "0x17",
                "Status": "0x0",
                "TicketOptions": "0x40810000",
            },
        })

    detector.parse_event_log(sample_events)
    detector.detect_kerberoasting()

    # Analyze Kerberoastable targets
    targets = [
        KerberoastTarget(
            username="svc_sql", spn="MSSQLSvc/SQL01.corp.local:1433",
            domain="corp.local", password_last_set="2022-06-15T10:00:00",
            admin_count=True, member_of=["Domain Admins"],
        ),
        KerberoastTarget(
            username="svc_web", spn="HTTP/web01.corp.local",
            domain="corp.local", password_last_set="2024-01-20T14:00:00",
            admin_count=False, member_of=["Web Admins"],
        ),
        KerberoastTarget(
            username="svc_backup", spn="HOST/backup01.corp.local",
            domain="corp.local", password_last_set="2021-03-01T08:00:00",
            admin_count=True, member_of=["Backup Operators"],
        ),
    ]
    detector.analyze_kerberoast_targets(targets)
    print(detector.generate_report())


if __name__ == "__main__":
    main()
