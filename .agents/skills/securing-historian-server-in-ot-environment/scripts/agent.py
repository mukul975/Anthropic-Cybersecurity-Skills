#!/usr/bin/env python3
"""Agent for securing historian servers in OT environments.

Audits network exposure, authentication configuration, data
integrity protections, and DMZ replication architecture of
process historian servers (OSIsoft PI, AVEVA, Honeywell PHD).
"""

import json
import socket
import sys
from pathlib import Path
from datetime import datetime


HISTORIAN_PORTS = {
    5450: ("PI Data Archive", "PI SDK/API connections"),
    5457: ("PI AF Server", "PI Asset Framework"),
    5459: ("PI Notifications", "Notification Service"),
    443: ("HTTPS", "Web API / PI Vision"),
    80: ("HTTP", "Unsecured web interface"),
    1433: ("MS SQL Server", "Direct database access"),
    5432: ("PostgreSQL", "Direct database access"),
    3389: ("RDP", "Remote Desktop"),
    135: ("RPC", "Windows RPC"),
    445: ("SMB", "Windows File Sharing"),
    8080: ("HTTP Alt", "Alternative web interface"),
    502: ("Modbus", "Industrial protocol"),
}

UNNECESSARY_PORTS = {80, 135, 445, 3389, 8080}


class HistorianSecurityAgent:
    """Audits OT historian server security configuration."""

    def __init__(self, historian_ip, historian_type="PI",
                 output_dir="./historian_audit"):
        self.ip = historian_ip
        self.hist_type = historian_type
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def check_network_exposure(self):
        """Scan historian for exposed network services."""
        exposed = []
        for port, (service, desc) in HISTORIAN_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.ip, port))
                sock.close()
                if result == 0:
                    exposed.append({
                        "port": port, "service": service, "description": desc,
                        "unnecessary": port in UNNECESSARY_PORTS,
                    })
            except (socket.error, OSError):
                pass

        for svc in exposed:
            if svc["unnecessary"]:
                self.findings.append({
                    "severity": "high",
                    "category": "Network Exposure",
                    "title": f"Unnecessary service: {svc['service']} (port {svc['port']})",
                    "remediation": f"Disable {svc['service']} or restrict via firewall",
                })
        if any(s["port"] == 80 for s in exposed):
            self.findings.append({
                "severity": "high",
                "category": "Encryption",
                "title": "HTTP (unencrypted) web interface exposed",
                "remediation": "Redirect HTTP to HTTPS and disable port 80",
            })
        return exposed

    def check_authentication(self):
        """Evaluate historian authentication configuration risks."""
        checks = [
            {
                "check": "PI Trust Authentication",
                "severity": "critical",
                "risk": "IP-based auth without credentials",
                "remediation": "Migrate to Windows Integrated Security",
            },
            {
                "check": "Default piadmin account",
                "severity": "critical",
                "risk": "Default admin may have weak password",
                "remediation": "Disable piadmin, use named Windows accounts",
            },
            {
                "check": "Anonymous SDK access",
                "severity": "high",
                "risk": "Unauthenticated PI SDK connections",
                "remediation": "Require authentication for all connections",
            },
            {
                "check": "Shared service accounts",
                "severity": "medium",
                "risk": "Non-attributable access to historian data",
                "remediation": "Use individual named accounts with PI Mappings",
            },
        ]
        for c in checks:
            self.findings.append({
                "severity": c["severity"],
                "category": "Authentication",
                "title": f"Review: {c['check']}",
                "detail": c["risk"],
                "remediation": c["remediation"],
            })
        return checks

    def check_data_integrity(self):
        """Evaluate data integrity protections."""
        checks = [
            {
                "check": "Audit trail for data modifications",
                "severity": "high",
                "detail": "Historical data edits must be logged with before/after values",
                "remediation": "Enable PI audit trail for all modifications",
            },
            {
                "check": "Backup integrity verification",
                "severity": "medium",
                "detail": "Backups should be tested regularly for recovery",
                "remediation": "Implement automated backup verification quarterly",
            },
            {
                "check": "Tag security enforcement",
                "severity": "high",
                "detail": "Per-tag access control must restrict write access",
                "remediation": "Configure tag-level security for critical process points",
            },
        ]
        for c in checks:
            self.findings.append({
                "severity": c["severity"],
                "category": "Data Integrity",
                "title": c["check"],
                "detail": c["detail"],
                "remediation": c["remediation"],
            })
        return checks

    def check_dmz_architecture(self):
        """Evaluate historian DMZ replication architecture."""
        checks = [
            {
                "check": "Data diode or unidirectional gateway",
                "severity": "high",
                "detail": "OT-to-IT replication should use hardware-enforced unidirectional flow",
                "remediation": "Deploy Waterfall or equivalent data diode between OT and DMZ",
            },
            {
                "check": "Enterprise direct access to OT historian",
                "severity": "critical",
                "detail": "Enterprise users must never connect directly to OT historian",
                "remediation": "Route all access through DMZ historian replica",
            },
        ]
        for c in checks:
            self.findings.append({
                "severity": c["severity"],
                "category": "DMZ Architecture",
                "title": c["check"],
                "detail": c["detail"],
                "remediation": c["remediation"],
            })
        return checks

    def generate_report(self):
        exposed = self.check_network_exposure()
        auth = self.check_authentication()
        integrity = self.check_data_integrity()
        dmz = self.check_dmz_architecture()

        severity_counts = {}
        for f in self.findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "historian_ip": self.ip,
            "historian_type": self.hist_type,
            "exposed_services": exposed,
            "severity_summary": severity_counts,
            "total_findings": len(self.findings),
            "findings": self.findings,
        }
        out = self.output_dir / "historian_audit_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <historian_ip> [--type PI|AVEVA|PHD]")
        sys.exit(1)
    ip = sys.argv[1]
    hist_type = "PI"
    if "--type" in sys.argv:
        hist_type = sys.argv[sys.argv.index("--type") + 1]
    agent = HistorianSecurityAgent(ip, hist_type)
    agent.generate_report()


if __name__ == "__main__":
    main()
