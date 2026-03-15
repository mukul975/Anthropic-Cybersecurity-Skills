#!/usr/bin/env python3
"""Agent for performing ransomware response.

Automates ransomware identification, impact assessment, backup
verification, IOC extraction, and recovery tracking during
ransomware incident response.
"""

import requests
import json
import sys
import hashlib
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class RansomwareResponseAgent:
    """Assists with structured ransomware incident response."""

    def __init__(self, case_id, output_dir):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.incident = {
            "case_id": case_id,
            "status": "active",
            "timeline": [],
        }

    def log_event(self, event_type, description, details=None):
        """Add a timestamped event to the incident timeline."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "description": description,
        }
        if details:
            event["details"] = details
        self.incident["timeline"].append(event)

    def identify_ransomware(self, ransom_note_path=None, encrypted_file_path=None,
                            extension=None):
        """Identify ransomware variant from note, file, or extension."""
        identification = {
            "method": "manual",
            "extension": extension,
        }

        if ransom_note_path and Path(ransom_note_path).exists():
            note_content = Path(ransom_note_path).read_text(errors="ignore")
            identification["ransom_note"] = note_content[:2000]

            known_patterns = {
                "LockBit": ["lockbit", "LOCKBIT", "restore-my-files"],
                "BlackCat/ALPHV": ["ALPHV", "BlackCat", "RECOVER-"],
                "Royal": ["Royal", "royal_w"],
                "Akira": ["akira", ".akira"],
                "Play": [".play", "PLAY"],
                "Cl0p": ["CL0P", "clop"],
                "Rhysida": ["rhysida", "RHYSIDA"],
            }
            for family, patterns in known_patterns.items():
                for pattern in patterns:
                    if pattern in note_content:
                        identification["family"] = family
                        break

        if encrypted_file_path and Path(encrypted_file_path).exists():
            file_hash = hashlib.sha256(
                Path(encrypted_file_path).read_bytes()
            ).hexdigest()
            identification["encrypted_sample_hash"] = file_hash

        self.incident["identification"] = identification
        self.log_event("identification", f"Ransomware identified: {identification.get('family', 'Unknown')}")
        return identification

    def check_decryptor_availability(self, family):
        """Check NoMoreRansom and known sources for free decryptors."""
        known_decryptors = {
            "GandCrab": "https://www.nomoreransom.org/en/decryption-tools.html",
            "REvil": "https://www.nomoreransom.org/en/decryption-tools.html",
            "Maze": "https://www.nomoreransom.org/en/decryption-tools.html",
            "Shade": "https://www.nomoreransom.org/en/decryption-tools.html",
            "Jigsaw": "https://www.nomoreransom.org/en/decryption-tools.html",
        }
        has_decryptor = family in known_decryptors
        return {
            "family": family,
            "decryptor_available": has_decryptor,
            "source": known_decryptors.get(family, "None known"),
            "nomoreransom_url": "https://www.nomoreransom.org/en/decryption-tools.html",
            "id_ransomware_url": "https://id-ransomware.malwarehunterteam.com/",
        }

    def assess_impact(self, encrypted_hosts=0, total_hosts=0,
                      encrypted_servers=0, total_servers=0,
                      dc_affected=0, total_dcs=0,
                      data_exfiltrated_gb=0, ransom_amount="",
                      backup_status="unknown"):
        """Assess the scope and impact of the ransomware incident."""
        assessment = {
            "encrypted_hosts": encrypted_hosts,
            "total_hosts": total_hosts,
            "host_impact_pct": round(encrypted_hosts / max(total_hosts, 1) * 100, 1),
            "encrypted_servers": encrypted_servers,
            "total_servers": total_servers,
            "dc_affected": dc_affected,
            "total_dcs": total_dcs,
            "data_exfiltrated_gb": data_exfiltrated_gb,
            "double_extortion": data_exfiltrated_gb > 0,
            "ransom_amount": ransom_amount,
            "backup_status": backup_status,
        }

        if backup_status == "clean":
            assessment["recommended_recovery"] = "Restore from backup"
        elif backup_status == "compromised":
            assessment["recommended_recovery"] = "Rebuild from scratch"
        else:
            assessment["recommended_recovery"] = "Verify backup integrity first"

        self.incident["impact_assessment"] = assessment
        self.log_event("impact_assessment", f"{encrypted_hosts}/{total_hosts} hosts encrypted")
        return assessment

    def generate_containment_checklist(self):
        """Generate prioritized containment checklist."""
        checklist = [
            {"priority": 1, "action": "Disconnect affected network segments from core infrastructure",
             "status": "pending", "note": "Pull network cable, do NOT power off"},
            {"priority": 2, "action": "Isolate all domain controllers immediately",
             "status": "pending", "note": "If GPO-based deployment suspected"},
            {"priority": 3, "action": "Disable compromised accounts used for deployment",
             "status": "pending"},
            {"priority": 4, "action": "Block lateral movement protocols (SMB 445, RDP 3389, WinRM 5985-5986)",
             "status": "pending"},
            {"priority": 5, "action": "Preserve at least one encrypted system powered on for memory forensics",
             "status": "pending", "note": "Encryption keys may be in memory"},
            {"priority": 6, "action": "Verify offline backup integrity",
             "status": "pending"},
            {"priority": 7, "action": "Engage incident response retainer and cyber insurance",
             "status": "pending"},
            {"priority": 8, "action": "Notify legal counsel for OFAC screening and regulatory assessment",
             "status": "pending"},
        ]
        self.incident["containment_checklist"] = checklist
        return checklist

    def generate_recovery_plan(self):
        """Generate recovery plan based on impact assessment."""
        assessment = self.incident.get("impact_assessment", {})
        backup_status = assessment.get("backup_status", "unknown")

        steps = []
        if backup_status == "clean":
            steps = [
                "Build clean isolated network segment for recovery",
                "Rebuild domain controllers from clean media",
                "Reset ALL user and service account passwords",
                "Restore servers in priority: auth > DNS > DHCP > business apps",
                "Reimage workstations (do not file-level restore)",
                "Restore data from verified clean backups",
                "Validate and reconnect to production network",
            ]
        else:
            steps = [
                "Verify backup integrity before proceeding",
                "If no clean backups, evaluate rebuild from scratch",
                "Check NoMoreRansom.org for available decryptors",
                "Consult with IR retainer on recovery options",
            ]

        plan = {
            "strategy": assessment.get("recommended_recovery", "TBD"),
            "steps": steps,
            "post_recovery_hardening": [
                "Enforce MFA on all remote access",
                "Implement 3-2-1-1-0 backup strategy",
                "Deploy application whitelisting on servers",
                "Implement network segmentation",
                "Deploy LAPS for local admin passwords",
                "Disable NTLM where possible",
            ],
        }
        self.incident["recovery_plan"] = plan
        return plan

    def generate_report(self):
        """Generate comprehensive ransomware incident report."""
        self.generate_containment_checklist()
        self.generate_recovery_plan()

        report = self.incident.copy()
        report["report_date"] = datetime.utcnow().isoformat()

        report_path = self.output_dir / f"{self.case_id}_ransomware_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <case_id> [output_dir] [ransom_note_path]")
        sys.exit(1)

    case_id = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./ransomware_response"

    agent = RansomwareResponseAgent(case_id, output_dir)

    if len(sys.argv) > 3:
        agent.identify_ransomware(ransom_note_path=sys.argv[3])

    agent.assess_impact(
        encrypted_hosts=0, total_hosts=0,
        backup_status="unknown"
    )
    agent.generate_report()


if __name__ == "__main__":
    main()
