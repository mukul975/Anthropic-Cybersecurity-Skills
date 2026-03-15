#!/usr/bin/env python3
"""Agent for ransomware attack recovery coordination.

Manages recovery workflow: backup verification, system rebuild
prioritization, credential reset tracking, and post-recovery
validation checklists with timeline documentation.
"""

import json
import sys
from datetime import datetime
from pathlib import Path


RECOVERY_PRIORITY = [
    ("Domain Controllers", "critical", "Rebuild from clean media first"),
    ("DNS/DHCP Servers", "critical", "Required for network functionality"),
    ("Authentication Services", "critical", "SSO, MFA, RADIUS"),
    ("Email Server", "high", "Communication during recovery"),
    ("Database Servers", "high", "Restore from verified clean backup"),
    ("Application Servers", "high", "Business-critical applications"),
    ("File Servers", "medium", "Restore data from backup"),
    ("Workstations", "medium", "Reimage, do not file-level restore"),
    ("Print Servers", "low", "Rebuild after core services"),
]


class RansomwareRecoveryAgent:
    """Coordinates ransomware attack recovery procedures."""

    def __init__(self, case_id, output_dir="./recovery"):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.recovery = {
            "case_id": case_id, "status": "in_progress",
            "timeline": [], "systems": [], "checklists": {},
        }

    def log_event(self, event_type, description):
        self.recovery["timeline"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type, "description": description,
        })

    def verify_backup(self, backup_path, backup_type, last_verified=None):
        """Record backup verification status."""
        status = {
            "path": backup_path, "type": backup_type,
            "verified_date": last_verified or datetime.utcnow().isoformat(),
            "integrity": "pending",
        }
        if Path(backup_path).exists() if not backup_path.startswith("s3://") else True:
            status["integrity"] = "accessible"
        self.recovery.setdefault("backups", []).append(status)
        self.log_event("backup_check", f"Verified {backup_type}: {backup_path}")
        return status

    def build_recovery_plan(self, clean_backup_available=True):
        """Generate prioritized system recovery plan."""
        systems = []
        for name, priority, note in RECOVERY_PRIORITY:
            systems.append({
                "system": name, "priority": priority, "note": note,
                "status": "pending", "recovery_method": (
                    "Restore from backup" if clean_backup_available
                    else "Rebuild from scratch"
                ),
            })
        self.recovery["systems"] = systems
        self.log_event("plan_created", f"{len(systems)} systems in recovery plan")
        return systems

    def update_system_status(self, system_name, status, notes=""):
        for sys_entry in self.recovery["systems"]:
            if sys_entry["system"] == system_name:
                sys_entry["status"] = status
                if notes:
                    sys_entry["recovery_notes"] = notes
                self.log_event("system_update",
                               f"{system_name}: {status}")
                return sys_entry
        return None

    def generate_credential_reset_checklist(self):
        """Generate credential reset checklist for post-recovery."""
        checklist = [
            {"item": "Reset KRBTGT password (twice, 12h apart)", "status": "pending",
             "priority": "critical"},
            {"item": "Reset all Domain Admin passwords", "status": "pending",
             "priority": "critical"},
            {"item": "Reset all service account passwords", "status": "pending",
             "priority": "critical"},
            {"item": "Reset all user passwords", "status": "pending",
             "priority": "high"},
            {"item": "Revoke and reissue all certificates", "status": "pending",
             "priority": "high"},
            {"item": "Rotate all API keys and tokens", "status": "pending",
             "priority": "high"},
            {"item": "Reset cloud IAM credentials", "status": "pending",
             "priority": "high"},
            {"item": "Deploy LAPS for local admin passwords", "status": "pending",
             "priority": "medium"},
        ]
        self.recovery["checklists"]["credential_reset"] = checklist
        return checklist

    def generate_hardening_checklist(self):
        """Post-recovery hardening recommendations."""
        checklist = [
            {"item": "Enforce MFA on all remote access", "status": "pending"},
            {"item": "Implement 3-2-1-1-0 backup strategy", "status": "pending"},
            {"item": "Deploy EDR on all endpoints", "status": "pending"},
            {"item": "Enable PowerShell Script Block Logging", "status": "pending"},
            {"item": "Implement network segmentation", "status": "pending"},
            {"item": "Block SMB between workstations", "status": "pending"},
            {"item": "Disable NTLM where possible", "status": "pending"},
            {"item": "Deploy application whitelisting on servers", "status": "pending"},
            {"item": "Implement privileged access workstations", "status": "pending"},
        ]
        self.recovery["checklists"]["post_hardening"] = checklist
        return checklist

    def get_recovery_progress(self):
        """Calculate overall recovery progress."""
        total = len(self.recovery["systems"])
        completed = sum(1 for s in self.recovery["systems"]
                        if s["status"] in ("recovered", "verified"))
        return {
            "total_systems": total,
            "recovered": completed,
            "progress_pct": round(completed / max(total, 1) * 100, 1),
        }

    def generate_report(self):
        self.generate_credential_reset_checklist()
        self.generate_hardening_checklist()
        progress = self.get_recovery_progress()

        report = {
            **self.recovery,
            "progress": progress,
            "report_date": datetime.utcnow().isoformat(),
        }
        report_path = self.output_dir / f"{self.case_id}_recovery.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    case_id = sys.argv[1] if len(sys.argv) > 1 else "RAN-2025-001"
    agent = RansomwareRecoveryAgent(case_id)
    agent.build_recovery_plan(clean_backup_available=True)
    agent.generate_report()


if __name__ == "__main__":
    main()
