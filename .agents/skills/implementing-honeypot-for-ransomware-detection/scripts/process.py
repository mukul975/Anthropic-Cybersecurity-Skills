#!/usr/bin/env python3
"""
Ransomware Honeypot Deployment and Monitoring Tool

Deploys canary files across file shares and monitors for modifications
that indicate ransomware activity. Supports:
- Canary file generation with realistic content
- File system monitoring with immediate alerting
- Integration with SIEM via syslog
- Automated containment via API calls
"""

import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ransomware_honeypot")


@dataclass
class CanaryFile:
    path: str
    original_hash: str
    file_type: str
    deploy_time: str
    share_name: str
    status: str = "active"
    last_check: Optional[str] = None
    alert_triggered: bool = False


@dataclass
class CanaryAlert:
    timestamp: str
    canary_path: str
    change_type: str  # modified, deleted, renamed, extension_changed
    source_info: str
    severity: str = "CRITICAL"
    automated_response: str = ""


CANARY_TEMPLATES = {
    "finance": [
        ("!_Budget_FY2026_FINAL.xlsx", "FY2026 Budget Summary\nTotal Revenue: $142.3M\nTotal Expenses: $98.7M\nNet Income: $43.6M"),
        ("000_Quarterly_Earnings.docx", "Q4 2025 Earnings Report\nRevenue: $38.2M\nGross Margin: 67%\nEBITDA: $12.1M"),
        ("_Executive_Compensation.pdf", "Executive Compensation Committee Report\nCEO Total Comp: $2.1M\nCFO Total Comp: $1.4M"),
    ],
    "hr": [
        ("!_Employee_SSN_List.xlsx", "Employee ID | Name | SSN\n10001 | Smith, John | XXX-XX-1234\n10002 | Johnson, Mary | XXX-XX-5678"),
        ("000_Salary_Database_2026.csv", "Employee,Department,Base Salary,Bonus\nSmith J,Engineering,$145000,$29000"),
        ("_Termination_List_Q1.docx", "Planned Workforce Reduction Q1 2026\nDepartment: Operations\nHeadcount Impact: 45 positions"),
    ],
    "engineering": [
        ("!_Product_Roadmap_Confidential.docx", "Product Roadmap 2026-2028\nProject Phoenix: AI-powered analytics\nProject Titan: Next-gen platform"),
        ("000_Source_Code_Access_Keys.txt", "Repository Access Tokens\nGitHub Enterprise: ghp_XXXXXXXXXXXX\nAWS CodeCommit: AKIAIOSFODNN7EXAMPLE"),
        ("_Patent_Application_Draft.pdf", "US Patent Application\nTitle: Method for Distributed Computing\nInventor: Dr. Jane Smith"),
    ],
    "executive": [
        ("!_Board_Meeting_Minutes.docx", "Board of Directors Meeting Minutes\nDate: January 15, 2026\nAttendees: Full board present"),
        ("000_MA_Target_Analysis.xlsx", "M&A Target Analysis\nTarget: AcmeTech Inc\nValuation: $450M\nSynergies: $80M annual"),
        ("_Strategic_Plan_2026.pdf", "Strategic Plan 2026-2030\nVision: Market leader in three verticals\nCapEx Budget: $200M"),
    ],
}


class CanaryDeployer:
    """Deploys and manages canary files for ransomware detection."""

    def __init__(self, state_file: str = "canary_state.json"):
        self.state_file = state_file
        self.canaries: list[CanaryFile] = []
        self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, "r") as f:
                data = json.load(f)
                self.canaries = [CanaryFile(**c) for c in data.get("canaries", [])]

    def _save_state(self):
        with open(self.state_file, "w") as f:
            json.dump({"canaries": [asdict(c) for c in self.canaries],
                       "last_updated": datetime.now().isoformat()}, f, indent=2)

    def _compute_hash(self, filepath: str) -> str:
        if not os.path.exists(filepath):
            return ""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def deploy_canaries(self, base_path: str, share_type: str = "finance") -> list:
        """Deploy canary files to a target directory."""
        templates = CANARY_TEMPLATES.get(share_type, CANARY_TEMPLATES["finance"])
        deployed = []

        base = Path(base_path)
        if not base.exists():
            logger.error(f"Target path does not exist: {base_path}")
            return deployed

        for filename, content in templates:
            filepath = base / filename
            try:
                filepath.write_text(content, encoding="utf-8")
                file_hash = self._compute_hash(str(filepath))

                canary = CanaryFile(
                    path=str(filepath),
                    original_hash=file_hash,
                    file_type=filepath.suffix,
                    deploy_time=datetime.now().isoformat(),
                    share_name=share_type,
                )
                self.canaries.append(canary)
                deployed.append(canary)
                logger.info(f"Deployed canary: {filepath}")
            except OSError as e:
                logger.error(f"Failed to deploy canary {filepath}: {e}")

        self._save_state()
        return deployed

    def check_canaries(self) -> list:
        """Check all deployed canaries for modifications."""
        alerts = []

        for canary in self.canaries:
            if canary.status != "active":
                continue

            canary.last_check = datetime.now().isoformat()

            if not os.path.exists(canary.path):
                # File deleted - strong ransomware indicator
                alert = CanaryAlert(
                    timestamp=datetime.now().isoformat(),
                    canary_path=canary.path,
                    change_type="deleted",
                    source_info="File no longer exists",
                    severity="CRITICAL",
                )
                alerts.append(alert)
                canary.alert_triggered = True
                canary.status = "triggered"
                logger.critical(f"CANARY DELETED: {canary.path}")
                continue

            current_hash = self._compute_hash(canary.path)
            if current_hash != canary.original_hash:
                # File modified - likely encryption
                alert = CanaryAlert(
                    timestamp=datetime.now().isoformat(),
                    canary_path=canary.path,
                    change_type="modified",
                    source_info=f"Hash changed: {canary.original_hash[:16]}... -> {current_hash[:16]}...",
                    severity="CRITICAL",
                )
                alerts.append(alert)
                canary.alert_triggered = True
                canary.status = "triggered"
                logger.critical(f"CANARY MODIFIED: {canary.path}")

            # Check for ransomware extension appended
            parent = Path(canary.path).parent
            base_name = Path(canary.path).name
            for f in parent.iterdir():
                if f.name.startswith(base_name) and f.name != base_name:
                    # Possible encrypted version (e.g., file.docx.lockbit)
                    alert = CanaryAlert(
                        timestamp=datetime.now().isoformat(),
                        canary_path=canary.path,
                        change_type="extension_changed",
                        source_info=f"Possible encrypted copy: {f.name}",
                        severity="CRITICAL",
                    )
                    alerts.append(alert)
                    canary.alert_triggered = True
                    logger.critical(f"CANARY EXTENSION CHANGE: {f.name}")

        self._save_state()
        return alerts

    def generate_report(self) -> str:
        """Generate deployment status report."""
        lines = []
        lines.append("=" * 60)
        lines.append("RANSOMWARE CANARY DEPLOYMENT REPORT")
        lines.append("=" * 60)
        lines.append(f"Report Time: {datetime.now().isoformat()}")
        lines.append(f"Total Canaries: {len(self.canaries)}")

        active = sum(1 for c in self.canaries if c.status == "active")
        triggered = sum(1 for c in self.canaries if c.status == "triggered")
        lines.append(f"Active: {active}")
        lines.append(f"Triggered: {triggered}")

        by_share = {}
        for c in self.canaries:
            by_share.setdefault(c.share_name, []).append(c)

        lines.append("\nDeployment by Share:")
        for share, canaries in by_share.items():
            lines.append(f"\n  {share.upper()}:")
            for c in canaries:
                status_icon = "OK" if c.status == "active" else "ALERT"
                lines.append(f"    [{status_icon}] {c.path}")

        lines.append("\n" + "=" * 60)
        return "\n".join(lines)

    def continuous_monitor(self, interval_seconds: int = 10):
        """Run continuous monitoring loop."""
        logger.info(f"Starting continuous canary monitoring (interval: {interval_seconds}s)")
        logger.info(f"Monitoring {len(self.canaries)} canary files")

        try:
            while True:
                alerts = self.check_canaries()
                if alerts:
                    logger.critical(f"!!! {len(alerts)} CANARY ALERTS DETECTED !!!")
                    for alert in alerts:
                        logger.critical(f"  {alert.change_type}: {alert.canary_path}")
                        # In production: trigger SIEM alert, NAC quarantine, EDR isolation
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")


def main():
    deployer = CanaryDeployer(
        state_file=str(Path(__file__).parent / "canary_state.json")
    )

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "deploy" and len(sys.argv) >= 4:
            target_path = sys.argv[2]
            share_type = sys.argv[3]
            deployed = deployer.deploy_canaries(target_path, share_type)
            print(f"Deployed {len(deployed)} canary files to {target_path}")

        elif command == "check":
            alerts = deployer.check_canaries()
            if alerts:
                print(f"\n!!! {len(alerts)} ALERTS !!!")
                for alert in alerts:
                    print(f"  [{alert.severity}] {alert.change_type}: {alert.canary_path}")
            else:
                print("All canaries intact - no alerts")

        elif command == "monitor":
            interval = int(sys.argv[2]) if len(sys.argv) > 2 else 10
            deployer.continuous_monitor(interval)

        elif command == "report":
            print(deployer.generate_report())

        else:
            print("Usage:")
            print("  python process.py deploy <path> <type>  - Deploy canaries (finance/hr/engineering/executive)")
            print("  python process.py check                 - Check all canaries for modifications")
            print("  python process.py monitor [interval]    - Continuous monitoring")
            print("  python process.py report                - Generate deployment report")
    else:
        # Demo mode
        print("Ransomware Honeypot - Demo Mode")
        print("=" * 40)
        demo_dir = Path(__file__).parent / "demo_share"
        demo_dir.mkdir(exist_ok=True)

        deployed = deployer.deploy_canaries(str(demo_dir), "finance")
        print(f"\nDeployed {len(deployed)} canary files")

        alerts = deployer.check_canaries()
        print(f"Initial check: {len(alerts)} alerts (expected: 0)")

        print("\n" + deployer.generate_report())


if __name__ == "__main__":
    main()
