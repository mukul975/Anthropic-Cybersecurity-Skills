#!/usr/bin/env python3
"""
Malware Eradication Automation Script

Scans systems for persistence mechanisms, removes identified malware
artifacts, and validates eradication success.

Requirements:
    pip install psutil yara-python
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Install psutil: pip install psutil")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"eradication_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
    ],
)
logger = logging.getLogger("malware_eradication")


class PersistenceScanner:
    """Scan for known persistence mechanisms on Windows and Linux."""

    def __init__(self):
        self.findings = []
        self.system = platform.system()

    def scan_all(self) -> list:
        """Run all persistence checks."""
        if self.system == "Windows":
            self._scan_registry_run_keys()
            self._scan_scheduled_tasks()
            self._scan_services()
            self._scan_startup_folders()
            self._scan_wmi_subscriptions()
        else:
            self._scan_crontabs()
            self._scan_systemd_services()
            self._scan_rc_local()
            self._scan_shell_profiles()
            self._scan_authorized_keys()
            self._scan_ld_preload()
        return self.findings

    def _scan_registry_run_keys(self):
        """Scan Windows registry Run keys."""
        run_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        ]
        for key in run_keys:
            try:
                result = subprocess.run(
                    ["reg", "query", key], capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        line = line.strip()
                        if line and "REG_SZ" in line or "REG_EXPAND_SZ" in line:
                            self.findings.append({
                                "type": "registry_run_key",
                                "location": key,
                                "value": line,
                                "risk": "medium",
                            })
            except Exception as e:
                logger.warning(f"Failed to scan {key}: {e}")

    def _scan_scheduled_tasks(self):
        """Scan Windows scheduled tasks."""
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    reader = csv.DictReader(lines)
                    for row in reader:
                        task_name = row.get("TaskName", "")
                        task_run = row.get("Task To Run", "")
                        if task_name and task_run and "N/A" not in task_run:
                            # Flag tasks with suspicious indicators
                            suspicious = any(kw in task_run.lower() for kw in [
                                "powershell", "cmd /c", "mshta", "wscript",
                                "cscript", "certutil", "bitsadmin", "temp",
                                "appdata", "public",
                            ])
                            self.findings.append({
                                "type": "scheduled_task",
                                "location": task_name,
                                "value": task_run,
                                "risk": "high" if suspicious else "low",
                            })
        except Exception as e:
            logger.warning(f"Failed to scan scheduled tasks: {e}")

    def _scan_services(self):
        """Scan Windows services for suspicious entries."""
        try:
            for service in psutil.win_service_iter():
                try:
                    info = service.as_dict()
                    binpath = info.get("binpath", "")
                    if binpath and not any(
                        binpath.lower().startswith(p) for p in [
                            "c:\\windows\\", "c:\\program files\\",
                            "c:\\program files (x86)\\",
                        ]
                    ):
                        self.findings.append({
                            "type": "service",
                            "location": info.get("name", ""),
                            "value": binpath,
                            "risk": "medium",
                            "status": info.get("status", ""),
                        })
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Failed to scan services: {e}")

    def _scan_startup_folders(self):
        """Scan Windows startup folders."""
        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        ]
        for path in startup_paths:
            if os.path.exists(path):
                for item in os.listdir(path):
                    full_path = os.path.join(path, item)
                    if os.path.isfile(full_path) and item != "desktop.ini":
                        self.findings.append({
                            "type": "startup_folder",
                            "location": path,
                            "value": full_path,
                            "risk": "medium",
                        })

    def _scan_wmi_subscriptions(self):
        """Scan for WMI event subscriptions (Windows)."""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-WMIObject -Namespace root\\Subscription -Class __EventFilter | Select-Object Name, Query | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15,
            )
            if result.stdout.strip():
                filters = json.loads(result.stdout)
                if isinstance(filters, dict):
                    filters = [filters]
                for f in filters:
                    self.findings.append({
                        "type": "wmi_subscription",
                        "location": "root\\Subscription\\__EventFilter",
                        "value": f.get("Name", "") + ": " + f.get("Query", ""),
                        "risk": "high",
                    })
        except Exception as e:
            logger.warning(f"Failed to scan WMI subscriptions: {e}")

    def _scan_crontabs(self):
        """Scan Linux crontab entries."""
        cron_paths = ["/etc/crontab"]
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                     "/etc/cron.weekly", "/etc/cron.monthly"]
        # User crontabs
        spool_dir = "/var/spool/cron/crontabs"
        if os.path.exists(spool_dir):
            for f in os.listdir(spool_dir):
                cron_paths.append(os.path.join(spool_dir, f))
        for d in cron_dirs:
            if os.path.exists(d):
                for f in os.listdir(d):
                    cron_paths.append(os.path.join(d, f))
        for path in cron_paths:
            if os.path.isfile(path):
                try:
                    with open(path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.findings.append({
                                    "type": "crontab",
                                    "location": path,
                                    "value": line,
                                    "risk": "medium",
                                })
                except PermissionError:
                    pass

    def _scan_systemd_services(self):
        """Scan for custom systemd services."""
        service_dirs = ["/etc/systemd/system", "/usr/lib/systemd/system"]
        for sdir in service_dirs:
            if os.path.exists(sdir):
                for f in os.listdir(sdir):
                    if f.endswith(".service"):
                        fpath = os.path.join(sdir, f)
                        try:
                            with open(fpath) as sf:
                                content = sf.read()
                                if "ExecStart" in content:
                                    self.findings.append({
                                        "type": "systemd_service",
                                        "location": fpath,
                                        "value": f,
                                        "risk": "low",
                                    })
                        except PermissionError:
                            pass

    def _scan_rc_local(self):
        """Scan /etc/rc.local."""
        if os.path.exists("/etc/rc.local"):
            try:
                with open("/etc/rc.local") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and line != "exit 0":
                            self.findings.append({
                                "type": "rc_local",
                                "location": "/etc/rc.local",
                                "value": line,
                                "risk": "high",
                            })
            except PermissionError:
                pass

    def _scan_shell_profiles(self):
        """Scan shell profile files for suspicious entries."""
        profile_files = [
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.profile"),
            os.path.expanduser("~/.bash_profile"),
            "/etc/profile",
        ]
        suspicious_commands = ["curl", "wget", "nc ", "ncat", "python -c", "perl -e",
                               "base64", "eval", "/dev/tcp"]
        for pf in profile_files:
            if os.path.exists(pf):
                try:
                    with open(pf) as f:
                        for line in f:
                            line = line.strip()
                            if any(cmd in line.lower() for cmd in suspicious_commands):
                                self.findings.append({
                                    "type": "shell_profile",
                                    "location": pf,
                                    "value": line,
                                    "risk": "high",
                                })
                except PermissionError:
                    pass

    def _scan_authorized_keys(self):
        """Scan for unauthorized SSH keys."""
        home_dirs = ["/root"] + [
            os.path.join("/home", d) for d in os.listdir("/home")
            if os.path.isdir(os.path.join("/home", d))
        ] if os.path.exists("/home") else ["/root"]
        for hd in home_dirs:
            ak_path = os.path.join(hd, ".ssh", "authorized_keys")
            if os.path.exists(ak_path):
                try:
                    with open(ak_path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self.findings.append({
                                    "type": "authorized_keys",
                                    "location": ak_path,
                                    "value": line[:100] + "..." if len(line) > 100 else line,
                                    "risk": "medium",
                                })
                except PermissionError:
                    pass

    def _scan_ld_preload(self):
        """Scan for LD_PRELOAD hijacking."""
        if os.path.exists("/etc/ld.so.preload"):
            try:
                with open("/etc/ld.so.preload") as f:
                    content = f.read().strip()
                    if content:
                        self.findings.append({
                            "type": "ld_preload",
                            "location": "/etc/ld.so.preload",
                            "value": content,
                            "risk": "critical",
                        })
            except PermissionError:
                pass


class MalwareRemover:
    """Remove identified malware artifacts."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.removal_log = []

    def remove_file(self, filepath: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove file: {filepath}")
            self.removal_log.append({"action": "remove_file", "target": filepath, "status": "dry_run"})
            return True
        try:
            if os.path.exists(filepath):
                file_hash = hashlib.sha256(open(filepath, "rb").read()).hexdigest()
                os.remove(filepath)
                self.removal_log.append({
                    "action": "remove_file", "target": filepath,
                    "status": "removed", "sha256": file_hash,
                })
                logger.info(f"Removed file: {filepath} (SHA256: {file_hash})")
                return True
        except Exception as e:
            self.removal_log.append({"action": "remove_file", "target": filepath, "status": f"failed: {e}"})
            logger.error(f"Failed to remove {filepath}: {e}")
        return False

    def remove_scheduled_task(self, task_name: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove scheduled task: {task_name}")
            self.removal_log.append({"action": "remove_task", "target": task_name, "status": "dry_run"})
            return True
        try:
            result = subprocess.run(
                ["schtasks", "/delete", "/tn", task_name, "/f"],
                capture_output=True, text=True, timeout=10,
            )
            status = "removed" if result.returncode == 0 else f"failed: {result.stderr}"
            self.removal_log.append({"action": "remove_task", "target": task_name, "status": status})
            return result.returncode == 0
        except Exception as e:
            self.removal_log.append({"action": "remove_task", "target": task_name, "status": f"failed: {e}"})
            return False

    def remove_registry_value(self, key: str, value_name: str) -> bool:
        if self.dry_run:
            logger.info(f"[DRY RUN] Would remove registry: {key}\\{value_name}")
            self.removal_log.append({"action": "remove_reg", "target": f"{key}\\{value_name}", "status": "dry_run"})
            return True
        try:
            result = subprocess.run(
                ["reg", "delete", key, "/v", value_name, "/f"],
                capture_output=True, text=True, timeout=10,
            )
            status = "removed" if result.returncode == 0 else f"failed: {result.stderr}"
            self.removal_log.append({"action": "remove_reg", "target": f"{key}\\{value_name}", "status": status})
            return result.returncode == 0
        except Exception as e:
            self.removal_log.append({"action": "remove_reg", "target": f"{key}\\{value_name}", "status": f"failed: {e}"})
            return False


def generate_report(findings: list, removal_log: list, output_path: str):
    """Generate eradication report."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "persistence_findings": {
            "total": len(findings),
            "by_risk": {},
            "by_type": {},
            "details": findings,
        },
        "eradication_actions": removal_log,
    }
    for f in findings:
        risk = f.get("risk", "unknown")
        ftype = f.get("type", "unknown")
        report["persistence_findings"]["by_risk"][risk] = report["persistence_findings"]["by_risk"].get(risk, 0) + 1
        report["persistence_findings"]["by_type"][ftype] = report["persistence_findings"]["by_type"].get(ftype, 0) + 1

    with open(output_path, "w") as fp:
        json.dump(report, fp, indent=2)
    logger.info(f"Report saved to: {output_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Malware Eradication Tool")
    parser.add_argument("--scan", action="store_true", help="Scan for persistence mechanisms")
    parser.add_argument("--remove-files", nargs="*", help="Files to remove")
    parser.add_argument("--remove-tasks", nargs="*", help="Scheduled tasks to remove")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate removal (default)")
    parser.add_argument("--execute", action="store_true", help="Actually perform removal (CAUTION)")
    parser.add_argument("--output", default="./eradication_report.json", help="Report output path")

    args = parser.parse_args()
    dry_run = not args.execute

    findings = []
    if args.scan:
        scanner = PersistenceScanner()
        findings = scanner.scan_all()
        logger.info(f"Found {len(findings)} persistence items")
        for f in findings:
            risk_label = f"[{f['risk'].upper()}]"
            logger.info(f"  {risk_label} {f['type']}: {f['location']} -> {f['value'][:80]}")

    remover = MalwareRemover(dry_run=dry_run)
    if args.remove_files:
        for fp in args.remove_files:
            remover.remove_file(fp)
    if args.remove_tasks:
        for task in args.remove_tasks:
            remover.remove_scheduled_task(task)

    generate_report(findings, remover.removal_log, args.output)


if __name__ == "__main__":
    main()
