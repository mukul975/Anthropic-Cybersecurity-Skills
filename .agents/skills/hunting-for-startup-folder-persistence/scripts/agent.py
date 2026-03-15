#!/usr/bin/env python3
"""Agent for hunting T1547.001 startup folder persistence on Windows."""

import json
import os
import hashlib
import argparse
import time
from datetime import datetime, timedelta
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object

SUSPICIOUS_EXTENSIONS = {
    ".exe": 30, ".bat": 35, ".cmd": 35, ".vbs": 40, ".vbe": 40,
    ".js": 40, ".jse": 40, ".wsf": 40, ".wsh": 35, ".ps1": 45,
    ".pif": 45, ".scr": 40, ".hta": 45, ".lnk": 15, ".url": 20,
}

LEGITIMATE_ENTRIES = [
    "desktop.ini", "Send to OneNote.lnk", "OneNote 2016.lnk",
    "Microsoft Teams.lnk", "Outlook.lnk", "OneDrive.lnk",
    "Cisco AnyConnect Secure Mobility Client.lnk",
    "Skype for Business.lnk", "Zoom.lnk",
]


def get_startup_paths():
    """Return user-specific and all-users startup folder paths."""
    paths = []
    user_startup = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
    )
    if os.path.isdir(user_startup):
        paths.append({"path": user_startup, "scope": "current_user"})
    all_users_startup = os.path.join(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup"
    )
    if os.path.isdir(all_users_startup):
        paths.append({"path": all_users_startup, "scope": "all_users"})
    return paths


def compute_file_hash(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return "access_denied"


def analyze_file(filepath, scope="unknown"):
    """Analyze a single file in a startup directory."""
    path = Path(filepath)
    name = path.name
    ext = path.suffix.lower()
    try:
        stat = path.stat()
        created = datetime.fromtimestamp(stat.st_ctime)
        modified = datetime.fromtimestamp(stat.st_mtime)
        size = stat.st_size
    except (PermissionError, OSError):
        return {"file": str(filepath), "error": "access_denied"}

    is_legitimate = name in LEGITIMATE_ENTRIES
    age_days = (datetime.now() - created).days

    risk = 0
    indicators = []
    risk += SUSPICIOUS_EXTENSIONS.get(ext, 0)
    if ext in SUSPICIOUS_EXTENSIONS and ext != ".lnk":
        indicators.append(f"suspicious_extension_{ext}")
    if age_days < 7:
        risk += 25
        indicators.append("recently_created")
    if age_days < 1:
        risk += 15
        indicators.append("created_within_24h")
    if size == 0:
        risk += 10
        indicators.append("zero_byte_file")
    if size > 10 * 1024 * 1024:
        risk += 10
        indicators.append("large_file_over_10mb")
    if not is_legitimate:
        risk += 10
        indicators.append("not_in_baseline")
    if scope == "all_users" and ext in SUSPICIOUS_EXTENSIONS:
        risk += 10
        indicators.append("all_users_startup")

    risk = min(risk, 100)

    return {
        "file": str(filepath),
        "filename": name,
        "extension": ext,
        "scope": scope,
        "size_bytes": size,
        "created": created.isoformat(),
        "modified": modified.isoformat(),
        "age_days": age_days,
        "sha256": compute_file_hash(filepath),
        "is_legitimate_baseline": is_legitimate,
        "suspicious_indicators": indicators,
        "risk_score": risk,
        "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
    }


def scan_startup_folders():
    """Scan all startup directories and analyze contents."""
    startup_paths = get_startup_paths()
    results = []
    for sp in startup_paths:
        folder = sp["path"]
        scope = sp["scope"]
        try:
            for entry in os.listdir(folder):
                full_path = os.path.join(folder, entry)
                if os.path.isfile(full_path):
                    analysis = analyze_file(full_path, scope)
                    results.append(analysis)
        except PermissionError:
            results.append({"path": folder, "error": "access_denied"})
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    return results


def check_registry_run_keys():
    """Check Registry Run keys for autostart entries."""
    import subprocess
    run_keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    entries = []
    for key in run_keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("HK") and "REG_" in line:
                        parts = line.split("REG_SZ", 1) if "REG_SZ" in line else line.split("REG_EXPAND_SZ", 1)
                        name = parts[0].strip() if parts else line
                        value = parts[1].strip() if len(parts) > 1 else ""
                        entries.append({
                            "registry_key": key,
                            "name": name,
                            "value": value,
                            "suspicious": any(p in value.lower() for p in
                                             ["powershell", "cmd.exe", "\\temp\\", "\\appdata\\",
                                              "mshta", "-enc", "downloadstring"]),
                        })
        except Exception:
            pass
    return entries


class StartupMonitorHandler(FileSystemEventHandler):
    """Watchdog handler for monitoring startup folder changes."""

    def __init__(self):
        self.events = []

    def on_created(self, event):
        if not event.is_directory:
            analysis = analyze_file(event.src_path)
            alert = {
                "event": "FILE_CREATED",
                "timestamp": datetime.now().isoformat(),
                "file": event.src_path,
                "risk_score": analysis.get("risk_score", 0),
                "risk_level": analysis.get("risk_level", "UNKNOWN"),
                "indicators": analysis.get("suspicious_indicators", []),
            }
            self.events.append(alert)
            print(json.dumps(alert, indent=2))

    def on_modified(self, event):
        if not event.is_directory:
            alert = {
                "event": "FILE_MODIFIED",
                "timestamp": datetime.now().isoformat(),
                "file": event.src_path,
            }
            self.events.append(alert)
            print(json.dumps(alert, indent=2))

    def on_deleted(self, event):
        if not event.is_directory:
            alert = {
                "event": "FILE_DELETED",
                "timestamp": datetime.now().isoformat(),
                "file": event.src_path,
            }
            self.events.append(alert)
            print(json.dumps(alert, indent=2))


def monitor_startup(duration_seconds=60):
    """Monitor startup folders in real-time using watchdog."""
    if not Observer:
        return {"error": "watchdog not installed: pip install watchdog"}
    handler = StartupMonitorHandler()
    observer = Observer()
    startup_paths = get_startup_paths()
    for sp in startup_paths:
        observer.schedule(handler, sp["path"], recursive=False)
    observer.start()
    try:
        time.sleep(duration_seconds)
    except KeyboardInterrupt:
        pass
    observer.stop()
    observer.join()
    return {"monitored_seconds": duration_seconds, "events_detected": handler.events}


def full_hunt():
    """Run comprehensive startup persistence threat hunt."""
    scan_results = scan_startup_folders()
    registry_entries = check_registry_run_keys()
    suspicious_files = [r for r in scan_results if r.get("risk_score", 0) >= 25]
    suspicious_reg = [e for e in registry_entries if e.get("suspicious")]
    return {
        "hunt_type": "Startup Folder Persistence (T1547.001)",
        "timestamp": datetime.now().isoformat(),
        "startup_paths": get_startup_paths(),
        "statistics": {
            "total_startup_files": len(scan_results),
            "suspicious_files": len(suspicious_files),
            "registry_run_entries": len(registry_entries),
            "suspicious_registry_entries": len(suspicious_reg),
        },
        "file_analysis": scan_results[:30],
        "registry_analysis": registry_entries[:20],
        "mitre_technique": {
            "id": "T1547.001",
            "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            "tactic": "Persistence, Privilege Escalation",
        },
        "recommendation": "Investigate CRITICAL and HIGH files. Verify hashes against known-good baselines."
            if suspicious_files else "No suspicious startup entries detected.",
    }


def main():
    parser = argparse.ArgumentParser(description="Startup Folder Persistence Hunting Agent (T1547.001)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("scan", help="Scan startup folders for suspicious files")
    sub.add_parser("registry", help="Check Registry Run keys")
    p_mon = sub.add_parser("monitor", help="Monitor startup folders in real-time")
    p_mon.add_argument("--duration", type=int, default=60, help="Monitor duration in seconds")
    sub.add_parser("full", help="Full persistence threat hunt")
    args = parser.parse_args()

    if args.command == "scan":
        result = scan_startup_folders()
    elif args.command == "registry":
        result = check_registry_run_keys()
    elif args.command == "monitor":
        result = monitor_startup(args.duration)
    elif args.command == "full" or args.command is None:
        result = full_hunt()
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
