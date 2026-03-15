#!/usr/bin/env python3
"""Detect data staging activity before exfiltration via archive creation and file consolidation monitoring."""

import json
import re
import os
import argparse
from datetime import datetime, timedelta
from collections import defaultdict

ARCHIVE_TOOLS = {
    "7z.exe": {"args": ["a", "-p", "-mhe=on"], "mitre": "T1560.001"},
    "7z": {"args": ["a", "-p", "-mhe=on"], "mitre": "T1560.001"},
    "rar.exe": {"args": ["a", "-hp", "-p"], "mitre": "T1560.001"},
    "rar": {"args": ["a", "-hp", "-p"], "mitre": "T1560.001"},
    "winrar.exe": {"args": ["a", "-p"], "mitre": "T1560.001"},
    "zip": {"args": ["-r", "-e", "--encrypt"], "mitre": "T1560.001"},
    "tar": {"args": ["-czf", "-cjf", "-cJf", "cf"], "mitre": "T1560.001"},
    "compress-archive": {"args": ["-path", "-destinationpath"], "mitre": "T1560.001"},
    "makecab.exe": {"args": ["/d", "/f"], "mitre": "T1560.001"},
}

STAGING_PATHS_WINDOWS = [
    r"c:\windows\temp", r"c:\users\public", r"c:\programdata",
    r"c:\$recycle.bin", r"c:\perflogs", r"c:\windows\debug",
    r"c:\users\default", r"c:\intel",
]

STAGING_PATHS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm", "/var/spool/cron",
    "/opt/.hidden", "/usr/local/tmp",
]

SENSITIVE_SOURCE_DIRS = [
    "documents", "desktop", "downloads", "database", "backup",
    "finance", "hr", "confidential", "shared", "onedrive",
]


def parse_process_logs(log_path):
    """Parse process creation logs (Sysmon/EDR JSON format)."""
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def detect_archive_creation(events):
    """Detect archive tool execution with compression arguments."""
    detections = []
    for event in events:
        image = event.get("Image", event.get("NewProcessName", "")).lower()
        cmdline = event.get("CommandLine", event.get("ProcessCommandLine", "")).lower()
        binary = image.rsplit("\\", 1)[-1] if "\\" in image else image.rsplit("/", 1)[-1]

        if binary not in ARCHIVE_TOOLS:
            continue

        tool_info = ARCHIVE_TOOLS[binary]
        matched_args = [a for a in tool_info["args"] if a.lower() in cmdline]

        output_files = re.findall(r'[\w\-./\\]+\.(zip|7z|rar|tar\.gz|tar\.bz2|tar|cab)', cmdline)
        encrypted = any(flag in cmdline for flag in ["-p", "-hp", "-mhe=on", "--encrypt", "-e"])

        archive_size = _estimate_archive_size(event)
        severity = "medium"
        if encrypted:
            severity = "high"
        if archive_size and archive_size > 100 * 1024 * 1024:
            severity = "critical"

        detections.append({
            "timestamp": event.get("UtcTime", event.get("TimeCreated", "")),
            "binary": binary,
            "command_line": event.get("CommandLine", event.get("ProcessCommandLine", "")),
            "output_archives": output_files,
            "encrypted": encrypted,
            "matched_args": matched_args,
            "user": event.get("User", event.get("SubjectUserName", "unknown")),
            "parent_process": event.get("ParentImage", event.get("ParentProcessName", "")),
            "severity": severity,
            "mitre": tool_info["mitre"],
            "indicator": "Archive creation (potential data staging)",
        })
    return detections


def _estimate_archive_size(event):
    """Estimate output file size from event metadata if available."""
    size_str = event.get("FileSize", event.get("TargetFileSize", ""))
    if size_str:
        try:
            return int(size_str)
        except ValueError:
            pass
    return None


def detect_staging_directory_writes(events):
    """Detect file writes to known staging directories."""
    staging_writes = []
    all_staging = STAGING_PATHS_WINDOWS + STAGING_PATHS_LINUX
    for event in events:
        target = event.get("TargetFilename", event.get("ObjectName", "")).lower()
        if not target:
            continue
        for staging_path in all_staging:
            if target.startswith(staging_path.lower()):
                staging_writes.append({
                    "timestamp": event.get("UtcTime", event.get("TimeCreated", "")),
                    "target_path": event.get("TargetFilename", event.get("ObjectName", "")),
                    "staging_directory": staging_path,
                    "process": event.get("Image", event.get("NewProcessName", "")),
                    "user": event.get("User", event.get("SubjectUserName", "unknown")),
                    "severity": "medium",
                    "mitre": "T1074.001",
                    "indicator": f"File write to staging directory: {staging_path}",
                })
                break
    return staging_writes


def detect_sensitive_source_reads(events, time_window_minutes=30):
    """Detect bulk reads from sensitive directories (document consolidation)."""
    user_reads = defaultdict(list)
    for event in events:
        source = event.get("SourceFilename", event.get("ObjectName", "")).lower()
        if not source:
            continue
        for sensitive_dir in SENSITIVE_SOURCE_DIRS:
            if sensitive_dir in source:
                user = event.get("User", event.get("SubjectUserName", "unknown"))
                user_reads[user].append({
                    "path": source,
                    "timestamp": event.get("UtcTime", event.get("TimeCreated", "")),
                    "sensitive_dir": sensitive_dir,
                })
                break
    consolidation_alerts = []
    for user, reads in user_reads.items():
        unique_dirs = len({r["sensitive_dir"] for r in reads})
        if len(reads) >= 20 or unique_dirs >= 3:
            consolidation_alerts.append({
                "user": user,
                "total_reads": len(reads),
                "unique_sensitive_dirs": unique_dirs,
                "directories_accessed": list({r["sensitive_dir"] for r in reads}),
                "first_access": reads[0]["timestamp"],
                "last_access": reads[-1]["timestamp"],
                "severity": "critical" if unique_dirs >= 3 else "high",
                "mitre": "T1074.001",
                "indicator": "Bulk reads from sensitive directories (data consolidation)",
            })
    return consolidation_alerts


def score_staging_risk(archives, staging_writes, consolidation):
    """Compute overall staging risk score (0-100)."""
    score = 0
    if archives:
        score += min(30, len(archives) * 10)
        if any(a["encrypted"] for a in archives):
            score += 20
    if staging_writes:
        score += min(25, len(staging_writes) * 5)
    if consolidation:
        score += min(25, len(consolidation) * 15)
    return min(100, score)


def generate_report(archives, staging_writes, consolidation, log_path):
    """Generate data staging hunt report."""
    risk_score = score_staging_risk(archives, staging_writes, consolidation)
    return {
        "report_time": datetime.utcnow().isoformat(),
        "log_source": log_path,
        "risk_score": risk_score,
        "risk_level": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium" if risk_score >= 20 else "low",
        "archive_creation_events": len(archives),
        "staging_directory_writes": len(staging_writes),
        "data_consolidation_alerts": len(consolidation),
        "mitre_techniques": ["T1074.001", "T1074.002", "T1560.001"],
        "archive_detections": archives,
        "staging_write_detections": staging_writes[:20],
        "consolidation_alerts": consolidation,
    }


def main():
    parser = argparse.ArgumentParser(description="Data Staging Detection Agent (MITRE T1074)")
    parser.add_argument("--log-file", required=True, help="JSON process/file event log")
    parser.add_argument("--output", default="data_staging_report.json")
    parser.add_argument("--read-threshold", type=int, default=20, help="Bulk read threshold")
    args = parser.parse_args()

    events = parse_process_logs(args.log_file)
    archives = detect_archive_creation(events)
    staging_writes = detect_staging_directory_writes(events)
    consolidation = detect_sensitive_source_reads(events)

    report = generate_report(archives, staging_writes, consolidation, args.log_file)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Analyzed {len(events)} events")
    print(f"[+] Archive creation: {len(archives)} | Staging writes: {len(staging_writes)} | Consolidation: {len(consolidation)}")
    print(f"[+] Risk score: {report['risk_score']}/100 ({report['risk_level']})")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
