#!/usr/bin/env python3
"""Agent for hunting suspicious scheduled tasks on Windows endpoints."""

import json
import argparse
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    import Evtx.Evtx as evtx
except ImportError:
    evtx = None


SUSPICIOUS_ACTIONS = [
    r"powershell", r"pwsh", r"cmd\.exe.*/c", r"wscript", r"cscript",
    r"mshta", r"rundll32", r"regsvr32", r"certutil",
    r"bitsadmin", r"msiexec.*http",
]

SUSPICIOUS_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\downloads\\",
    r"\\public\\", r"\\programdata\\", r"\\users\\.*\\desktop\\",
    r"c:\\windows\\temp",
]

LEGITIMATE_TASK_PREFIXES = [
    "\\Microsoft\\Windows\\", "\\Microsoft\\Office\\",
    "\\Microsoft\\EdgeUpdate\\",
]


def parse_schtasks_csv(csv_path):
    """Parse output of schtasks /query /fo CSV /v."""
    import csv
    tasks = []
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tasks.append({
                "hostname": row.get("HostName", ""),
                "task_name": row.get("TaskName", ""),
                "status": row.get("Status", ""),
                "task_to_run": row.get("Task To Run", ""),
                "run_as_user": row.get("Run As User", ""),
                "schedule_type": row.get("Schedule Type", ""),
                "author": row.get("Author", ""),
            })
    return tasks


def analyze_tasks(tasks):
    """Analyze scheduled tasks for suspicious properties."""
    findings = []
    for task in tasks:
        name = task.get("task_name", "")
        action = task.get("task_to_run", "")
        run_as = task.get("run_as_user", "")
        is_legit_prefix = any(name.startswith(p) for p in LEGITIMATE_TASK_PREFIXES)
        risk_score = 0
        reasons = []
        for pattern in SUSPICIOUS_ACTIONS:
            if re.search(pattern, action, re.IGNORECASE):
                risk_score += 30
                reasons.append(f"suspicious_action:{pattern}")
        for pattern in SUSPICIOUS_PATHS:
            if re.search(pattern, action, re.IGNORECASE):
                risk_score += 25
                reasons.append(f"suspicious_path:{pattern}")
        if run_as and "SYSTEM" in run_as.upper():
            risk_score += 15
            reasons.append("runs_as_system")
        if not is_legit_prefix and name.count("\\") <= 1:
            risk_score += 10
            reasons.append("non_standard_location")
        if re.search(r"(http|https|ftp)://", action, re.IGNORECASE):
            risk_score += 40
            reasons.append("network_url_in_action")
        if re.search(r"-enc\s|encodedcommand", action, re.IGNORECASE):
            risk_score += 35
            reasons.append("encoded_command")
        if risk_score > 0:
            severity = "CRITICAL" if risk_score >= 60 else "HIGH" if risk_score >= 30 else "MEDIUM"
            findings.append({
                "task_name": name,
                "action": action[:500],
                "run_as_user": run_as,
                "risk_score": risk_score,
                "severity": severity,
                "reasons": reasons,
                "hostname": task.get("hostname", ""),
            })
    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def hunt_evtx_4698(evtx_path):
    """Hunt Event ID 4698 (scheduled task creation) in EVTX."""
    if evtx is None:
        return []
    findings = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            xml_str = record.xml()
            try:
                root = ET.fromstring(xml_str)
                ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                eid_el = root.find(".//ns:EventID", ns)
                if eid_el is None or eid_el.text != "4698":
                    continue
                data = {}
                for d in root.findall(".//ns:Data", ns):
                    data[d.get("Name", "")] = d.text or ""
                task_name = data.get("TaskName", "")
                task_content = data.get("TaskContent", "")
                is_suspicious = any(
                    re.search(p, task_content, re.IGNORECASE) for p in SUSPICIOUS_ACTIONS)
                if is_suspicious:
                    findings.append({
                        "timestamp": record.timestamp().isoformat(),
                        "task_name": task_name,
                        "user": data.get("SubjectUserName", ""),
                        "task_content_preview": task_content[:500],
                        "severity": "HIGH",
                    })
            except ET.ParseError:
                continue
    return findings


def generate_sigma_rule():
    """Generate Sigma rule for suspicious scheduled task creation."""
    return {
        "title": "Suspicious Scheduled Task Created",
        "id": "e4db2c6a-3f1b-4c8d-9e2a-7b5c4d6e8f0a",
        "status": "production",
        "level": "high",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": 4698},
            "filter_legit": {"TaskName|startswith": ["\\Microsoft\\Windows\\", "\\Microsoft\\Office\\"]},
            "suspicious_content": {
                "TaskContent|contains": ["powershell", "cmd /c", "wscript", "mshta",
                                          "\\Temp\\", "\\AppData\\", "http://", "https://"],
            },
            "condition": "selection and not filter_legit and suspicious_content",
        },
        "tags": ["attack.persistence", "attack.execution", "attack.t1053.005"],
    }


def main():
    parser = argparse.ArgumentParser(description="Suspicious Scheduled Tasks Hunter")
    parser.add_argument("--csv", help="schtasks CSV export")
    parser.add_argument("--evtx", help="Security EVTX log file")
    parser.add_argument("--output", default="schtask_hunt_report.json")
    parser.add_argument("--action", choices=["analyze", "hunt_evtx", "sigma", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("analyze", "full") and args.csv:
        tasks = parse_schtasks_csv(args.csv)
        findings = analyze_tasks(tasks)
        report["findings"]["task_analysis"] = findings
        print(f"[+] Suspicious tasks: {len(findings)} / {len(tasks)} total")

    if args.action in ("hunt_evtx", "full") and args.evtx:
        findings = hunt_evtx_4698(args.evtx)
        report["findings"]["evtx_4698"] = findings
        print(f"[+] EVTX 4698 suspicious: {len(findings)}")

    if args.action in ("sigma", "full"):
        report["findings"]["sigma_rule"] = generate_sigma_rule()
        print("[+] Sigma rule generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
