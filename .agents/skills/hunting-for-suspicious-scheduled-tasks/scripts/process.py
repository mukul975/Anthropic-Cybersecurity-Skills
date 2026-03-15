#!/usr/bin/env python3
"""
Suspicious Scheduled Task Detection Script
Analyzes Windows event logs for malicious scheduled task creation,
modification, and execution patterns.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

SUSPICIOUS_ACTION_PATTERNS = [
    (r"(?i)powershell", "powershell_execution", "HIGH"),
    (r"(?i)(cmd\.exe|cmd\s/c)", "command_shell", "HIGH"),
    (r"(?i)(wscript|cscript)", "script_execution", "HIGH"),
    (r"(?i)(mshta|rundll32|regsvr32)", "lolbin_execution", "CRITICAL"),
    (r"(?i)(http|https)://", "network_download", "CRITICAL"),
    (r"(?i)(\\temp\\|\\appdata\\|\\downloads\\)", "user_writable_path", "HIGH"),
    (r"(?i)(-enc\s|-encodedcommand)", "encoded_command", "CRITICAL"),
    (r"(?i)(base64|frombase64)", "base64_content", "HIGH"),
]

LEGITIMATE_TASK_PATHS = [
    r"(?i)\\Microsoft\\",
    r"(?i)\\Windows\\",
    r"(?i)\\Adobe\\",
    r"(?i)\\Google\\",
]


def parse_events(input_path: str) -> list[dict]:
    path = Path(input_path)
    events = []
    if path.suffix == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get("events", [])
    elif path.suffix == ".csv":
        with open(path, "r", encoding="utf-8-sig") as f:
            events = [dict(row) for row in csv.DictReader(f)]
    return events


def detect_suspicious_tasks(events: list[dict]) -> list[dict]:
    findings = []
    for event in events:
        event_code = str(event.get("EventCode", event.get("EventID", "")))
        computer = event.get("Computer", event.get("host", ""))
        timestamp = event.get("TimeCreated", event.get("_time", ""))
        user = event.get("SubjectUserName", event.get("user", ""))

        if event_code == "4698":
            task_name = event.get("TaskName", "")
            task_content = event.get("TaskContent", "")
            if any(re.search(p, task_name) for p in LEGITIMATE_TASK_PATHS):
                continue

            cmd_match = re.search(r"<Command>([^<]+)</Command>", task_content)
            args_match = re.search(r"<Arguments>([^<]+)</Arguments>", task_content)
            command = cmd_match.group(1) if cmd_match else ""
            arguments = args_match.group(1) if args_match else ""
            full_action = f"{command} {arguments}"

            for pattern, category, severity in SUSPICIOUS_ACTION_PATTERNS:
                if re.search(pattern, full_action):
                    findings.append({
                        "timestamp": timestamp, "computer": computer, "user": user,
                        "task_name": task_name, "command": command,
                        "arguments": arguments, "category": category,
                        "severity": severity, "technique": "T1053.005",
                    })
                    break

        elif event_code == "1":
            image = event.get("Image", "")
            cmdline = event.get("CommandLine", "")
            if "schtasks.exe" in image.lower() and "/create" in cmdline.lower():
                for pattern, category, severity in SUSPICIOUS_ACTION_PATTERNS:
                    if re.search(pattern, cmdline):
                        findings.append({
                            "timestamp": timestamp, "computer": computer, "user": user,
                            "task_name": "via_schtasks",
                            "command": image, "arguments": cmdline,
                            "category": f"schtasks_{category}",
                            "severity": severity, "technique": "T1053.005",
                        })
                        break

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 3))


def run_hunt(input_path: str, output_dir: str) -> None:
    print(f"[*] Scheduled Task Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    findings = detect_suspicious_tasks(events)
    print(f"[!] Suspicious task detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "schtask_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-SCHTASK-{datetime.date.today().isoformat()}",
                    "findings": findings}, f, indent=2)
    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Suspicious Scheduled Task Detection")
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", default="./schtask_hunt_output")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
