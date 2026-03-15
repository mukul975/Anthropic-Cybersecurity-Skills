#!/usr/bin/env python3
"""Scheduled Task Persistence Detection - Analyzes Windows task creation events for suspicious persistence indicators."""

import json, csv, argparse, datetime, re
from collections import defaultdict
from pathlib import Path

SUSPICIOUS_TASK_PATTERNS = {
    "commands": [
        r"powershell", r"cmd\.exe", r"wscript", r"cscript", r"mshta",
        r"certutil", r"bitsadmin", r"rundll32", r"regsvr32",
    ],
    "arguments": [
        r"-enc", r"-encodedcommand", r"iex", r"downloadstring",
        r"http[s]?://", r"bypass", r"hidden", r"base64",
    ],
    "paths": [
        r"\\temp\\", r"\\appdata\\", r"\\programdata\\",
        r"\\public\\", r"\\downloads\\",
    ],
}

def parse_logs(path):
    p = Path(path)
    if p.suffix == ".json":
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else data.get("events", [])
    elif p.suffix == ".csv":
        with open(p, encoding="utf-8-sig") as f:
            return [dict(r) for r in csv.DictReader(f)]
    return []

def analyze_task(event):
    eid = event.get("EventCode", event.get("EventID", event.get("event_id", "")))
    if str(eid) not in ("4698", "106"):
        return None
    task_name = event.get("Task_Name", event.get("TaskName", ""))
    task_content = event.get("Task_Content", event.get("TaskContent", event.get("command_line", "")))
    host = event.get("Computer", event.get("hostname", "unknown"))
    user = event.get("User", event.get("AccountName", "unknown"))
    ts = event.get("_time", event.get("timestamp", event.get("UtcTime", "")))

    risk = 20
    indicators = []
    for cat, patterns in SUSPICIOUS_TASK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, task_content, re.IGNORECASE):
                risk += 15
                indicators.append(f"Suspicious {cat}: {pattern}")
    if not indicators:
        return None
    risk = min(risk, 100)
    return {
        "technique": "T1053.005",
        "task_name": task_name,
        "task_content": task_content[:500],
        "hostname": host, "user": user, "timestamp": ts,
        "risk_score": risk,
        "risk_level": "CRITICAL" if risk >= 70 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 30 else "LOW",
        "indicators": indicators,
    }

def run_hunt(input_path, output_dir):
    print(f"[*] Scheduled Task Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_logs(input_path)
    findings = [f for f in (analyze_task(e) for e in events) if f]
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with open(Path(output_dir) / "schtask_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-SCHTASK-{datetime.date.today()}", "findings": findings}, f, indent=2)
    print(f"[+] {len(findings)} findings written to {output_dir}")

def main():
    p = argparse.ArgumentParser(description="Scheduled Task Persistence Detection")
    sp = p.add_subparsers(dest="cmd")
    h = sp.add_parser("hunt")
    h.add_argument("--input", "-i", required=True)
    h.add_argument("--output", "-o", default="./schtask_output")
    sp.add_parser("queries")
    args = p.parse_args()
    if args.cmd == "hunt": run_hunt(args.input, args.output)
    elif args.cmd == "queries":
        print("=== Splunk ===")
        print('''index=wineventlog (EventCode=4698 OR EventCode=106)
| where match(Task_Content, "(?i)(powershell|cmd|wscript|mshta|http|encoded)")
| table _time Computer User Task_Name Task_Content''')
    else: p.print_help()

if __name__ == "__main__": main()
