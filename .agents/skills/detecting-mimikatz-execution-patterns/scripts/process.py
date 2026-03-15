#!/usr/bin/env python3
"""Mimikatz Detection - Analyzes logs for T1003.001 indicators."""

import json, csv, argparse, datetime, re
from collections import defaultdict
from pathlib import Path

DETECTION_PATTERNS = [
    r'sekurlsa::',
    r'lsadump::',
    r'kerberos::list',
    r'privilege::debug',
    r'token::elevate',
    r'dpapi::',
    r'vault::cred',
    r'crypto::cng',
    r'Invoke-Mimikatz',
    r'mimikatz',
    r'gentilkiwi',
]

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

def analyze_event(event):
    cmd = event.get("CommandLine", event.get("command_line", event.get("ProcessCommandLine", "")))
    content = event.get("Task_Content", event.get("Parameters", event.get("RawEventData", "")))
    search_text = f"{cmd} {content}"
    risk = 0
    indicators = []
    for pattern in DETECTION_PATTERNS:
        if re.search(pattern, search_text, re.IGNORECASE):
            risk += 25
            indicators.append(f"Pattern match: {pattern}")
    if not indicators:
        return None
    risk = min(risk, 100)
    return {
        "technique": "T1003.001",
        "command_line": cmd[:500] if cmd else content[:500],
        "hostname": event.get("Computer", event.get("DeviceName", event.get("hostname", "unknown"))),
        "user": event.get("User", event.get("AccountName", event.get("UserId", "unknown"))),
        "timestamp": event.get("_time", event.get("timestamp", event.get("UtcTime", event.get("Timestamp", "")))),
        "risk_score": risk,
        "risk_level": "CRITICAL" if risk >= 75 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 25 else "LOW",
        "indicators": indicators,
    }

def run_hunt(input_path, output_dir):
    print(f"[*] Mimikatz Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_logs(input_path)
    findings = [f for f in (analyze_event(e) for e in events) if f]
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    slug = "detecting_mimikatz_e"
    with open(Path(output_dir) / f"{slug}_findings.json", "w", encoding="utf-8") as f:
        json.dump({"hunt_id": f"TH-{datetime.date.today()}", "total_events": len(events), "findings": findings}, f, indent=2)
    with open(Path(output_dir) / "hunt_report.md", "w", encoding="utf-8") as f:
        f.write(f"# Mimikatz Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for finding in sorted(findings, key=lambda x: x["risk_score"], reverse=True)[:20]:
            f.write(f"### [{finding['risk_level']}] {finding['technique']}\n")
            f.write(f"- **Host**: {finding['hostname']}\n")
            f.write(f"- **Indicators**: {', '.join(finding['indicators'])}\n\n")
    print(f"[+] {len(findings)} findings written to {output_dir}")

def main():
    p = argparse.ArgumentParser(description="Mimikatz Detection")
    sp = p.add_subparsers(dest="cmd")
    h = sp.add_parser("hunt"); h.add_argument("--input", "-i", required=True); h.add_argument("--output", "-o", default="./detecting_mimik_output")
    sp.add_parser("queries")
    args = p.parse_args()
    if args.cmd == "hunt": run_hunt(args.input, args.output)
    elif args.cmd == "queries":
        print("=== Detection Queries ===")
        print("See references/workflows.md for platform-specific queries")
    else: p.print_help()

if __name__ == "__main__": main()
