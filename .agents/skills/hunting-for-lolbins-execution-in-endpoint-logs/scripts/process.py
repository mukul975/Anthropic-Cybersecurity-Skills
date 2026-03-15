#!/usr/bin/env python3
"""
LOLBins Execution Hunting Script
Analyzes process creation logs to detect suspicious usage of
Living Off the Land Binaries by matching command-line patterns.
"""

import json
import csv
import argparse
import datetime
import re
from pathlib import Path

LOLBIN_PATTERNS = {
    "certutil.exe": {
        "patterns": [
            (r"(?i)-urlcache", "download_cradle", "HIGH"),
            (r"(?i)-decode", "file_decode", "HIGH"),
            (r"(?i)-encode", "file_encode", "MEDIUM"),
            (r"(?i)-verifyctl", "download_alt", "HIGH"),
        ],
        "technique": "T1140",
    },
    "mshta.exe": {
        "patterns": [
            (r"(?i)https?://", "remote_hta", "CRITICAL"),
            (r"(?i)javascript:", "inline_script", "CRITICAL"),
            (r"(?i)vbscript:", "inline_vbs", "CRITICAL"),
        ],
        "technique": "T1218.005",
    },
    "rundll32.exe": {
        "patterns": [
            (r"(?i)\\(temp|appdata|users)\\", "unusual_dll_path", "HIGH"),
            (r"(?i)javascript:", "js_execution", "CRITICAL"),
            (r"(?i)shell32\.dll.*ShellExec_RunDLL", "shell_exec", "MEDIUM"),
        ],
        "technique": "T1218.011",
    },
    "regsvr32.exe": {
        "patterns": [
            (r"(?i)/s.*/n.*/u.*/i:", "squiblydoo", "CRITICAL"),
            (r"(?i)scrobj\.dll", "scriptlet_exec", "CRITICAL"),
            (r"(?i)https?://", "remote_registration", "CRITICAL"),
        ],
        "technique": "T1218.010",
    },
    "msbuild.exe": {
        "patterns": [
            (r"(?i)\\(temp|appdata|users|public)\\", "unusual_project", "HIGH"),
            (r"(?i)\.(csproj|vbproj|xml)$", "project_execution", "MEDIUM"),
        ],
        "technique": "T1127.001",
    },
    "bitsadmin.exe": {
        "patterns": [
            (r"(?i)/transfer", "bits_download", "HIGH"),
            (r"(?i)/create.*(/addfile|/setnotifycmdline)", "bits_persistence", "CRITICAL"),
        ],
        "technique": "T1197",
    },
    "cmstp.exe": {
        "patterns": [
            (r"(?i)/s.*/ni", "uac_bypass", "CRITICAL"),
            (r"(?i)\.inf", "inf_execution", "HIGH"),
        ],
        "technique": "T1218.003",
    },
    "wmic.exe": {
        "patterns": [
            (r"(?i)/format:", "xsl_execution", "HIGH"),
            (r"(?i)process\s+call\s+create", "remote_exec", "HIGH"),
        ],
        "technique": "T1047",
    },
}

SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "w3wp.exe", "httpd.exe", "nginx.exe",
    "wmiprvse.exe", "svchost.exe",
}


def parse_events(input_path: str) -> list[dict]:
    """Parse process creation events from JSON or CSV."""
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


def analyze_lolbins(events: list[dict]) -> list[dict]:
    """Detect suspicious LOLBin execution patterns."""
    findings = []
    for event in events:
        image = event.get("Image", event.get("FileName", event.get("image", "")))
        cmdline = event.get("CommandLine", event.get("ProcessCommandLine", event.get("command_line", "")))
        parent = event.get("ParentImage", event.get("InitiatingProcessFileName", event.get("parent_image", "")))
        user = event.get("User", event.get("AccountName", event.get("user", "")))
        computer = event.get("Computer", event.get("DeviceName", event.get("host", "")))
        timestamp = event.get("UtcTime", event.get("Timestamp", event.get("_time", "")))

        if not image or not cmdline:
            continue

        image_name = image.split("\\")[-1].lower()
        for lolbin, config in LOLBIN_PATTERNS.items():
            if image_name != lolbin.lower():
                continue
            for pattern, category, severity in config["patterns"]:
                if re.search(pattern, cmdline):
                    parent_name = parent.split("\\")[-1].lower() if parent else ""
                    suspicious_parent = parent_name in SUSPICIOUS_PARENTS
                    if suspicious_parent:
                        severity = "CRITICAL"

                    findings.append({
                        "timestamp": timestamp,
                        "computer": computer,
                        "user": user,
                        "lolbin": lolbin,
                        "image_path": image,
                        "command_line": cmdline,
                        "parent_process": parent,
                        "technique": config["technique"],
                        "category": category,
                        "severity": severity,
                        "suspicious_parent": suspicious_parent,
                    })
                    break

    return sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4))


def run_hunt(input_path: str, output_dir: str) -> None:
    """Execute LOLBin hunting analysis."""
    print(f"[*] LOLBin Execution Hunt - {datetime.datetime.now().isoformat()}")
    events = parse_events(input_path)
    print(f"[*] Loaded {len(events)} process events")

    findings = analyze_lolbins(events)
    print(f"[!] LOLBin detections: {len(findings)}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(output_path / "lolbin_findings.json", "w", encoding="utf-8") as f:
        json.dump({
            "hunt_id": f"TH-LOLBIN-{datetime.date.today().isoformat()}",
            "total_events": len(events),
            "findings_count": len(findings),
            "findings": findings,
        }, f, indent=2)

    with open(output_path / "lolbin_report.md", "w", encoding="utf-8") as f:
        f.write("# LOLBin Execution Hunt Report\n\n")
        f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Events Analyzed**: {len(events)}\n")
        f.write(f"**Findings**: {len(findings)}\n\n")
        for finding in findings:
            f.write(f"## [{finding['severity']}] {finding['lolbin']} - {finding['category']}\n")
            f.write(f"- **Host**: {finding['computer']}\n")
            f.write(f"- **User**: {finding['user']}\n")
            f.write(f"- **Command**: `{finding['command_line']}`\n")
            f.write(f"- **Parent**: {finding['parent_process']}\n")
            f.write(f"- **Technique**: {finding['technique']}\n\n")

    print(f"[+] Results written to {output_dir}")


def main():
    parser = argparse.ArgumentParser(description="LOLBin Execution Hunting")
    parser.add_argument("--input", "-i", required=True, help="Path to process creation logs")
    parser.add_argument("--output", "-o", default="./lolbin_hunt_output", help="Output directory")
    args = parser.parse_args()
    run_hunt(args.input, args.output)


if __name__ == "__main__":
    main()
