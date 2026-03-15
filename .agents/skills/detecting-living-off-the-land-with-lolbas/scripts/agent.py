#!/usr/bin/env python3
"""Detect Living Off the Land Binaries (LOLBAS) abuse via process telemetry and Sigma rules."""

import json
import re
import argparse
from datetime import datetime
from collections import defaultdict

LOLBIN_SIGNATURES = {
    "certutil.exe": {
        "suspicious_args": ["-urlcache", "-split", "-decode", "-encode", "-f http", "-verifyctl"],
        "mitre": "T1140",
        "description": "Certificate utility abused for download/decode",
    },
    "mshta.exe": {
        "suspicious_args": ["http://", "https://", "javascript:", "vbscript:", ".hta"],
        "mitre": "T1218.005",
        "description": "HTML Application host executing remote content",
    },
    "regsvr32.exe": {
        "suspicious_args": ["/s /n /u /i:http", "/i:http", "scrobj.dll", ".sct"],
        "mitre": "T1218.010",
        "description": "COM scriptlet execution via regsvr32 (Squiblydoo)",
    },
    "rundll32.exe": {
        "suspicious_args": ["javascript:", "http://", "shell32.dll,ShellExec_RunDLL", "comsvcs.dll,MiniDump"],
        "mitre": "T1218.011",
        "description": "Rundll32 proxy execution or credential dumping",
    },
    "msbuild.exe": {
        "suspicious_args": [".xml", ".csproj", "/p:", "inline task"],
        "mitre": "T1127.001",
        "description": "MSBuild inline task code execution",
    },
    "bitsadmin.exe": {
        "suspicious_args": ["/transfer", "/create", "/addfile", "/resume", "/complete"],
        "mitre": "T1197",
        "description": "BITS job used for file download or persistence",
    },
    "wmic.exe": {
        "suspicious_args": ["process call create", "/node:", "os get", "format:"],
        "mitre": "T1047",
        "description": "WMI command-line for execution or reconnaissance",
    },
    "cmstp.exe": {
        "suspicious_args": ["/ni", "/s", ".inf"],
        "mitre": "T1218.003",
        "description": "CMSTP UAC bypass with malicious INF",
    },
}

SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wmiprvse.exe", "svchost.exe", "taskeng.exe", "cmd.exe",
}


def parse_process_events(log_path):
    """Parse Sysmon or Windows 4688 process creation events from JSON log."""
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                continue
    return events


def detect_lolbin_abuse(events):
    """Detect LOLBin abuse from process creation events."""
    detections = []
    for event in events:
        image = event.get("Image", event.get("NewProcessName", "")).lower()
        cmdline = event.get("CommandLine", event.get("ProcessCommandLine", "")).lower()
        parent = event.get("ParentImage", event.get("ParentProcessName", "")).lower()
        binary_name = image.rsplit("\\", 1)[-1] if "\\" in image else image.rsplit("/", 1)[-1]

        if binary_name not in LOLBIN_SIGNATURES:
            continue

        sig = LOLBIN_SIGNATURES[binary_name]
        matched_args = [arg for arg in sig["suspicious_args"] if arg.lower() in cmdline]
        if not matched_args:
            continue

        parent_name = parent.rsplit("\\", 1)[-1] if "\\" in parent else parent.rsplit("/", 1)[-1]
        parent_suspicious = parent_name in SUSPICIOUS_PARENTS

        severity = "high" if parent_suspicious else "medium"
        if len(matched_args) > 1:
            severity = "critical"

        detections.append({
            "timestamp": event.get("UtcTime", event.get("TimeCreated", datetime.utcnow().isoformat())),
            "binary": binary_name,
            "command_line": event.get("CommandLine", event.get("ProcessCommandLine", "")),
            "parent_process": parent,
            "parent_suspicious": parent_suspicious,
            "matched_signatures": matched_args,
            "mitre_technique": sig["mitre"],
            "description": sig["description"],
            "severity": severity,
            "user": event.get("User", event.get("SubjectUserName", "unknown")),
            "pid": event.get("ProcessId", event.get("NewProcessId", "")),
        })
    return detections


def generate_sigma_rule(binary_name):
    """Generate a Sigma detection rule for a specific LOLBin."""
    if binary_name not in LOLBIN_SIGNATURES:
        return None
    sig = LOLBIN_SIGNATURES[binary_name]
    rule = {
        "title": f"Suspicious {binary_name} Execution",
        "id": f"lolbas-{binary_name.replace('.exe', '')}-detection",
        "status": "experimental",
        "description": sig["description"],
        "references": ["https://lolbas-project.github.io/"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": f"\\{binary_name}"},
            "condition_args": {
                "CommandLine|contains": sig["suspicious_args"]
            },
            "condition": "selection and condition_args",
        },
        "falsepositives": ["Legitimate administrative use"],
        "level": "high",
        "tags": [f"attack.{sig['mitre'].lower()}"],
    }
    return rule


def build_report(detections, log_path):
    """Build structured detection report."""
    by_binary = defaultdict(list)
    for d in detections:
        by_binary[d["binary"]].append(d)

    severity_counts = defaultdict(int)
    for d in detections:
        severity_counts[d["severity"]] += 1

    return {
        "report_time": datetime.utcnow().isoformat(),
        "log_source": log_path,
        "total_detections": len(detections),
        "severity_summary": dict(severity_counts),
        "detections_by_binary": {k: len(v) for k, v in by_binary.items()},
        "mitre_techniques": list({d["mitre_technique"] for d in detections}),
        "detections": detections,
    }


def main():
    parser = argparse.ArgumentParser(description="LOLBAS Abuse Detection Agent")
    parser.add_argument("--log-file", required=True, help="JSON log file with process creation events")
    parser.add_argument("--output", default="lolbas_detections.json", help="Output report path")
    parser.add_argument("--generate-sigma", action="store_true", help="Generate Sigma rules for all LOLBins")
    args = parser.parse_args()

    events = parse_process_events(args.log_file)
    detections = detect_lolbin_abuse(events)
    report = build_report(detections, args.log_file)

    if args.generate_sigma:
        report["sigma_rules"] = {}
        for binary in LOLBIN_SIGNATURES:
            report["sigma_rules"][binary] = generate_sigma_rule(binary)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Analyzed {len(events)} events, found {len(detections)} LOLBin abuse detections")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
