#!/usr/bin/env python3
"""Registry Run Key Persistence Hunter - detects T1547.001 persistence via Sysmon Event 13 analysis and registry run key auditing"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

RUN_KEY_PATHS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
]

SUSPICIOUS_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp",
    r"\\downloads\\", r"\\programdata\\", r"\\public\\",
    r"\\users\\public", r"\\recycler\\", r"\\perflogs\\",
]

LOLBINS = [
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe", "forfiles.exe",
    "pcalua.exe", "bash.exe", "scriptrunner.exe",
]

SUSPICIOUS_MODIFIERS = [
    "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe", "python3.exe",
    "wmic.exe", "reg.exe", "mshta.exe", "cscript.exe", "wscript.exe",
]

KNOWN_GOOD_VALUES = [
    "SecurityHealth", "WindowsDefender", "iTunesHelper", "VMware",
    "RealTimeProtection", "OneDrive", "Teams", "Spotify",
]


def load_data(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def is_run_key(target_object):
    """Check if registry path matches Run/RunOnce keys."""
    target_lower = target_object.lower().replace("/", "\\")
    for rk in RUN_KEY_PATHS:
        if rk.lower() in target_lower:
            return True
    return False


def analyze_sysmon_events(events):
    """Analyze Sysmon Event ID 13 (RegistryEvent Value Set) for persistence."""
    findings = []
    for evt in events:
        event_id = evt.get("EventID", evt.get("event_id", evt.get("EventCode", 0)))
        if str(event_id) != "13":
            continue
        event_data = evt.get("EventData", evt)
        target_obj = event_data.get("TargetObject", event_data.get("target_object", ""))
        details = event_data.get("Details", event_data.get("details", event_data.get("value", "")))
        image = event_data.get("Image", event_data.get("image", event_data.get("process", "")))
        user = event_data.get("User", event_data.get("user", ""))
        timestamp = evt.get("TimeCreated", evt.get("timestamp", evt.get("UtcTime", "")))
        if not is_run_key(target_obj):
            continue
        severity = "medium"
        indicators = []
        details_lower = (details or "").lower()
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path.lower() in details_lower:
                severity = "high"
                indicators.append(f"suspicious_path:{susp_path.strip(chr(92))}")
                break
        for lolbin in LOLBINS:
            if lolbin.lower() in details_lower:
                severity = "high"
                indicators.append(f"lolbin:{lolbin}")
                break
        if "powershell" in details_lower and ("-enc" in details_lower or "-e " in details_lower or "encodedcommand" in details_lower):
            severity = "critical"
            indicators.append("encoded_powershell")
        if re.search(r"(FromBase64|IEX|Invoke-Expression|DownloadString|Net\.WebClient)", details or "", re.IGNORECASE):
            severity = "critical"
            indicators.append("malicious_powershell_pattern")
        image_name = (image or "").split("\\")[-1].lower()
        for susp_mod in SUSPICIOUS_MODIFIERS:
            if susp_mod.lower() == image_name:
                severity = max(severity, "high", key=lambda x: {"low": 0, "medium": 1, "high": 2, "critical": 3}[x])
                indicators.append(f"suspicious_modifier:{susp_mod}")
                break
        value_name = target_obj.split("\\")[-1] if "\\" in target_obj else target_obj
        is_known_good = any(kg.lower() in value_name.lower() for kg in KNOWN_GOOD_VALUES)
        if is_known_good:
            severity = "low"
            indicators.append("known_good_match")
        findings.append({
            "type": "registry_run_key_persistence",
            "severity": severity,
            "resource": target_obj,
            "detail": f"Run key set by {image_name or 'unknown'}: {(details or '')[:120]}",
            "mitre_technique": "T1547.001",
            "mitre_tactic": "Persistence",
            "modifying_process": image,
            "registry_value": details,
            "user": user,
            "timestamp": timestamp,
            "indicators": indicators,
        })
    return findings


def analyze_registry_snapshot(entries):
    """Analyze a static registry snapshot for suspicious Run key values."""
    findings = []
    for entry in entries:
        key_path = entry.get("key", entry.get("path", ""))
        value_name = entry.get("name", entry.get("value_name", ""))
        value_data = entry.get("data", entry.get("value_data", entry.get("value", "")))
        if not is_run_key(key_path) and not any(rk.lower().split("\\")[-1] in key_path.lower() for rk in RUN_KEY_PATHS[:4]):
            continue
        severity = "medium"
        indicators = []
        data_lower = (value_data or "").lower()
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path.lower() in data_lower:
                severity = "high"
                indicators.append(f"suspicious_path")
                break
        for lolbin in LOLBINS:
            if lolbin.lower() in data_lower:
                severity = "high"
                indicators.append(f"lolbin:{lolbin}")
                break
        if not Path(value_data.strip('"').split(" ")[0]).suffix.lower() in (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".com", ""):
            pass
        is_known = any(kg.lower() in (value_name or "").lower() for kg in KNOWN_GOOD_VALUES)
        if is_known:
            severity = "low"
        findings.append({
            "type": "run_key_entry",
            "severity": severity,
            "resource": f"{key_path}\\{value_name}",
            "detail": f"Value: {(value_data or '')[:120]}",
            "mitre_technique": "T1547.001",
            "indicators": indicators,
        })
    return findings


def generate_sigma_rule(finding):
    """Generate a Sigma detection rule from a finding."""
    details = finding.get("registry_value", finding.get("detail", ""))
    return {
        "title": f"Suspicious Run Key Persistence - {finding['resource'].split(chr(92))[-1]}",
        "status": "experimental",
        "logsource": {"product": "windows", "category": "registry_set"},
        "detection": {
            "selection": {
                "EventType": "SetValue",
                "TargetObject|contains": "CurrentVersion\\Run",
                "Details|contains": details[:60] if details else "",
            },
            "condition": "selection",
        },
        "level": finding["severity"],
        "tags": ["attack.persistence", "attack.t1547.001"],
    }


def analyze(data):
    findings = []
    if isinstance(data, list):
        has_event_id = any("EventID" in e or "event_id" in e or "EventCode" in e for e in data)
        if has_event_id:
            findings.extend(analyze_sysmon_events(data))
        else:
            findings.extend(analyze_registry_snapshot(data))
    elif isinstance(data, dict):
        sysmon = data.get("sysmon_events", data.get("events", []))
        registry = data.get("registry_entries", data.get("snapshot", []))
        findings.extend(analyze_sysmon_events(sysmon))
        findings.extend(analyze_registry_snapshot(registry))
    return findings


def generate_report(input_path):
    data = load_data(input_path)
    findings = analyze(data)
    sev = Counter(f["severity"] for f in findings)
    critical_high = [f for f in findings if f["severity"] in ("critical", "high")]
    sigma_rules = [generate_sigma_rule(f) for f in critical_high[:5]]
    return {
        "report": "registry_run_key_persistence_hunt",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "mitre_technique": "T1547.001",
        "total_findings": len(findings),
        "severity_summary": dict(sev),
        "high_priority_count": len(critical_high),
        "sigma_rules": sigma_rules,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description="Registry Run Key Persistence Hunter")
    ap.add_argument("--input", required=True, help="Input JSON with Sysmon events or registry snapshot")
    ap.add_argument("--output", help="Output JSON report path")
    args = ap.parse_args()
    report = generate_report(args.input)
    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
