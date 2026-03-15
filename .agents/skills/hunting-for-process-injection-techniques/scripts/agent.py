#!/usr/bin/env python3
"""Detect process injection techniques (T1055) via Sysmon Event IDs 8 and 10."""

import json
import argparse
from datetime import datetime
from collections import defaultdict

LEGITIMATE_INJECTION_PAIRS = {
    ("csrss.exe", "svchost.exe"), ("lsass.exe", "svchost.exe"),
    ("services.exe", "svchost.exe"), ("smss.exe", "csrss.exe"),
    ("wininit.exe", "services.exe"), ("svchost.exe", "runtimebroker.exe"),
    ("msmpeng.exe", "svchost.exe"),  # Windows Defender
    ("mbamservice.exe", "svchost.exe"),  # Malwarebytes
    ("avp.exe", "svchost.exe"),  # Kaspersky
}

SUSPICIOUS_SOURCE_PROCESSES = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "msbuild.exe", "installutil.exe",
    "winword.exe", "excel.exe", "powerpnt.exe",
}

HIGH_VALUE_TARGETS = {
    "lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe",
    "csrss.exe", "services.exe", "spoolsv.exe", "taskhost.exe",
    "dllhost.exe", "wininit.exe",
}

DANGEROUS_ACCESS_RIGHTS = {
    "0x1F0FFF": "PROCESS_ALL_ACCESS",
    "0x001F0FFF": "PROCESS_ALL_ACCESS",
    "0x1FFFFF": "PROCESS_ALL_ACCESS",
    "0x0040": "PROCESS_DUP_HANDLE",
    "0x0020": "PROCESS_VM_WRITE",
    "0x0008": "PROCESS_VM_OPERATION",
    "0x0002": "PROCESS_CREATE_THREAD",
    "0x001A": "PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD",
    "0x143A": "CLASSIC_INJECTION_RIGHTS",
}

INJECTION_SUBTECHNIQUES = {
    "CreateRemoteThread": {"id": "T1055.001", "name": "DLL Injection"},
    "NtWriteVirtualMemory": {"id": "T1055.001", "name": "DLL Injection"},
    "QueueUserAPC": {"id": "T1055.004", "name": "APC Injection"},
    "NtMapViewOfSection": {"id": "T1055.012", "name": "Process Hollowing"},
    "SetWindowsHookEx": {"id": "T1055.001", "name": "DLL Injection via Hook"},
}


def parse_sysmon_events(log_path):
    """Parse Sysmon JSON events, focusing on Event IDs 1, 8, and 10."""
    events = {"process_create": [], "create_remote_thread": [], "process_access": []}
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_id = event.get("EventID", event.get("event_id", 0))
            if event_id == 1:
                events["process_create"].append(event)
            elif event_id == 8:
                events["create_remote_thread"].append(event)
            elif event_id == 10:
                events["process_access"].append(event)
    return events


def detect_remote_thread_injection(events):
    """Detect suspicious CreateRemoteThread (Sysmon Event ID 8)."""
    detections = []
    for event in events:
        source_image = event.get("SourceImage", "").lower()
        target_image = event.get("TargetImage", "").lower()
        source_name = source_image.rsplit("\\", 1)[-1] if "\\" in source_image else source_image
        target_name = target_image.rsplit("\\", 1)[-1] if "\\" in target_image else target_image

        if (source_name, target_name) in LEGITIMATE_INJECTION_PAIRS:
            continue

        severity = "medium"
        if source_name in SUSPICIOUS_SOURCE_PROCESSES:
            severity = "high"
        if target_name in HIGH_VALUE_TARGETS:
            severity = "critical" if severity == "high" else "high"

        start_function = event.get("StartFunction", "")
        start_module = event.get("StartModule", "")
        subtechnique = INJECTION_SUBTECHNIQUES.get("CreateRemoteThread", {})

        detections.append({
            "event_id": 8,
            "timestamp": event.get("UtcTime", event.get("TimeCreated", "")),
            "source_image": event.get("SourceImage", ""),
            "target_image": event.get("TargetImage", ""),
            "start_function": start_function,
            "start_module": start_module,
            "source_pid": event.get("SourceProcessId", ""),
            "target_pid": event.get("TargetProcessId", ""),
            "new_thread_id": event.get("NewThreadId", ""),
            "user": event.get("User", "unknown"),
            "severity": severity,
            "mitre_technique": subtechnique.get("id", "T1055"),
            "mitre_name": subtechnique.get("name", "Process Injection"),
            "indicator": f"CreateRemoteThread: {source_name} -> {target_name}",
        })
    return detections


def detect_suspicious_process_access(events):
    """Detect suspicious ProcessAccess (Sysmon Event ID 10)."""
    detections = []
    for event in events:
        source_image = event.get("SourceImage", "").lower()
        target_image = event.get("TargetImage", "").lower()
        source_name = source_image.rsplit("\\", 1)[-1] if "\\" in source_image else source_image
        target_name = target_image.rsplit("\\", 1)[-1] if "\\" in target_image else target_image
        granted_access = event.get("GrantedAccess", "").lower()

        if (source_name, target_name) in LEGITIMATE_INJECTION_PAIRS:
            continue

        access_label = DANGEROUS_ACCESS_RIGHTS.get(granted_access, "")
        if not access_label and granted_access not in {"0x1f0fff", "0x001a", "0x143a", "0x0020"}:
            continue

        severity = "medium"
        if source_name in SUSPICIOUS_SOURCE_PROCESSES:
            severity = "high"
        if target_name == "lsass.exe":
            severity = "critical"
        if "ALL_ACCESS" in access_label:
            severity = "critical"

        detections.append({
            "event_id": 10,
            "timestamp": event.get("UtcTime", event.get("TimeCreated", "")),
            "source_image": event.get("SourceImage", ""),
            "target_image": event.get("TargetImage", ""),
            "granted_access": granted_access,
            "access_label": access_label,
            "source_pid": event.get("SourceProcessId", ""),
            "target_pid": event.get("TargetProcessId", ""),
            "user": event.get("User", "unknown"),
            "severity": severity,
            "mitre_technique": "T1055",
            "indicator": f"Suspicious process access: {source_name} -> {target_name} ({access_label})",
        })
    return detections


def build_injection_graph(thread_detections, access_detections):
    """Build a source->target injection relationship graph."""
    graph = defaultdict(lambda: {"targets": set(), "event_count": 0})
    for d in thread_detections + access_detections:
        src = d["source_image"].rsplit("\\", 1)[-1] if "\\" in d["source_image"] else d["source_image"]
        tgt = d["target_image"].rsplit("\\", 1)[-1] if "\\" in d["target_image"] else d["target_image"]
        graph[src]["targets"].add(tgt)
        graph[src]["event_count"] += 1
    return {src: {"targets": list(info["targets"]), "event_count": info["event_count"]}
            for src, info in graph.items()}


def generate_report(events, thread_detections, access_detections, injection_graph, log_path):
    """Generate process injection hunt report."""
    all_detections = thread_detections + access_detections
    severity_counts = defaultdict(int)
    for d in all_detections:
        severity_counts[d["severity"]] += 1
    return {
        "report_time": datetime.utcnow().isoformat(),
        "log_source": log_path,
        "events_parsed": {
            "process_create": len(events["process_create"]),
            "create_remote_thread": len(events["create_remote_thread"]),
            "process_access": len(events["process_access"]),
        },
        "total_detections": len(all_detections),
        "severity_summary": dict(severity_counts),
        "create_remote_thread_detections": thread_detections,
        "process_access_detections": access_detections,
        "injection_graph": injection_graph,
        "mitre_techniques": ["T1055", "T1055.001", "T1055.004", "T1055.012"],
    }


def main():
    parser = argparse.ArgumentParser(description="Process Injection Detection Agent (T1055)")
    parser.add_argument("--log-file", required=True, help="Sysmon JSON event log file")
    parser.add_argument("--output", default="process_injection_report.json")
    args = parser.parse_args()

    events = parse_sysmon_events(args.log_file)
    thread_detections = detect_remote_thread_injection(events["create_remote_thread"])
    access_detections = detect_suspicious_process_access(events["process_access"])
    injection_graph = build_injection_graph(thread_detections, access_detections)

    report = generate_report(events, thread_detections, access_detections, injection_graph, args.log_file)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    total = len(thread_detections) + len(access_detections)
    print(f"[+] Parsed {sum(len(v) for v in events.values())} Sysmon events")
    print(f"[+] CreateRemoteThread: {len(thread_detections)} | ProcessAccess: {len(access_detections)}")
    print(f"[+] Total injections detected: {total}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
