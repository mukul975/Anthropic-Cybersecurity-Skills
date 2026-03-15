#!/usr/bin/env python3
"""
Tetragon Runtime Security Event Analyzer

Parses Tetragon JSON event logs and generates security reports
including process execution anomalies, policy violations, and
container escape attempt detection.
"""

import json
import sys
import subprocess
import argparse
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path


def run_kubectl_command(command: list[str]) -> str:
    """Execute a kubectl command and return output."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"[ERROR] kubectl command failed: {result.stderr.strip()}")
            return ""
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print("[ERROR] kubectl command timed out")
        return ""
    except FileNotFoundError:
        print("[ERROR] kubectl not found in PATH")
        return ""


def get_tetragon_status() -> dict:
    """Check Tetragon DaemonSet health."""
    output = run_kubectl_command([
        "kubectl", "get", "ds", "tetragon", "-n", "kube-system",
        "-o", "jsonpath={.status.desiredNumberScheduled},{.status.numberReady}"
    ])
    if not output:
        return {"healthy": False, "desired": 0, "ready": 0}
    parts = output.split(",")
    desired = int(parts[0]) if len(parts) > 0 and parts[0] else 0
    ready = int(parts[1]) if len(parts) > 1 and parts[1] else 0
    return {"healthy": desired == ready and desired > 0, "desired": desired, "ready": ready}


def get_tracing_policies() -> list[dict]:
    """List all TracingPolicies deployed in the cluster."""
    output = run_kubectl_command([
        "kubectl", "get", "tracingpolicies", "-o", "json"
    ])
    if not output:
        return []
    try:
        data = json.loads(output)
        policies = []
        for item in data.get("items", []):
            policies.append({
                "name": item["metadata"]["name"],
                "created": item["metadata"].get("creationTimestamp", "unknown"),
                "kprobes": len(item.get("spec", {}).get("kprobes", [])),
                "tracepoints": len(item.get("spec", {}).get("tracepoints", []))
            })
        return policies
    except (json.JSONDecodeError, KeyError):
        return []


def parse_tetragon_events(log_file: str) -> list[dict]:
    """Parse Tetragon JSON event log file."""
    events = []
    path = Path(log_file)
    if not path.exists():
        print(f"[ERROR] Log file not found: {log_file}")
        return events

    with open(path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                print(f"[WARN] Skipping malformed JSON at line {line_num}")
    return events


def classify_event(event: dict) -> str:
    """Classify a Tetragon event by type."""
    if "process_exec" in event:
        return "process_exec"
    elif "process_exit" in event:
        return "process_exit"
    elif "process_kprobe" in event:
        return "kprobe"
    elif "process_tracepoint" in event:
        return "tracepoint"
    elif "process_lsm" in event:
        return "lsm"
    return "unknown"


def extract_process_info(event: dict) -> dict:
    """Extract process information from a Tetragon event."""
    info = {"binary": "", "args": "", "namespace": "", "pod": "", "uid": 0, "action": ""}
    for event_type in ["process_exec", "process_kprobe", "process_tracepoint"]:
        if event_type in event:
            process = event[event_type].get("process", {})
            info["binary"] = process.get("binary", "")
            info["args"] = process.get("arguments", "")
            info["uid"] = process.get("uid", {}).get("value", 0)
            pod_info = process.get("pod", {})
            info["namespace"] = pod_info.get("namespace", "")
            info["pod"] = pod_info.get("name", "")
            if event_type == "process_kprobe":
                info["action"] = event[event_type].get("action", "")
            break
    return info


def detect_suspicious_binaries(events: list[dict]) -> list[dict]:
    """Detect execution of known suspicious binaries."""
    suspicious_binaries = {
        "/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/curl",
        "/usr/bin/wget", "/usr/bin/nc", "/usr/bin/ncat",
        "/usr/bin/nmap", "/usr/bin/python", "/usr/bin/python3",
        "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/gcc",
        "/usr/bin/cc", "/usr/bin/make", "/usr/bin/xmrig",
        "/tmp/xmrig", "/usr/bin/minerd",
        "/usr/bin/sudo", "/bin/su", "/usr/bin/passwd",
        "/usr/bin/nsenter", "/usr/bin/unshare"
    }
    findings = []
    for event in events:
        info = extract_process_info(event)
        if info["binary"] in suspicious_binaries:
            findings.append({
                "severity": "HIGH" if info["binary"] in {"/usr/bin/xmrig", "/usr/bin/nsenter", "/usr/bin/unshare"} else "MEDIUM",
                "binary": info["binary"],
                "args": info["args"],
                "namespace": info["namespace"],
                "pod": info["pod"],
                "description": f"Suspicious binary execution: {info['binary']}"
            })
    return findings


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """Detect privilege escalation attempts from event data."""
    findings = []
    priv_esc_binaries = {"/usr/bin/sudo", "/bin/su", "/usr/bin/passwd", "/usr/bin/newgrp"}
    for event in events:
        info = extract_process_info(event)
        if info["binary"] in priv_esc_binaries and info["namespace"]:
            findings.append({
                "severity": "CRITICAL",
                "binary": info["binary"],
                "namespace": info["namespace"],
                "pod": info["pod"],
                "description": f"Privilege escalation attempt via {info['binary']} in pod {info['pod']}"
            })
        if info["uid"] == 0 and info["binary"] and info["namespace"]:
            findings.append({
                "severity": "HIGH",
                "binary": info["binary"],
                "namespace": info["namespace"],
                "pod": info["pod"],
                "description": f"Process running as root (UID 0): {info['binary']}"
            })
    return findings


def detect_container_escape_attempts(events: list[dict]) -> list[dict]:
    """Detect potential container escape attempts."""
    escape_indicators = {
        "__x64_sys_setns": "Namespace manipulation (potential container escape)",
        "__x64_sys_unshare": "Namespace unshare (potential privilege escalation)",
        "__x64_sys_mount": "Mount syscall (potential host filesystem access)",
        "__x64_sys_ptrace": "Ptrace syscall (potential process injection)",
    }
    findings = []
    for event in events:
        if "process_kprobe" in event:
            function_name = event["process_kprobe"].get("functionName", "")
            if function_name in escape_indicators:
                info = extract_process_info(event)
                findings.append({
                    "severity": "CRITICAL",
                    "function": function_name,
                    "binary": info["binary"],
                    "namespace": info["namespace"],
                    "pod": info["pod"],
                    "action": info["action"],
                    "description": escape_indicators[function_name]
                })
    return findings


def generate_event_summary(events: list[dict]) -> dict:
    """Generate a statistical summary of Tetragon events."""
    event_types = Counter()
    namespaces = Counter()
    binaries = Counter()
    actions = Counter()

    for event in events:
        event_type = classify_event(event)
        event_types[event_type] += 1
        info = extract_process_info(event)
        if info["namespace"]:
            namespaces[info["namespace"]] += 1
        if info["binary"]:
            binaries[info["binary"]] += 1
        if info["action"]:
            actions[info["action"]] += 1

    return {
        "total_events": len(events),
        "event_types": dict(event_types.most_common(10)),
        "top_namespaces": dict(namespaces.most_common(10)),
        "top_binaries": dict(binaries.most_common(20)),
        "enforcement_actions": dict(actions),
    }


def generate_report(events: list[dict], output_format: str = "text") -> str:
    """Generate a comprehensive security report."""
    summary = generate_event_summary(events)
    suspicious = detect_suspicious_binaries(events)
    priv_esc = detect_privilege_escalation(events)
    escape_attempts = detect_container_escape_attempts(events)
    tetragon_status = get_tetragon_status()
    policies = get_tracing_policies()

    if output_format == "json":
        report = {
            "report_generated": datetime.utcnow().isoformat(),
            "tetragon_status": tetragon_status,
            "tracing_policies": policies,
            "event_summary": summary,
            "findings": {
                "suspicious_binaries": suspicious,
                "privilege_escalation": priv_esc,
                "container_escape_attempts": escape_attempts
            },
            "risk_score": calculate_risk_score(suspicious, priv_esc, escape_attempts)
        }
        return json.dumps(report, indent=2)

    lines = []
    lines.append("=" * 70)
    lines.append("TETRAGON RUNTIME SECURITY REPORT")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}")
    lines.append("=" * 70)

    lines.append("\n## Tetragon Health")
    lines.append(f"  Status: {'HEALTHY' if tetragon_status['healthy'] else 'DEGRADED'}")
    lines.append(f"  Nodes: {tetragon_status['ready']}/{tetragon_status['desired']} ready")

    lines.append(f"\n## TracingPolicies Deployed: {len(policies)}")
    for p in policies:
        lines.append(f"  - {p['name']} (kprobes: {p['kprobes']}, tracepoints: {p['tracepoints']})")

    lines.append(f"\n## Event Summary")
    lines.append(f"  Total Events: {summary['total_events']}")
    lines.append("  Event Types:")
    for etype, count in summary["event_types"].items():
        lines.append(f"    {etype}: {count}")

    lines.append("\n  Top Namespaces:")
    for ns, count in summary["top_namespaces"].items():
        lines.append(f"    {ns}: {count}")

    lines.append("\n  Top Binaries:")
    for binary, count in list(summary["top_binaries"].items())[:10]:
        lines.append(f"    {binary}: {count}")

    risk = calculate_risk_score(suspicious, priv_esc, escape_attempts)
    lines.append(f"\n## Risk Score: {risk['score']}/100 ({risk['level']})")

    if escape_attempts:
        lines.append(f"\n## CRITICAL: Container Escape Attempts ({len(escape_attempts)})")
        for f in escape_attempts:
            lines.append(f"  [{f['severity']}] {f['description']}")
            lines.append(f"    Pod: {f['namespace']}/{f['pod']} | Binary: {f['binary']}")

    if priv_esc:
        lines.append(f"\n## Privilege Escalation Findings ({len(priv_esc)})")
        for f in priv_esc[:20]:
            lines.append(f"  [{f['severity']}] {f['description']}")

    if suspicious:
        lines.append(f"\n## Suspicious Binary Executions ({len(suspicious)})")
        for f in suspicious[:20]:
            lines.append(f"  [{f['severity']}] {f['description']}")
            lines.append(f"    Namespace: {f['namespace']} | Pod: {f['pod']}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def calculate_risk_score(suspicious: list, priv_esc: list, escapes: list) -> dict:
    """Calculate overall risk score based on findings."""
    score = 0
    score += len(escapes) * 25
    score += len([f for f in priv_esc if f["severity"] == "CRITICAL"]) * 15
    score += len([f for f in priv_esc if f["severity"] == "HIGH"]) * 5
    score += len([f for f in suspicious if f["severity"] == "HIGH"]) * 10
    score += len([f for f in suspicious if f["severity"] == "MEDIUM"]) * 3
    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level}


def main():
    parser = argparse.ArgumentParser(
        description="Tetragon Runtime Security Event Analyzer"
    )
    parser.add_argument(
        "--log-file",
        help="Path to Tetragon JSON event log file"
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--status-only", action="store_true",
        help="Only check Tetragon health and policy status"
    )
    args = parser.parse_args()

    if args.status_only:
        status = get_tetragon_status()
        policies = get_tracing_policies()
        print(f"Tetragon Health: {'HEALTHY' if status['healthy'] else 'DEGRADED'}")
        print(f"Nodes Ready: {status['ready']}/{status['desired']}")
        print(f"TracingPolicies: {len(policies)}")
        for p in policies:
            print(f"  - {p['name']}")
        return

    if not args.log_file:
        print("[ERROR] --log-file is required (or use --status-only)")
        sys.exit(1)

    events = parse_tetragon_events(args.log_file)
    if not events:
        print("[WARN] No events found in log file")
        return

    report = generate_report(events, args.format)
    print(report)


if __name__ == "__main__":
    main()
