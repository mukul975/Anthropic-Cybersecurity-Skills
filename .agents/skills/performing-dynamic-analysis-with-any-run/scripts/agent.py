#!/usr/bin/env python3
"""
Dynamic Analysis with ANY.RUN Agent
Submits malware samples to ANY.RUN sandbox via API, monitors task execution,
and retrieves behavioral analysis results including process trees, network
indicators, and MITRE ATT&CK mappings.

Supports both the official anyrun-sdk (pip install anyrun-sdk) with
SandboxConnector and the legacy REST API via requests.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

import requests

try:
    from anyrun.connectors import SandboxConnector
    HAS_ANYRUN_SDK = True
except ImportError:
    HAS_ANYRUN_SDK = False


ANYRUN_API_BASE = "https://api.any.run/v1"


def submit_file(filepath: str, api_key: str, os_version: str = "windows-10",
                 privacy: str = "private", timeout_seconds: int = 120) -> dict:
    """Submit a file to ANY.RUN for dynamic analysis."""
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    headers = {"Authorization": f"API-Key {api_key}"}

    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        data = {
            "env_os": os_version,
            "env_bitness": 64,
            "env_type": "complete",
            "opt_privacy_type": privacy,
            "opt_timeout": timeout_seconds,
            "opt_network_connect": True,
            "opt_network_fakenet": False,
            "opt_network_tor": False,
        }

        resp = requests.post(
            f"{ANYRUN_API_BASE}/analysis",
            headers=headers, files=files, data=data, timeout=60,
        )

    if resp.status_code in (200, 201):
        result = resp.json()
        return {
            "task_id": result.get("data", {}).get("taskid", ""),
            "status": "submitted",
            "task_url": f"https://app.any.run/tasks/{result.get('data', {}).get('taskid', '')}",
        }

    return {"error": f"Submission failed: {resp.status_code} - {resp.text[:200]}"}


def submit_url(url: str, api_key: str, os_version: str = "windows-10") -> dict:
    """Submit a URL to ANY.RUN for dynamic analysis."""
    headers = {"Authorization": f"API-Key {api_key}"}
    data = {
        "obj_url": url,
        "env_os": os_version,
        "env_bitness": 64,
        "opt_privacy_type": "private",
        "opt_timeout": 120,
        "opt_network_connect": True,
    }

    resp = requests.post(
        f"{ANYRUN_API_BASE}/analysis",
        headers=headers, data=data, timeout=60,
    )

    if resp.status_code in (200, 201):
        result = resp.json()
        return {
            "task_id": result.get("data", {}).get("taskid", ""),
            "status": "submitted",
        }

    return {"error": f"URL submission failed: {resp.status_code}"}


def get_task_report(task_id: str, api_key: str) -> dict:
    """Retrieve the full analysis report for a completed task."""
    headers = {"Authorization": f"API-Key {api_key}"}

    resp = requests.get(
        f"{ANYRUN_API_BASE}/analysis/{task_id}",
        headers=headers, timeout=30,
    )

    if resp.status_code != 200:
        return {"error": f"Report retrieval failed: {resp.status_code}"}

    data = resp.json().get("data", {})

    report = {
        "task_id": task_id,
        "verdict": data.get("analysis", {}).get("scores", {}).get("verdict", {}).get("verdict", "unknown"),
        "threat_level": data.get("analysis", {}).get("scores", {}).get("verdict", {}).get("threatLevelText", ""),
        "tags": data.get("analysis", {}).get("tags", []),
    }

    processes = data.get("analysis", {}).get("processes", [])
    report["processes"] = []
    for proc in processes:
        report["processes"].append({
            "pid": proc.get("pid", 0),
            "name": proc.get("fileName", ""),
            "command_line": proc.get("commandLine", "")[:200],
            "parent_pid": proc.get("parentPID", 0),
            "is_malicious": proc.get("scores", {}).get("verdict", {}).get("isMalicious", False),
        })

    network = data.get("analysis", {}).get("network", {})
    report["network"] = {
        "dns_requests": [
            {"domain": d.get("domain", ""), "ip": d.get("ip", "")}
            for d in network.get("dnsRequests", [])
        ],
        "http_requests": [
            {"url": h.get("url", ""), "method": h.get("method", ""), "status": h.get("status", 0)}
            for h in network.get("httpRequests", [])
        ],
        "connections": [
            {"ip": c.get("ip", ""), "port": c.get("port", 0), "protocol": c.get("protocol", "")}
            for c in network.get("connections", [])
        ],
    }

    mitre = data.get("analysis", {}).get("mitre", [])
    report["mitre_techniques"] = [
        {"technique_id": m.get("id", ""), "name": m.get("name", ""), "tactic": m.get("tactic", "")}
        for m in mitre
    ]

    return report


def wait_for_completion(task_id: str, api_key: str, max_wait: int = 300) -> dict:
    """Poll task status until analysis completes."""
    headers = {"Authorization": f"API-Key {api_key}"}
    start = time.time()

    while time.time() - start < max_wait:
        resp = requests.get(
            f"{ANYRUN_API_BASE}/analysis/{task_id}",
            headers=headers, timeout=30,
        )

        if resp.status_code == 200:
            status = resp.json().get("data", {}).get("analysis", {}).get("status", "")
            if status == "done":
                return {"status": "completed", "elapsed": round(time.time() - start)}
            if status == "failed":
                return {"status": "failed", "elapsed": round(time.time() - start)}

        time.sleep(15)

    return {"status": "timeout", "elapsed": max_wait}


def get_iocs_from_report(report: dict) -> dict:
    """Extract IOCs from an ANY.RUN analysis report."""
    iocs = {
        "domains": set(),
        "ips": set(),
        "urls": set(),
        "processes": [],
        "mitre_techniques": [],
    }

    for dns_req in report.get("network", {}).get("dns_requests", []):
        if dns_req.get("domain"):
            iocs["domains"].add(dns_req["domain"])
        if dns_req.get("ip"):
            iocs["ips"].add(dns_req["ip"])

    for http_req in report.get("network", {}).get("http_requests", []):
        if http_req.get("url"):
            iocs["urls"].add(http_req["url"])

    for conn in report.get("network", {}).get("connections", []):
        if conn.get("ip"):
            iocs["ips"].add(conn["ip"])

    for proc in report.get("processes", []):
        if proc.get("is_malicious"):
            iocs["processes"].append(proc["name"])

    iocs["mitre_techniques"] = report.get("mitre_techniques", [])
    iocs["domains"] = sorted(iocs["domains"])
    iocs["ips"] = sorted(iocs["ips"])
    iocs["urls"] = sorted(iocs["urls"])

    return iocs


def generate_report(submission: dict, report: dict, iocs: dict) -> str:
    """Generate dynamic analysis report."""
    lines = [
        "DYNAMIC ANALYSIS REPORT (ANY.RUN)",
        "=" * 50,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Task ID: {report.get('task_id', submission.get('task_id', 'N/A'))}",
        f"Task URL: {submission.get('task_url', 'N/A')}",
        "",
        f"Verdict: {report.get('verdict', 'N/A')}",
        f"Threat Level: {report.get('threat_level', 'N/A')}",
        f"Tags: {', '.join(report.get('tags', []))}",
        "",
        f"PROCESSES ({len(report.get('processes', []))}):",
    ]

    for proc in report.get("processes", [])[:10]:
        mal = " [MALICIOUS]" if proc.get("is_malicious") else ""
        lines.append(f"  PID {proc['pid']}: {proc['name']}{mal}")
        if proc.get("command_line"):
            lines.append(f"    CMD: {proc['command_line'][:100]}")

    lines.extend([
        "",
        "NETWORK IOCs:",
        f"  Domains: {len(iocs.get('domains', []))}",
        f"  IPs: {len(iocs.get('ips', []))}",
        f"  URLs: {len(iocs.get('urls', []))}",
    ])

    if iocs.get("mitre_techniques"):
        lines.extend(["", "MITRE ATT&CK TECHNIQUES:"])
        for tech in iocs["mitre_techniques"][:10]:
            lines.append(f"  {tech['technique_id']} - {tech['name']} ({tech['tactic']})")

    return "\n".join(lines)


def run_with_sdk(api_key: str, target: str, is_url: bool) -> dict:
    """Use official anyrun-sdk (SandboxConnector) if available."""
    with SandboxConnector.windows(api_key) as connector:
        if is_url:
            analysis_id = connector.run_url_analysis(target)
        else:
            analysis_id = connector.run_file_analysis(target)

        print(f"[*] SDK analysis ID: {analysis_id}")
        for status in connector.get_task_status(analysis_id):
            print(f"[*] Status: {status}")

        verdict = connector.get_analysis_verdict(analysis_id)
        report = connector.get_analysis_report(analysis_id)
        return {"analysis_id": analysis_id, "verdict": verdict, "report": report}


if __name__ == "__main__":
    api_key = os.getenv("ANYRUN_API_KEY", "")
    if not api_key:
        print("[!] Set ANYRUN_API_KEY environment variable")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_or_url> [--url]")
        sys.exit(1)

    target = sys.argv[1]
    is_url = "--url" in sys.argv or target.startswith("http")

    # Prefer official SDK when available, fall back to REST API
    if HAS_ANYRUN_SDK:
        print("[*] Using official anyrun-sdk (SandboxConnector)")
        sdk_result = run_with_sdk(api_key, target, is_url)
        print(json.dumps(sdk_result, indent=2, default=str))
        sys.exit(0)

    print("[*] anyrun-sdk not found, using REST API fallback")

    if is_url:
        print(f"[*] Submitting URL: {target}")
        submission = submit_url(target, api_key)
    else:
        print(f"[*] Submitting file: {target}")
        submission = submit_file(target, api_key)

    if "error" in submission:
        print(f"[!] {submission['error']}")
        sys.exit(1)

    task_id = submission["task_id"]
    print(f"[*] Task ID: {task_id}")

    print("[*] Waiting for analysis to complete...")
    completion = wait_for_completion(task_id, api_key)
    print(f"[*] Status: {completion['status']} ({completion.get('elapsed', 0)}s)")

    if completion["status"] == "completed":
        report = get_task_report(task_id, api_key)
        iocs = get_iocs_from_report(report)

        output_text = generate_report(submission, report, iocs)
        print(output_text)

        output = f"anyrun_analysis_{task_id}.json"
        with open(output, "w") as f:
            json.dump({"submission": submission, "report": report, "iocs": iocs}, f, indent=2)
        print(f"\n[*] Results saved to {output}")
    else:
        print(f"[!] Analysis did not complete: {completion['status']}")
