#!/usr/bin/env python3
"""Snort IDS configuration and rule management agent."""

import subprocess
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


SNORT_BIN = "/usr/local/bin/snort"
SNORT_CONF = "/usr/local/etc/snort/snort.lua"
RULES_DIR = "/usr/local/etc/snort/rules"
LOG_DIR = "/var/log/snort"


def check_snort_installed():
    """Verify Snort 3 installation and return version info."""
    try:
        result = subprocess.run(
            [SNORT_BIN, "-V"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines() + result.stderr.splitlines():
            if "Snort++" in line or "Version" in line:
                return {"installed": True, "version": line.strip()}
        return {"installed": True, "output": result.stdout.strip()}
    except FileNotFoundError:
        return {"installed": False, "error": "Snort binary not found at " + SNORT_BIN}
    except subprocess.TimeoutExpired:
        return {"installed": False, "error": "Snort version check timed out"}


def validate_configuration(config_path=SNORT_CONF):
    """Validate Snort configuration file syntax."""
    try:
        result = subprocess.run(
            [SNORT_BIN, "-c", config_path, "--daq-dir", "/usr/local/lib/daq", "-T"],
            capture_output=True, text=True, timeout=60
        )
        success = result.returncode == 0
        rules_loaded = None
        for line in result.stdout.splitlines() + result.stderr.splitlines():
            match = re.search(r"(\d+)\s+rules loaded", line, re.IGNORECASE)
            if match:
                rules_loaded = int(match.group(1))
        return {
            "valid": success,
            "rules_loaded": rules_loaded,
            "output": result.stderr.strip() if result.stderr else result.stdout.strip(),
        }
    except FileNotFoundError:
        return {"valid": False, "error": "Snort binary not found"}
    except subprocess.TimeoutExpired:
        return {"valid": False, "error": "Validation timed out after 60s"}


def parse_alert_fast(log_path=None):
    """Parse Snort alert_fast.txt and return alert statistics."""
    log_path = log_path or os.path.join(LOG_DIR, "alert_fast.txt")
    if not os.path.exists(log_path):
        return {"error": f"Alert log not found: {log_path}"}

    alerts = []
    sid_counts = {}
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            sid_match = re.search(r"\[(\d+):(\d+):(\d+)\]", line)
            msg_match = re.search(r'\] (.+?) \[', line)
            if sid_match:
                gid, sid, rev = sid_match.groups()
                key = f"{gid}:{sid}"
                sid_counts[key] = sid_counts.get(key, 0) + 1
                alerts.append({
                    "gid": gid, "sid": sid, "rev": rev,
                    "message": msg_match.group(1) if msg_match else "",
                    "raw": line[:200],
                })

    top_rules = sorted(sid_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    return {
        "total_alerts": len(alerts),
        "unique_sids": len(sid_counts),
        "top_rules": [{"sid": s, "count": c} for s, c in top_rules],
        "recent_alerts": alerts[-10:],
    }


def parse_alert_json(log_path=None):
    """Parse Snort alert_json.txt for structured alert analysis."""
    log_path = log_path or os.path.join(LOG_DIR, "alert_json.txt")
    if not os.path.exists(log_path):
        return {"error": f"JSON alert log not found: {log_path}"}

    alerts = []
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
                alerts.append(alert)
            except json.JSONDecodeError:
                continue

    src_ips = {}
    dst_ips = {}
    for a in alerts:
        src = a.get("src_addr", "unknown")
        dst = a.get("dst_addr", "unknown")
        src_ips[src] = src_ips.get(src, 0) + 1
        dst_ips[dst] = dst_ips.get(dst, 0) + 1

    return {
        "total_alerts": len(alerts),
        "top_source_ips": sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10],
        "top_dest_ips": sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10],
        "recent_alerts": alerts[-5:],
    }


def test_rule_against_pcap(pcap_path, rule_file=None):
    """Test Snort rules against a PCAP file for validation."""
    if not os.path.exists(pcap_path):
        return {"error": f"PCAP file not found: {pcap_path}"}

    output_dir = os.path.join(LOG_DIR, "test_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        SNORT_BIN, "-c", SNORT_CONF,
        "--daq-dir", "/usr/local/lib/daq",
        "-r", pcap_path, "-l", output_dir, "-A", "fast",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        alert_file = os.path.join(output_dir, "alert_fast.txt")
        alert_count = 0
        if os.path.exists(alert_file):
            with open(alert_file) as f:
                alert_count = sum(1 for line in f if line.strip())
        return {
            "pcap": pcap_path,
            "alerts_generated": alert_count,
            "output_dir": output_dir,
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "PCAP analysis timed out after 120s"}


def count_rules(rules_path=None):
    """Count active rules in rule files."""
    rules_path = rules_path or RULES_DIR
    total = 0
    files = {}
    for f in Path(rules_path).glob("*.rules"):
        count = 0
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    count += 1
        files[f.name] = count
        total += count
    return {"total_rules": total, "rule_files": files}


def generate_report():
    """Generate a Snort IDS deployment status report."""
    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "snort": check_snort_installed(),
        "config_valid": validate_configuration(),
        "rule_counts": count_rules(),
        "alert_stats": parse_alert_fast(),
    }
    return report


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    if action == "report":
        print(json.dumps(generate_report(), indent=2))
    elif action == "validate":
        print(json.dumps(validate_configuration(), indent=2))
    elif action == "alerts":
        print(json.dumps(parse_alert_fast(), indent=2))
    elif action == "alerts-json":
        print(json.dumps(parse_alert_json(), indent=2))
    elif action == "rules":
        print(json.dumps(count_rules(), indent=2))
    elif action == "test-pcap" and len(sys.argv) > 2:
        print(json.dumps(test_rule_against_pcap(sys.argv[2]), indent=2))
    else:
        print("Usage: agent.py [report|validate|alerts|alerts-json|rules|test-pcap <file>]")
