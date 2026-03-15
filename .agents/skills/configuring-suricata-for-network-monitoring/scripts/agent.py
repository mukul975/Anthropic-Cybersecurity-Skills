#!/usr/bin/env python3
"""Suricata IDS/IPS monitoring and EVE JSON log analysis agent."""

import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


SURICATA_BIN = "/usr/bin/suricata"
SURICATA_CONF = "/etc/suricata/suricata.yaml"
EVE_LOG = "/var/log/suricata/eve.json"
RULES_DIR = "/var/lib/suricata/rules"


def check_suricata_status():
    """Check Suricata installation and running status."""
    version = {"installed": False}
    try:
        result = subprocess.run(
            [SURICATA_BIN, "--build-info"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "Suricata version" in line.lower() or "version:" in line.lower():
                version = {"installed": True, "version": line.strip()}
                break
        if not version.get("version"):
            version = {"installed": True, "build_info": result.stdout[:300]}
    except FileNotFoundError:
        version = {"installed": False, "error": "Suricata not found"}

    running = False
    try:
        r = subprocess.run(["pgrep", "-x", "suricata"], capture_output=True, text=True)
        running = r.returncode == 0
    except FileNotFoundError:
        pass

    return {**version, "running": running}


def validate_config():
    """Validate Suricata configuration."""
    try:
        result = subprocess.run(
            [SURICATA_BIN, "-T", "-c", SURICATA_CONF, "-v"],
            capture_output=True, text=True, timeout=60
        )
        return {
            "valid": result.returncode == 0,
            "output": result.stderr.strip()[-500:] if result.stderr else result.stdout.strip()[-500:],
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def parse_eve_alerts(log_path=None, limit=10000):
    """Parse EVE JSON log for alert events and produce statistics."""
    log_path = log_path or EVE_LOG
    if not os.path.exists(log_path):
        return {"error": f"EVE log not found: {log_path}"}

    alerts = []
    signatures = Counter()
    src_ips = Counter()
    dest_ips = Counter()
    severities = Counter()

    with open(log_path, "r") as f:
        for i, line in enumerate(f):
            if i > limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert_info = event.get("alert", {})
            sig = alert_info.get("signature", "unknown")
            signatures[sig] += 1
            src_ips[event.get("src_ip", "unknown")] += 1
            dest_ips[event.get("dest_ip", "unknown")] += 1
            severities[alert_info.get("severity", 0)] += 1
            alerts.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "signature": sig,
                "sid": alert_info.get("signature_id"),
                "severity": alert_info.get("severity"),
            })

    return {
        "total_alerts": len(alerts),
        "top_signatures": signatures.most_common(15),
        "top_src_ips": src_ips.most_common(10),
        "top_dest_ips": dest_ips.most_common(10),
        "severity_distribution": dict(severities),
        "recent_alerts": alerts[-10:],
    }


def parse_eve_dns(log_path=None, limit=50000):
    """Analyze DNS queries from EVE log for threat hunting."""
    log_path = log_path or EVE_LOG
    if not os.path.exists(log_path):
        return {"error": f"EVE log not found: {log_path}"}

    domains = Counter()
    query_types = Counter()
    long_queries = []

    with open(log_path, "r") as f:
        for i, line in enumerate(f):
            if i > limit:
                break
            try:
                event = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if event.get("event_type") != "dns":
                continue
            dns = event.get("dns", {})
            rrname = dns.get("rrname", "")
            if rrname:
                domains[rrname] += 1
                query_types[dns.get("rrtype", "unknown")] += 1
                if len(rrname) > 60:
                    long_queries.append({
                        "src_ip": event.get("src_ip"),
                        "query": rrname,
                        "length": len(rrname),
                    })

    return {
        "unique_domains": len(domains),
        "top_domains": domains.most_common(20),
        "query_types": dict(query_types),
        "long_queries_suspicious": long_queries[:20],
    }


def parse_eve_tls(log_path=None, limit=50000):
    """Extract JA3 fingerprints and TLS metadata from EVE log."""
    log_path = log_path or EVE_LOG
    if not os.path.exists(log_path):
        return {"error": f"EVE log not found: {log_path}"}

    ja3_hashes = Counter()
    sni_list = Counter()

    with open(log_path, "r") as f:
        for i, line in enumerate(f):
            if i > limit:
                break
            try:
                event = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if event.get("event_type") != "tls":
                continue
            tls = event.get("tls", {})
            ja3 = tls.get("ja3", {})
            if isinstance(ja3, dict):
                h = ja3.get("hash")
            else:
                h = None
            if h:
                ja3_hashes[h] += 1
            sni = tls.get("sni", "")
            if sni:
                sni_list[sni] += 1

    return {
        "unique_ja3": len(ja3_hashes),
        "top_ja3_hashes": ja3_hashes.most_common(20),
        "top_sni": sni_list.most_common(20),
    }


def update_rules():
    """Run suricata-update to fetch latest rulesets."""
    try:
        result = subprocess.run(
            ["suricata-update"], capture_output=True, text=True, timeout=120
        )
        return {"success": result.returncode == 0, "output": result.stdout.strip()[-500:]}
    except FileNotFoundError:
        return {"success": False, "error": "suricata-update not found"}


def count_rules():
    """Count active Suricata rules."""
    rules_file = os.path.join(RULES_DIR, "suricata.rules")
    if not os.path.exists(rules_file):
        return {"error": "Rules file not found"}
    active = 0
    with open(rules_file) as f:
        for line in f:
            if line.strip() and not line.strip().startswith("#"):
                active += 1
    return {"active_rules": active, "rules_file": rules_file}


def generate_report():
    """Generate full Suricata deployment report."""
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": check_suricata_status(),
        "config": validate_config(),
        "rules": count_rules(),
        "alerts": parse_eve_alerts(),
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "report"
    actions = {
        "report": generate_report,
        "status": check_suricata_status,
        "validate": validate_config,
        "alerts": parse_eve_alerts,
        "dns": parse_eve_dns,
        "tls": parse_eve_tls,
        "update-rules": update_rules,
        "rules": count_rules,
    }
    fn = actions.get(action)
    if fn:
        print(json.dumps(fn(), indent=2, default=str))
    else:
        print(f"Usage: agent.py [{' | '.join(actions.keys())}]")
