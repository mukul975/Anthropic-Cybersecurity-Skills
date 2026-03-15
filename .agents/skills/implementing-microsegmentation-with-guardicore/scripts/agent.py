#!/usr/bin/env python3
"""Guardicore Microsegmentation Agent - audits segmentation policies and network flow visibility."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

GC_API = "https://gc-centra.example.com/api/v3.0"


def gc_request(api_url, token, endpoint, method="GET", data=None):
    cmd = ["curl", "-s", "-k", "-X", method,
           "-H", f"Authorization: Bearer {token}",
           "-H", "Content-Type: application/json",
           f"{api_url}{endpoint}"]
    if data:
        cmd.extend(["-d", json.dumps(data)])
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def authenticate(api_url, username, password):
    """Authenticate to Guardicore Centra and get access token."""
    data = {"username": username, "password": password}
    result = gc_request(api_url, "", "/authenticate", "POST", data)
    return result.get("access_token", "")


def get_segmentation_policies(api_url, token):
    """Retrieve all segmentation policies."""
    return gc_request(api_url, token, "/policies")


def get_network_flows(api_url, token, hours_back=24):
    """Get recent network flow data for analysis."""
    params = f"?time_range={hours_back}h&limit=1000"
    return gc_request(api_url, token, f"/connections{params}")


def get_labels(api_url, token):
    """Get all asset labels/tags."""
    return gc_request(api_url, token, "/labels")


def get_agents(api_url, token):
    """Get deployed agent status."""
    return gc_request(api_url, token, "/agents")


def analyze_policy_coverage(policies, flows):
    """Analyze how well policies cover observed traffic."""
    policy_rules = set()
    for policy in policies:
        for rule in policy.get("rules", []):
            src = rule.get("source", {}).get("label", "any")
            dst = rule.get("destination", {}).get("label", "any")
            port = rule.get("port", "any")
            policy_rules.add((src, dst, str(port)))
    covered = 0
    uncovered_flows = []
    for flow in flows:
        src_label = flow.get("source_label", "unknown")
        dst_label = flow.get("destination_label", "unknown")
        port = str(flow.get("destination_port", ""))
        if (src_label, dst_label, port) in policy_rules or ("any", "any", "any") in policy_rules:
            covered += 1
        else:
            uncovered_flows.append({
                "source": flow.get("source_ip", ""),
                "destination": flow.get("destination_ip", ""),
                "port": port,
                "protocol": flow.get("protocol", ""),
                "bytes": flow.get("bytes_total", 0),
            })
    total = len(flows)
    return {
        "total_flows": total,
        "covered_by_policy": covered,
        "uncovered": len(uncovered_flows),
        "coverage_percent": round(covered / max(total, 1) * 100, 1),
        "top_uncovered_flows": sorted(uncovered_flows, key=lambda x: x["bytes"], reverse=True)[:20],
    }


def detect_lateral_movement_risk(flows):
    """Identify potential lateral movement patterns in east-west traffic."""
    source_targets = defaultdict(set)
    for flow in flows:
        src = flow.get("source_ip", "")
        dst = flow.get("destination_ip", "")
        if src and dst and src != dst:
            source_targets[src].add(dst)
    risks = []
    for src, targets in source_targets.items():
        if len(targets) > 10:
            risks.append({"source_ip": src, "unique_targets": len(targets), "risk": "high"})
    return sorted(risks, key=lambda x: x["unique_targets"], reverse=True)


def audit_agent_health(agents):
    """Audit deployment agent health status."""
    healthy = sum(1 for a in agents if a.get("status") == "online")
    offline = sum(1 for a in agents if a.get("status") == "offline")
    return {"total": len(agents), "online": healthy, "offline": offline,
            "health_percent": round(healthy / max(len(agents), 1) * 100, 1)}


def generate_report(policies, flows, agents, api_url):
    coverage = analyze_policy_coverage(policies, flows)
    lateral = detect_lateral_movement_risk(flows)
    health = audit_agent_health(agents)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "guardicore_url": api_url,
        "total_policies": len(policies),
        "policy_coverage": coverage,
        "lateral_movement_risks": lateral[:10],
        "agent_health": health,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Guardicore Microsegmentation Audit Agent")
    parser.add_argument("--api-url", default=GC_API, help="Guardicore Centra API URL")
    parser.add_argument("--username", required=True, help="API username")
    parser.add_argument("--password", required=True, help="API password")
    parser.add_argument("--hours-back", type=int, default=24, help="Flow analysis window (hours)")
    parser.add_argument("--output", default="microseg_report.json")
    args = parser.parse_args()

    token = authenticate(args.api_url, args.username, args.password)
    policies = get_segmentation_policies(args.api_url, token)
    flows = get_network_flows(args.api_url, token, args.hours_back)
    agents = get_agents(args.api_url, token)
    report = generate_report(policies, flows, agents, args.api_url)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Coverage: %.1f%%, Agent health: %.1f%%",
                report["policy_coverage"]["coverage_percent"], report["agent_health"]["health_percent"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
