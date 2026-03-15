#!/usr/bin/env python3
"""
Microsegmentation Policy Analyzer and Flow Validator

Analyzes network flow data to identify microsegmentation opportunities,
validates policies against observed traffic, and generates segmentation reports.
"""

import json
import csv
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional


def parse_flow_data(flow_file: str) -> list:
    """Parse network flow data from CSV or JSON format."""
    flows = []
    path = Path(flow_file)
    if path.suffix == ".csv":
        with open(flow_file) as f:
            reader = csv.DictReader(f)
            for row in reader:
                flows.append({
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "src_port": int(row.get("src_port", 0)),
                    "dst_port": int(row.get("dst_port", 0)),
                    "protocol": row.get("protocol", "tcp").lower(),
                    "bytes": int(row.get("bytes", 0)),
                    "packets": int(row.get("packets", 0)),
                    "timestamp": row.get("timestamp", ""),
                    "src_label": row.get("src_label", ""),
                    "dst_label": row.get("dst_label", ""),
                })
    elif path.suffix == ".json":
        with open(flow_file) as f:
            flows = json.load(f)
    return flows


def build_dependency_map(flows: list) -> dict:
    """Build an application dependency map from flow data."""
    dep_map = defaultdict(lambda: defaultdict(lambda: {
        "ports": set(), "protocols": set(), "total_bytes": 0,
        "total_packets": 0, "flow_count": 0
    }))

    for flow in flows:
        src = flow.get("src_label") or flow["src_ip"]
        dst = flow.get("dst_label") or flow["dst_ip"]
        port = flow["dst_port"]
        proto = flow["protocol"]

        dep_map[src][dst]["ports"].add(port)
        dep_map[src][dst]["protocols"].add(proto)
        dep_map[src][dst]["total_bytes"] += flow.get("bytes", 0)
        dep_map[src][dst]["total_packets"] += flow.get("packets", 0)
        dep_map[src][dst]["flow_count"] += 1

    serializable = {}
    for src, destinations in dep_map.items():
        serializable[src] = {}
        for dst, stats in destinations.items():
            serializable[src][dst] = {
                "ports": sorted(list(stats["ports"])),
                "protocols": sorted(list(stats["protocols"])),
                "total_bytes": stats["total_bytes"],
                "total_packets": stats["total_packets"],
                "flow_count": stats["flow_count"],
            }
    return serializable


def generate_segmentation_rules(dep_map: dict, default_action: str = "deny") -> list:
    """Generate microsegmentation rules from dependency map."""
    rules = []
    rule_id = 1

    for src, destinations in dep_map.items():
        for dst, stats in destinations.items():
            for port in stats["ports"]:
                for proto in stats["protocols"]:
                    rules.append({
                        "id": rule_id,
                        "action": "allow",
                        "src": src,
                        "dst": dst,
                        "port": port,
                        "protocol": proto,
                        "justification": f"Observed {stats['flow_count']} flows, {stats['total_bytes']} bytes",
                        "status": "proposed",
                    })
                    rule_id += 1

    rules.append({
        "id": rule_id,
        "action": default_action,
        "src": "any",
        "dst": "any",
        "port": "any",
        "protocol": "any",
        "justification": "Default deny - zero trust baseline",
        "status": "proposed",
    })
    return rules


def validate_policy_against_flows(policy_rules: list, flows: list) -> dict:
    """Validate segmentation policy against observed flows. Identify blocks and gaps."""
    results = {
        "allowed_flows": 0,
        "blocked_flows": 0,
        "unmatched_flows": 0,
        "blocked_details": [],
        "unmatched_details": [],
    }

    allow_rules = [r for r in policy_rules if r["action"] == "allow"]
    has_default_deny = any(
        r["action"] == "deny" and r.get("src") == "any" and r.get("dst") == "any"
        for r in policy_rules
    )

    for flow in flows:
        src = flow.get("src_label") or flow["src_ip"]
        dst = flow.get("dst_label") or flow["dst_ip"]
        port = flow["dst_port"]
        proto = flow["protocol"]

        matched = False
        for rule in allow_rules:
            src_match = rule["src"] in (src, "any")
            dst_match = rule["dst"] in (dst, "any")
            port_match = rule["port"] in (port, "any")
            proto_match = rule["protocol"] in (proto, "any")

            if src_match and dst_match and port_match and proto_match:
                results["allowed_flows"] += 1
                matched = True
                break

        if not matched:
            if has_default_deny:
                results["blocked_flows"] += 1
                results["blocked_details"].append({
                    "src": src, "dst": dst, "port": port, "protocol": proto,
                    "timestamp": flow.get("timestamp", ""),
                })
            else:
                results["unmatched_flows"] += 1
                results["unmatched_details"].append({
                    "src": src, "dst": dst, "port": port, "protocol": proto,
                })

    return results


def identify_segmentation_zones(flows: list, workload_labels: dict) -> dict:
    """Identify natural segmentation zones from flow patterns and labels."""
    zones = defaultdict(lambda: {"workloads": set(), "internal_flows": 0, "external_flows": 0})

    for flow in flows:
        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]

        src_zone = workload_labels.get(src_ip, {}).get("application", "unknown")
        dst_zone = workload_labels.get(dst_ip, {}).get("application", "unknown")

        zones[src_zone]["workloads"].add(src_ip)
        zones[dst_zone]["workloads"].add(dst_ip)

        if src_zone == dst_zone:
            zones[src_zone]["internal_flows"] += 1
        else:
            zones[src_zone]["external_flows"] += 1
            zones[dst_zone]["external_flows"] += 1

    serializable = {}
    for zone_name, stats in zones.items():
        serializable[zone_name] = {
            "workloads": sorted(list(stats["workloads"])),
            "workload_count": len(stats["workloads"]),
            "internal_flows": stats["internal_flows"],
            "external_flows": stats["external_flows"],
            "isolation_ratio": round(
                stats["internal_flows"] / max(stats["internal_flows"] + stats["external_flows"], 1),
                2
            ),
        }
    return serializable


def detect_anomalous_flows(flows: list, policy_rules: list) -> list:
    """Detect flows that violate segmentation policy and may indicate lateral movement."""
    anomalies = []
    allow_set = set()

    for rule in policy_rules:
        if rule["action"] == "allow":
            allow_set.add((rule["src"], rule["dst"], rule["port"], rule["protocol"]))

    for flow in flows:
        src = flow.get("src_label") or flow["src_ip"]
        dst = flow.get("dst_label") or flow["dst_ip"]
        port = flow["dst_port"]
        proto = flow["protocol"]

        is_allowed = (
            (src, dst, port, proto) in allow_set
            or ("any", dst, port, proto) in allow_set
            or (src, "any", port, proto) in allow_set
            or (src, dst, "any", proto) in allow_set
        )

        if not is_allowed:
            anomalies.append({
                "src": src,
                "dst": dst,
                "port": port,
                "protocol": proto,
                "bytes": flow.get("bytes", 0),
                "timestamp": flow.get("timestamp", ""),
                "severity": "high" if port in [22, 3389, 445, 135] else "medium",
                "reason": "Flow not covered by any allow rule",
            })

    return sorted(anomalies, key=lambda x: x["severity"])


def generate_segmentation_report(flows: list, policy_rules: list, workload_labels: dict) -> dict:
    """Generate comprehensive microsegmentation report."""
    dep_map = build_dependency_map(flows)
    zones = identify_segmentation_zones(flows, workload_labels)
    validation = validate_policy_against_flows(policy_rules, flows)
    anomalies = detect_anomalous_flows(flows, policy_rules)

    unique_sources = set(f.get("src_label") or f["src_ip"] for f in flows)
    unique_dests = set(f.get("dst_label") or f["dst_ip"] for f in flows)
    unique_ports = set(f["dst_port"] for f in flows)

    return {
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_flows": len(flows),
            "unique_sources": len(unique_sources),
            "unique_destinations": len(unique_dests),
            "unique_ports": len(unique_ports),
            "segmentation_zones": len(zones),
            "policy_rules": len(policy_rules),
            "allowed_flows": validation["allowed_flows"],
            "blocked_flows": validation["blocked_flows"],
            "anomalies_detected": len(anomalies),
        },
        "zones": zones,
        "validation": validation,
        "anomalies": anomalies[:50],
        "dependency_map_summary": {
            src: len(dsts) for src, dsts in dep_map.items()
        },
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Microsegmentation Policy Analyzer")
    parser.add_argument("--flows", type=str, help="Path to flow data (CSV or JSON)")
    parser.add_argument("--policy", type=str, help="Path to policy rules JSON")
    parser.add_argument("--labels", type=str, help="Path to workload labels JSON")
    parser.add_argument("--action", choices=["map", "rules", "validate", "report", "anomalies"],
                        default="report", help="Action to perform")
    parser.add_argument("--output", type=str, default="segmentation_report.json", help="Output file")
    args = parser.parse_args()

    if not args.flows:
        parser.print_help()
        return

    flows = parse_flow_data(args.flows)
    print(f"Loaded {len(flows)} flows")

    policy_rules = []
    if args.policy:
        with open(args.policy) as f:
            policy_rules = json.load(f)

    workload_labels = {}
    if args.labels:
        with open(args.labels) as f:
            workload_labels = json.load(f)

    if args.action == "map":
        dep_map = build_dependency_map(flows)
        with open(args.output, "w") as f:
            json.dump(dep_map, f, indent=2)
        print(f"Dependency map: {len(dep_map)} sources mapped")

    elif args.action == "rules":
        dep_map = build_dependency_map(flows)
        rules = generate_segmentation_rules(dep_map)
        with open(args.output, "w") as f:
            json.dump(rules, f, indent=2)
        print(f"Generated {len(rules)} proposed rules")

    elif args.action == "validate":
        if not policy_rules:
            print("Error: --policy required for validation")
            return
        results = validate_policy_against_flows(policy_rules, flows)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Allowed: {results['allowed_flows']}, Blocked: {results['blocked_flows']}")

    elif args.action == "anomalies":
        if not policy_rules:
            print("Error: --policy required for anomaly detection")
            return
        anomalies = detect_anomalous_flows(flows, policy_rules)
        with open(args.output, "w") as f:
            json.dump(anomalies, f, indent=2)
        print(f"Detected {len(anomalies)} anomalous flows")

    elif args.action == "report":
        report = generate_segmentation_report(flows, policy_rules, workload_labels)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Report generated: {args.output}")
        print(f"  Zones: {report['summary']['segmentation_zones']}")
        print(f"  Anomalies: {report['summary']['anomalies_detected']}")

    print(f"Output saved to {args.output}")


if __name__ == "__main__":
    main()
