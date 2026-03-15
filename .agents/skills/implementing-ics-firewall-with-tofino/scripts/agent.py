#!/usr/bin/env python3
"""Agent for auditing and configuring Tofino ICS firewall rules."""

import json
import argparse
import re
from datetime import datetime
from collections import Counter, defaultdict


OT_PROTOCOLS = {
    "modbus": {"port": 502, "layer": "TCP", "dpi": True},
    "enip": {"port": 44818, "layer": "TCP/UDP", "dpi": True},
    "dnp3": {"port": 20000, "layer": "TCP", "dpi": True},
    "opc_ua": {"port": 4840, "layer": "TCP", "dpi": True},
    "s7comm": {"port": 102, "layer": "TCP", "dpi": True},
    "bacnet": {"port": 47808, "layer": "UDP", "dpi": True},
    "iec61850_mms": {"port": 102, "layer": "TCP", "dpi": True},
    "profinet": {"port": 34964, "layer": "UDP", "dpi": False},
}

RISKY_MODBUS_FUNCTIONS = {
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
}


def audit_firewall_rules(rules_path):
    """Audit Tofino firewall rules for security issues."""
    with open(rules_path) as f:
        rules = json.load(f)
    rule_list = rules if isinstance(rules, list) else rules.get("rules", [])
    findings = []

    for rule in rule_list:
        action = rule.get("action", "").lower()
        src = rule.get("source", rule.get("src", "any"))
        dst = rule.get("destination", rule.get("dst", "any"))
        protocol = rule.get("protocol", "").lower()
        port = rule.get("port", rule.get("dst_port", "any"))

        if src == "any" and dst == "any" and action == "allow":
            findings.append({
                "rule": rule.get("id", rule.get("name", "")),
                "issue": "Allow-any-any rule detected",
                "severity": "CRITICAL",
                "recommendation": "Restrict to specific source/destination",
            })

        if protocol in ("modbus", "enip", "s7comm") and not rule.get("dpi_enabled", False):
            findings.append({
                "rule": rule.get("id", ""),
                "issue": f"DPI not enabled for {protocol}",
                "severity": "HIGH",
                "recommendation": f"Enable deep packet inspection for {protocol}",
            })

        if protocol == "modbus":
            allowed_funcs = rule.get("allowed_functions", [])
            risky = [f for f in allowed_funcs if f in RISKY_MODBUS_FUNCTIONS]
            if risky:
                findings.append({
                    "rule": rule.get("id", ""),
                    "issue": f"Write functions allowed: {risky}",
                    "severity": "HIGH",
                    "detail": {fc: RISKY_MODBUS_FUNCTIONS[fc] for fc in risky},
                })

        if action == "allow" and not rule.get("logging", False):
            findings.append({
                "rule": rule.get("id", ""),
                "issue": "Allow rule without logging",
                "severity": "MEDIUM",
            })

    has_deny_all = any(r.get("action", "").lower() == "deny" and
                       r.get("source", "any") == "any" and
                       r.get("destination", "any") == "any" for r in rule_list)
    if not has_deny_all:
        findings.append({
            "issue": "No default deny-all rule found",
            "severity": "CRITICAL",
            "recommendation": "Add deny-all as last rule",
        })

    return findings


def analyze_ot_traffic_log(log_path):
    """Analyze OT network traffic log for anomalies."""
    with open(log_path) as f:
        entries = json.load(f)
    items = entries if isinstance(entries, list) else entries.get("flows", [])

    by_protocol = Counter()
    by_src = Counter()
    anomalies = []

    for entry in items:
        proto = entry.get("protocol", entry.get("app_protocol", "unknown")).lower()
        by_protocol[proto] += 1
        by_src[entry.get("src_ip", "unknown")] += 1

        port = entry.get("dst_port", 0)
        if proto == "modbus" and port != 502:
            anomalies.append({"type": "non_standard_port", "protocol": proto,
                              "port": port, "severity": "HIGH"})

        if entry.get("action", "").lower() == "denied":
            anomalies.append({
                "type": "denied_connection",
                "src": entry.get("src_ip", ""),
                "dst": entry.get("dst_ip", ""),
                "protocol": proto,
                "severity": "MEDIUM",
            })

    return {
        "total_flows": len(items),
        "by_protocol": dict(by_protocol),
        "unique_sources": len(by_src),
        "anomalies": anomalies[:50],
        "anomaly_count": len(anomalies),
    }


def generate_zone_rules(zone_config):
    """Generate Tofino firewall rules from zone configuration."""
    rules = []
    zones = zone_config.get("zones", [])
    for zone in zones:
        zone_name = zone.get("name", "")
        allowed_protocols = zone.get("allowed_protocols", [])
        plc_ips = zone.get("plc_ips", [])
        hmi_ips = zone.get("hmi_ips", [])
        eng_ips = zone.get("engineering_ips", [])

        for proto in allowed_protocols:
            proto_info = OT_PROTOCOLS.get(proto, {})
            port = proto_info.get("port", "any")
            for hmi in hmi_ips:
                for plc in plc_ips:
                    rules.append({
                        "zone": zone_name,
                        "action": "allow",
                        "source": hmi,
                        "destination": plc,
                        "protocol": proto,
                        "port": port,
                        "dpi_enabled": proto_info.get("dpi", False),
                        "logging": True,
                    })
            if proto == "modbus":
                for eng in eng_ips:
                    for plc in plc_ips:
                        rules.append({
                            "zone": zone_name,
                            "action": "allow",
                            "source": eng,
                            "destination": plc,
                            "protocol": "modbus",
                            "port": 502,
                            "dpi_enabled": True,
                            "allowed_functions": [1, 2, 3, 4],
                            "logging": True,
                            "comment": "Read-only Modbus for engineering",
                        })

    rules.append({"action": "deny", "source": "any", "destination": "any",
                  "protocol": "any", "logging": True, "comment": "Default deny-all"})
    return rules


def main():
    parser = argparse.ArgumentParser(description="Tofino ICS Firewall Agent")
    parser.add_argument("--rules", help="Firewall rules JSON to audit")
    parser.add_argument("--traffic-log", help="OT traffic log JSON")
    parser.add_argument("--zone-config", help="Zone config JSON for rule generation")
    parser.add_argument("--action", choices=["audit", "traffic", "generate", "full"],
                        default="full")
    parser.add_argument("--output", default="tofino_ics_firewall_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.rules:
        findings = audit_firewall_rules(args.rules)
        report["results"]["audit"] = findings
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        print(f"[+] Audit: {len(findings)} findings, {critical} critical")

    if args.action in ("traffic", "full") and args.traffic_log:
        result = analyze_ot_traffic_log(args.traffic_log)
        report["results"]["traffic"] = result
        print(f"[+] Traffic: {result['total_flows']} flows, {result['anomaly_count']} anomalies")

    if args.action in ("generate", "full") and args.zone_config:
        with open(args.zone_config) as f:
            zc = json.load(f)
        rules = generate_zone_rules(zc)
        report["results"]["generated_rules"] = rules
        print(f"[+] Generated {len(rules)} firewall rules")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
