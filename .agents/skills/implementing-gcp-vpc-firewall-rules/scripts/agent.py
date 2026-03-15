#!/usr/bin/env python3
"""GCP VPC firewall rules audit and management agent."""

import json
import sys
import argparse
from datetime import datetime

try:
    from google.cloud import compute_v1
    from google.api_core.exceptions import GoogleAPIError
except ImportError:
    print("Install: pip install google-cloud-compute")
    sys.exit(1)


def get_firewall_client():
    """Create GCP Compute Engine firewall client."""
    return compute_v1.FirewallsClient()


def list_firewall_rules(project_id):
    """List all VPC firewall rules in a project."""
    client = get_firewall_client()
    rules = []
    for rule in client.list(project=project_id):
        rules.append({
            "name": rule.name,
            "network": rule.network.split("/")[-1] if rule.network else "",
            "direction": rule.direction,
            "priority": rule.priority,
            "action": "ALLOW" if rule.allowed else "DENY",
            "source_ranges": list(rule.source_ranges) if rule.source_ranges else [],
            "destination_ranges": list(rule.destination_ranges) if rule.destination_ranges else [],
            "target_tags": list(rule.target_tags) if rule.target_tags else [],
            "allowed": [{"protocol": a.I_p_protocol,
                         "ports": list(a.ports) if a.ports else ["all"]}
                        for a in rule.allowed] if rule.allowed else [],
            "denied": [{"protocol": d.I_p_protocol,
                        "ports": list(d.ports) if d.ports else ["all"]}
                       for d in rule.denied] if rule.denied else [],
            "disabled": rule.disabled,
            "log_config_enabled": rule.log_config.enable if rule.log_config else False,
        })
    return sorted(rules, key=lambda r: r["priority"])


def find_overly_permissive_rules(project_id):
    """Identify firewall rules that are overly permissive (0.0.0.0/0)."""
    rules = list_firewall_rules(project_id)
    findings = []
    for rule in rules:
        if rule["disabled"]:
            continue
        if "0.0.0.0/0" in rule.get("source_ranges", []):
            for allowed in rule.get("allowed", []):
                ports = allowed.get("ports", ["all"])
                severity = "CRITICAL" if "all" in ports or "22" in ports or "3389" in ports \
                    else "HIGH" if "80" in ports or "443" in ports else "MEDIUM"
                findings.append({
                    "rule_name": rule["name"],
                    "network": rule["network"],
                    "severity": severity,
                    "protocol": allowed["protocol"],
                    "ports": ports,
                    "issue": "Source range 0.0.0.0/0 allows traffic from any IP",
                    "recommendation": "Restrict source ranges to specific CIDR blocks",
                })
    return findings


def audit_default_rules(project_id):
    """Audit default network firewall rules for security issues."""
    rules = list_firewall_rules(project_id)
    default_issues = []
    for rule in rules:
        if "default" in rule["name"].lower():
            if "0.0.0.0/0" in rule.get("source_ranges", []) and not rule["disabled"]:
                default_issues.append({
                    "rule": rule["name"],
                    "issue": "Default rule allows traffic from all sources",
                    "action": "Disable or restrict default permissive rules",
                })
    return default_issues


def create_firewall_rule(project_id, name, network, direction, priority,
                         allowed_protocols, source_ranges, target_tags=None):
    """Create a new VPC firewall rule."""
    client = get_firewall_client()
    allowed = []
    for proto, ports in allowed_protocols.items():
        entry = compute_v1.Allowed()
        entry.I_p_protocol = proto
        if ports:
            entry.ports = ports
        allowed.append(entry)
    rule = compute_v1.Firewall()
    rule.name = name
    rule.network = f"projects/{project_id}/global/networks/{network}"
    rule.direction = direction
    rule.priority = priority
    rule.allowed = allowed
    rule.source_ranges = source_ranges
    if target_tags:
        rule.target_tags = target_tags
    rule.log_config = compute_v1.FirewallLogConfig(enable=True)
    try:
        operation = client.insert(project=project_id, firewall_resource=rule)
        return {"name": name, "status": "creating", "operation": operation.name}
    except GoogleAPIError as e:
        return {"name": name, "status": "error", "message": str(e)}


def delete_firewall_rule(project_id, rule_name):
    """Delete a firewall rule by name."""
    client = get_firewall_client()
    try:
        operation = client.delete(project=project_id, firewall=rule_name)
        return {"name": rule_name, "status": "deleting", "operation": operation.name}
    except GoogleAPIError as e:
        return {"name": rule_name, "status": "error", "message": str(e)}


def check_logging_status(project_id):
    """Check which firewall rules have logging enabled."""
    rules = list_firewall_rules(project_id)
    unlogged = [r for r in rules if not r["log_config_enabled"] and not r["disabled"]]
    logged = [r for r in rules if r["log_config_enabled"]]
    return {"logged": len(logged), "unlogged": len(unlogged),
            "unlogged_rules": [r["name"] for r in unlogged]}


def run_firewall_audit(project_id):
    """Run a comprehensive firewall audit."""
    print(f"\n{'='*60}")
    print(f"  GCP VPC FIREWALL AUDIT")
    print(f"  Project: {project_id}")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    rules = list_firewall_rules(project_id)
    print(f"--- ALL RULES ({len(rules)}) ---")
    for r in rules:
        status = "DISABLED" if r["disabled"] else "ACTIVE"
        print(f"  [{r['priority']:5d}] {r['name']} ({status}) -> {r['network']}")

    findings = find_overly_permissive_rules(project_id)
    print(f"\n--- OVERLY PERMISSIVE RULES ({len(findings)}) ---")
    for f in findings:
        print(f"  [{f['severity']}] {f['rule_name']}: {f['protocol']} ports {f['ports']}")
        print(f"    {f['recommendation']}")

    default_issues = audit_default_rules(project_id)
    print(f"\n--- DEFAULT RULE ISSUES ({len(default_issues)}) ---")
    for d in default_issues:
        print(f"  {d['rule']}: {d['issue']}")

    logging = check_logging_status(project_id)
    print(f"\n--- LOGGING STATUS ---")
    print(f"  Rules with logging:    {logging['logged']}")
    print(f"  Rules without logging: {logging['unlogged']}")

    print(f"\n{'='*60}\n")
    return {"total_rules": len(rules), "permissive_findings": len(findings),
            "logging": logging}


def main():
    parser = argparse.ArgumentParser(description="GCP VPC Firewall Rules Agent")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--audit", action="store_true", help="Run firewall audit")
    parser.add_argument("--list", action="store_true", help="List all rules")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    if args.audit:
        report = run_firewall_audit(args.project)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.list:
        rules = list_firewall_rules(args.project)
        print(json.dumps(rules, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
