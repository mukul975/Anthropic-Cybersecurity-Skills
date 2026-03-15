#!/usr/bin/env python3
"""pfSense Firewall Configuration Agent - Manages firewall rules via pfSense API."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PfSenseAPI:
    """Client for pfSense REST API (pfsense-api package)."""

    def __init__(self, base_url, api_key, api_secret):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"{api_key} {api_secret}",
            "Content-Type": "application/json",
        })
        self.session.verify = False

    def get(self, endpoint):
        resp = self.session.get(f"{self.base_url}/api/v1/{endpoint}")
        resp.raise_for_status()
        return resp.json()

    def post(self, endpoint, data):
        resp = self.session.post(f"{self.base_url}/api/v1/{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()

    def put(self, endpoint, data):
        resp = self.session.put(f"{self.base_url}/api/v1/{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()

    def delete(self, endpoint, data=None):
        resp = self.session.delete(f"{self.base_url}/api/v1/{endpoint}", json=data)
        resp.raise_for_status()
        return resp.json()


def get_firewall_rules(api):
    """Retrieve all firewall rules from pfSense."""
    result = api.get("firewall/rule")
    rules = result.get("data", [])
    logger.info("Retrieved %d firewall rules", len(rules))
    return rules


def create_firewall_rule(api, interface, action, protocol, source, destination, dst_port, description):
    """Create a new firewall rule on pfSense."""
    rule = {
        "type": action,
        "interface": interface,
        "ipprotocol": "inet",
        "protocol": protocol,
        "src": source,
        "dst": destination,
        "dstport": dst_port,
        "descr": description,
        "top": False,
    }
    result = api.post("firewall/rule", rule)
    logger.info("Created rule: %s %s %s -> %s:%s (%s)",
                action, protocol, source, destination, dst_port, description)
    return result


def create_lan_to_wan_rules(api):
    """Create standard LAN-to-WAN egress rules."""
    rules = [
        ("pass", "tcp", "LAN net", "any", "80", "Allow HTTP outbound"),
        ("pass", "tcp", "LAN net", "any", "443", "Allow HTTPS outbound"),
        ("pass", "udp", "LAN net", "any", "53", "Allow DNS outbound"),
        ("pass", "tcp", "LAN net", "any", "53", "Allow DNS TCP outbound"),
        ("block", "any", "LAN net", "any", "", "Block all other LAN egress"),
    ]
    for action, proto, src, dst, port, desc in rules:
        create_firewall_rule(api, "lan", action, proto, src, dst, port, desc)
    logger.info("Created %d LAN-to-WAN rules", len(rules))


def create_dmz_rules(api, dmz_interface="opt1"):
    """Create DMZ isolation rules allowing only inbound web traffic."""
    rules = [
        ("pass", "tcp", "any", "DMZ net", "80", "Allow HTTP to DMZ web servers"),
        ("pass", "tcp", "any", "DMZ net", "443", "Allow HTTPS to DMZ web servers"),
        ("block", "any", "DMZ net", "LAN net", "", "Block DMZ to LAN"),
        ("pass", "tcp", "DMZ net", "any", "80", "Allow DMZ HTTP outbound for updates"),
        ("pass", "tcp", "DMZ net", "any", "443", "Allow DMZ HTTPS outbound"),
        ("pass", "udp", "DMZ net", "any", "53", "Allow DMZ DNS"),
    ]
    for action, proto, src, dst, port, desc in rules:
        create_firewall_rule(api, dmz_interface, action, proto, src, dst, port, desc)
    logger.info("Created %d DMZ rules", len(rules))


def create_guest_isolation_rules(api, guest_interface="opt2"):
    """Create guest network isolation rules - internet only, no internal access."""
    rules = [
        ("block", "any", "GUEST net", "LAN net", "", "Block Guest to LAN"),
        ("block", "any", "GUEST net", "DMZ net", "", "Block Guest to DMZ"),
        ("block", "any", "GUEST net", "192.168.0.0/16", "", "Block Guest to RFC1918"),
        ("block", "any", "GUEST net", "10.0.0.0/8", "", "Block Guest to RFC1918"),
        ("block", "any", "GUEST net", "172.16.0.0/12", "", "Block Guest to RFC1918"),
        ("pass", "any", "GUEST net", "any", "", "Allow Guest to Internet"),
    ]
    for action, proto, src, dst, port, desc in rules:
        create_firewall_rule(api, guest_interface, action, proto, src, dst, port, desc)
    logger.info("Created %d Guest isolation rules", len(rules))


def configure_nat_port_forward(api, interface, external_port, target_ip, target_port, protocol="tcp"):
    """Create a NAT port forward rule."""
    nat_rule = {
        "interface": interface,
        "protocol": protocol,
        "src": "any",
        "dst": "wanip",
        "dstport": external_port,
        "target": target_ip,
        "local-port": target_port,
        "descr": f"Port forward {external_port} -> {target_ip}:{target_port}",
    }
    result = api.post("firewall/nat/port_forward", nat_rule)
    logger.info("Created NAT: %s:%s -> %s:%s", interface, external_port, target_ip, target_port)
    return result


def audit_firewall_rules(rules):
    """Audit firewall rules for common security issues."""
    findings = []
    for i, rule in enumerate(rules):
        if rule.get("src") == "any" and rule.get("dst") == "any" and rule.get("type") == "pass":
            findings.append({
                "rule_index": i,
                "finding": "Overly permissive rule: any-to-any pass",
                "severity": "High",
                "rule": rule.get("descr", "No description"),
            })
        if not rule.get("descr"):
            findings.append({
                "rule_index": i,
                "finding": "Rule without description",
                "severity": "Low",
                "rule": f"Rule #{i}",
            })
        if rule.get("disabled"):
            findings.append({
                "rule_index": i,
                "finding": "Disabled rule should be reviewed or removed",
                "severity": "Info",
                "rule": rule.get("descr", "No description"),
            })
    logger.info("Audit: %d findings across %d rules", len(findings), len(rules))
    return findings


def get_firewall_logs(api, limit=100):
    """Retrieve recent firewall log entries."""
    result = api.get(f"diagnostics/system_log/firewall?limit={limit}")
    return result.get("data", [])


def generate_report(rules, audit_findings, nat_rules=None):
    """Generate pfSense firewall configuration report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_rules": len(rules),
        "audit_findings": audit_findings,
        "rules_summary": [
            {"interface": r.get("interface", ""), "type": r.get("type", ""),
             "description": r.get("descr", "")}
            for r in rules
        ],
    }
    print(f"PFSENSE FIREWALL REPORT: {len(rules)} rules, {len(audit_findings)} findings")
    return report


def main():
    parser = argparse.ArgumentParser(description="pfSense Firewall Configuration Agent")
    parser.add_argument("--url", required=True, help="pfSense base URL (https://192.168.1.1)")
    parser.add_argument("--api-key", required=True, help="pfSense API key")
    parser.add_argument("--api-secret", required=True, help="pfSense API secret")
    parser.add_argument("--audit-only", action="store_true", help="Audit rules without changes")
    parser.add_argument("--setup-dmz", action="store_true", help="Create DMZ rules")
    parser.add_argument("--setup-guest", action="store_true", help="Create guest isolation rules")
    parser.add_argument("--output", default="pfsense_report.json")
    args = parser.parse_args()

    api = PfSenseAPI(args.url, args.api_key, args.api_secret)
    rules = get_firewall_rules(api)
    findings = audit_firewall_rules(rules)

    if not args.audit_only:
        if args.setup_dmz:
            create_dmz_rules(api)
        if args.setup_guest:
            create_guest_isolation_rules(api)

    report = generate_report(rules, findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
