# OT Network Assessment Analysis Scripts

Full standalone scripts referenced from `SKILL.md` Steps 2-3. Both require `scapy` (Step 2 also uses `scapy.contrib.modbus`).

## Step 2: OT Network Passive Discovery and Asset Inventory Builder

Uses pcap captures from SPAN ports to identify OT assets, protocols, and communication patterns without active scanning. Classifies assets by Purdue level, maps industrial protocols by port, and flags cross-zone flows:

```python
#!/usr/bin/env python3
"""OT Network Passive Discovery and Asset Inventory Builder.

Uses pcap captures from SPAN ports to identify OT assets, protocols,
and communication patterns without active scanning.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP
    from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)

# Industrial protocol port mappings
OT_PROTOCOL_PORTS = {
    502: "Modbus/TCP",
    102: "S7comm (Siemens)",
    44818: "EtherNet/IP (CIP)",
    2222: "EtherNet/IP (implicit)",
    4840: "OPC UA",
    20000: "DNP3",
    47808: "BACnet",
    1911: "Niagara Fox",
    789: "Crimson v3 (Red Lion)",
    2404: "IEC 60870-5-104",
    18245: "GE SRTP",
    5094: "HART-IP",
}

PURDUE_LEVEL_RANGES = {
    "Level 0-1 (Field Devices)": ["10.10.0.0/16", "192.168.10.0/24"],
    "Level 2 (Control Systems)": ["10.20.0.0/16", "192.168.20.0/24"],
    "Level 3 (Site Operations)": ["10.30.0.0/16", "192.168.30.0/24"],
    "Level 3.5 (DMZ)": ["172.16.0.0/16"],
    "Level 4 (Enterprise)": ["10.0.0.0/16"],
}


def classify_purdue_level(ip_addr):
    """Classify an IP address to its Purdue Reference Model level."""
    from ipaddress import ip_address, ip_network

    addr = ip_address(ip_addr)
    for level, subnets in PURDUE_LEVEL_RANGES.items():
        for subnet in subnets:
            if addr in ip_network(subnet):
                return level
    return "Unknown"


def analyze_ot_pcap(pcap_file):
    """Analyze pcap file to discover OT assets and communication patterns."""
    packets = rdpcap(pcap_file)

    assets = {}
    connections = defaultdict(lambda: {"count": 0, "protocols": set(), "ports": set()})
    protocol_stats = defaultdict(int)
    cross_zone_flows = []

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Track assets
        for ip in (src_ip, dst_ip):
            if ip not in assets:
                assets[ip] = {
                    "ip": ip,
                    "purdue_level": classify_purdue_level(ip),
                    "protocols_observed": set(),
                    "roles": set(),
                    "first_seen": str(pkt.time),
                    "last_seen": str(pkt.time),
                    "mac": None,
                }
            assets[ip]["last_seen"] = str(pkt.time)

        # Identify OT protocols by port
        dst_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        if dst_port and dst_port in OT_PROTOCOL_PORTS:
            protocol_name = OT_PROTOCOL_PORTS[dst_port]
            protocol_stats[protocol_name] += 1
            assets[src_ip]["protocols_observed"].add(protocol_name)
            assets[dst_ip]["protocols_observed"].add(protocol_name)

            # Determine roles
            assets[src_ip]["roles"].add("client/master")
            assets[dst_ip]["roles"].add("server/slave")

        # Track connections
        conn_key = (src_ip, dst_ip)
        connections[conn_key]["count"] += 1
        if dst_port:
            connections[conn_key]["ports"].add(dst_port)
            if dst_port in OT_PROTOCOL_PORTS:
                connections[conn_key]["protocols"].add(OT_PROTOCOL_PORTS[dst_port])

        # Detect cross-zone communication
        src_level = classify_purdue_level(src_ip)
        dst_level = classify_purdue_level(dst_ip)
        if src_level != dst_level and src_level != "Unknown" and dst_level != "Unknown":
            cross_zone_flows.append({
                "src": src_ip,
                "src_level": src_level,
                "dst": dst_ip,
                "dst_level": dst_level,
                "protocol": OT_PROTOCOL_PORTS.get(dst_port, f"port/{dst_port}"),
            })

    return {
        "asset_count": len(assets),
        "assets": {ip: {k: list(v) if isinstance(v, set) else v for k, v in info.items()} for ip, info in assets.items()},
        "protocol_distribution": dict(protocol_stats),
        "total_connections": len(connections),
        "cross_zone_flows": cross_zone_flows[:50],
    }


def generate_assessment_report(results):
    """Generate the OT network assessment findings report."""
    report = []
    report.append("=" * 70)
    report.append("OT NETWORK PASSIVE DISCOVERY REPORT")
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("=" * 70)

    report.append(f"\nTotal Assets Discovered: {results['asset_count']}")
    report.append(f"Total Unique Connections: {results['total_connections']}")

    report.append("\n--- INDUSTRIAL PROTOCOL DISTRIBUTION ---")
    for proto, count in sorted(results["protocol_distribution"].items(), key=lambda x: -x[1]):
        report.append(f"  {proto}: {count} packets")

    report.append("\n--- CROSS-ZONE COMMUNICATION FLOWS ---")
    if results["cross_zone_flows"]:
        for flow in results["cross_zone_flows"][:20]:
            report.append(
                f"  {flow['src']} ({flow['src_level']}) -> "
                f"{flow['dst']} ({flow['dst_level']}) via {flow['protocol']}"
            )
    else:
        report.append("  No cross-zone flows detected (check subnet classifications)")

    report.append("\n--- FINDINGS ---")
    # Check for Level 4 to Level 0-1 direct connections (critical finding)
    for flow in results["cross_zone_flows"]:
        if "Level 4" in flow["src_level"] and "Level 0-1" in flow["dst_level"]:
            report.append(
                f"  [CRITICAL] Direct Enterprise-to-Field traffic: "
                f"{flow['src']} -> {flow['dst']} via {flow['protocol']}"
            )
        elif "Level 4" in flow["src_level"] and "Level 2" in flow["dst_level"]:
            report.append(
                f"  [HIGH] Enterprise-to-Control traffic bypassing DMZ: "
                f"{flow['src']} -> {flow['dst']} via {flow['protocol']}"
            )

    return "\n".join(report)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ot_network_discovery.py <pcap_file>")
        sys.exit(1)

    results = analyze_ot_pcap(sys.argv[1])
    print(generate_assessment_report(results))

    # Save detailed JSON
    output_file = sys.argv[1].replace(".pcap", "_inventory.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nDetailed inventory saved to: {output_file}")
```

## Step 3: OT Zone Firewall Rule Analyzer

Parses firewall rule exports (CSV) and evaluates them against the IEC 62443 zone/conduit model, flagging prohibited conduits, overly permissive `any` rules, and unauthorized ports:

```python
#!/usr/bin/env python3
"""OT Zone Firewall Rule Analyzer.

Parses firewall rule exports (CSV format) and evaluates them against
IEC 62443 zone/conduit model requirements.
"""

import csv
import json
import sys
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FirewallRule:
    rule_id: str
    source_zone: str
    source_ip: str
    dest_zone: str
    dest_ip: str
    service: str
    port: str
    action: str
    enabled: bool
    comment: str = ""


# IEC 62443 zone communication policy
# Defines which zone pairs are allowed to communicate and through what conduit
ALLOWED_CONDUITS = {
    ("Level 4", "Level 3.5"): {
        "allowed_ports": [443, 3389, 22],
        "description": "Enterprise to DMZ - web services, jump hosts",
        "requires_inspection": True,
    },
    ("Level 3.5", "Level 3"): {
        "allowed_ports": [443, 1433, 5432, 8080],
        "description": "DMZ to Site Ops - historian mirror, OPC relay",
        "requires_inspection": True,
    },
    ("Level 3", "Level 2"): {
        "allowed_ports": [502, 44818, 4840, 102],
        "description": "Site Ops to Control - OPC UA, Modbus, S7comm",
        "requires_inspection": True,
    },
    ("Level 2", "Level 1"): {
        "allowed_ports": [502, 44818, 102, 2222],
        "description": "Control to Field - direct industrial protocols",
        "requires_inspection": False,
    },
}

# Prohibited direct connections
PROHIBITED_CONDUITS = [
    ("Level 4", "Level 3"),
    ("Level 4", "Level 2"),
    ("Level 4", "Level 1"),
    ("Level 4", "Level 0"),
    ("Level 3", "Level 1"),
    ("Level 3", "Level 0"),
    ("Internet", "Level 3.5"),
    ("Internet", "Level 3"),
    ("Internet", "Level 2"),
    ("Internet", "Level 1"),
]


def parse_firewall_rules(csv_file):
    """Parse firewall rules from CSV export."""
    rules = []
    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(FirewallRule(
                rule_id=row.get("rule_id", ""),
                source_zone=row.get("source_zone", ""),
                source_ip=row.get("source_ip", ""),
                dest_zone=row.get("dest_zone", ""),
                dest_ip=row.get("dest_ip", ""),
                service=row.get("service", ""),
                port=row.get("port", ""),
                action=row.get("action", ""),
                enabled=row.get("enabled", "true").lower() == "true",
                comment=row.get("comment", ""),
            ))
    return rules


def analyze_rules(rules):
    """Analyze firewall rules against IEC 62443 zone model."""
    findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    for rule in rules:
        if not rule.enabled or rule.action.lower() != "allow":
            continue

        zone_pair = (rule.source_zone, rule.dest_zone)
        port = int(rule.port) if rule.port.isdigit() else 0

        # Check for prohibited conduits
        if zone_pair in PROHIBITED_CONDUITS:
            findings["critical"].append({
                "rule_id": rule.rule_id,
                "finding": f"Prohibited direct connection: {rule.source_zone} -> {rule.dest_zone}",
                "detail": f"Rule allows {rule.source_ip} to reach {rule.dest_ip}:{rule.port} ({rule.service})",
                "remediation": "Remove rule. Route traffic through DMZ (Level 3.5) with application-layer inspection.",
            })

        # Check for overly broad rules (any/any)
        elif rule.source_ip in ("any", "0.0.0.0/0") or rule.dest_ip in ("any", "0.0.0.0/0"):
            findings["high"].append({
                "rule_id": rule.rule_id,
                "finding": f"Overly permissive rule with 'any' address",
                "detail": f"{rule.source_ip} -> {rule.dest_ip}:{rule.port} in {zone_pair}",
                "remediation": "Restrict to specific host IPs per IEC 62443 least-privilege conduit policy.",
            })

        # Check allowed conduits for port violations
        elif zone_pair in ALLOWED_CONDUITS:
            conduit = ALLOWED_CONDUITS[zone_pair]
            if port and port not in conduit["allowed_ports"]:
                findings["medium"].append({
                    "rule_id": rule.rule_id,
                    "finding": f"Unauthorized port in conduit {zone_pair}",
                    "detail": f"Port {port} ({rule.service}) not in allowed list {conduit['allowed_ports']}",
                    "remediation": f"Remove port {port} from conduit or justify in risk assessment.",
                })

    return findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ot_firewall_analyzer.py <rules.csv>")
        sys.exit(1)

    rules = parse_firewall_rules(sys.argv[1])
    findings = analyze_rules(rules)

    print("=" * 70)
    print("OT ZONE FIREWALL RULE ANALYSIS")
    print("=" * 70)
    for severity in ["critical", "high", "medium", "low"]:
        if findings[severity]:
            print(f"\n--- {severity.upper()} FINDINGS ({len(findings[severity])}) ---")
            for f in findings[severity]:
                print(f"  [{f['rule_id']}] {f['finding']}")
                print(f"    Detail: {f['detail']}")
                print(f"    Fix: {f['remediation']}")
```
