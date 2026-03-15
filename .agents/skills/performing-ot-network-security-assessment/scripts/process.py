#!/usr/bin/env python3
"""OT Network Security Assessment - Automated Discovery and Analysis.

This script performs passive OT network discovery from pcap captures,
classifies assets by Purdue level, maps industrial protocol usage,
and identifies security findings.

Usage:
    python process.py --pcap <capture.pcap> [--firewall-rules <rules.csv>]
    python process.py --live-capture --interface <iface> --duration <seconds>
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional

try:
    from scapy.all import rdpcap, sniff, IP, TCP, UDP, Ether, ARP
except ImportError:
    print("[ERROR] scapy is required: pip install scapy")
    sys.exit(1)


# ── Industrial Protocol Definitions ──────────────────────────────────

OT_PROTOCOLS = {
    502:   {"name": "Modbus/TCP", "vendor": "Open", "risk": "high", "auth": False},
    102:   {"name": "S7comm", "vendor": "Siemens", "risk": "high", "auth": False},
    44818: {"name": "EtherNet/IP", "vendor": "ODVA/Rockwell", "risk": "high", "auth": False},
    2222:  {"name": "EtherNet/IP Implicit", "vendor": "ODVA", "risk": "medium", "auth": False},
    4840:  {"name": "OPC UA", "vendor": "OPC Foundation", "risk": "low", "auth": True},
    20000: {"name": "DNP3", "vendor": "IEEE", "risk": "high", "auth": False},
    47808: {"name": "BACnet/IP", "vendor": "ASHRAE", "risk": "high", "auth": False},
    1911:  {"name": "Niagara Fox", "vendor": "Tridium", "risk": "high", "auth": False},
    2404:  {"name": "IEC 60870-5-104", "vendor": "IEC", "risk": "high", "auth": False},
    18245: {"name": "GE SRTP", "vendor": "GE", "risk": "high", "auth": False},
    5094:  {"name": "HART-IP", "vendor": "FieldComm", "risk": "medium", "auth": False},
    789:   {"name": "Crimson v3", "vendor": "Red Lion", "risk": "high", "auth": False},
    1089:  {"name": "FF HSE", "vendor": "Fieldbus Foundation", "risk": "medium", "auth": False},
    9600:  {"name": "OMRON FINS", "vendor": "OMRON", "risk": "high", "auth": False},
    5007:  {"name": "Mitsubishi MELSEC", "vendor": "Mitsubishi", "risk": "high", "auth": False},
}

# Modbus function codes with write capability
MODBUS_WRITE_FUNCS = {5, 6, 15, 16, 22, 23}
MODBUS_DIAGNOSTIC_FUNCS = {8, 17, 43}


# ── Purdue Level Classification ─────────────────────────────────────

@dataclass
class PurdueConfig:
    """Configuration for Purdue level subnet mappings."""
    level_0_1: list = field(default_factory=lambda: ["10.10.0.0/16", "192.168.10.0/24"])
    level_2: list = field(default_factory=lambda: ["10.20.0.0/16", "192.168.20.0/24"])
    level_3: list = field(default_factory=lambda: ["10.30.0.0/16", "192.168.30.0/24"])
    level_3_5: list = field(default_factory=lambda: ["172.16.0.0/16"])
    level_4: list = field(default_factory=lambda: ["10.0.0.0/8"])


def classify_purdue_level(ip_str, config=None):
    """Classify IP to Purdue level based on subnet mappings."""
    if config is None:
        config = PurdueConfig()

    try:
        addr = ip_address(ip_str)
    except ValueError:
        return "Unknown"

    level_map = [
        ("Level 0-1", config.level_0_1),
        ("Level 2", config.level_2),
        ("Level 3", config.level_3),
        ("Level 3.5", config.level_3_5),
        ("Level 4", config.level_4),
    ]

    for level_name, subnets in level_map:
        for subnet in subnets:
            if addr in ip_network(subnet, strict=False):
                return level_name
    return "Unknown"


# ── Asset and Finding Models ─────────────────────────────────────────

@dataclass
class OTAsset:
    ip: str
    mac: str = ""
    purdue_level: str = ""
    protocols: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    vendor_hint: str = ""
    first_seen: str = ""
    last_seen: str = ""
    ports_open: list = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    severity: str  # critical, high, medium, low
    title: str
    description: str
    affected_assets: list = field(default_factory=list)
    iec_62443_ref: str = ""
    nist_800_82_ref: str = ""
    remediation: str = ""


# ── Passive Discovery Engine ─────────────────────────────────────────

class OTNetworkDiscovery:
    """Passive OT network discovery and analysis engine."""

    def __init__(self, purdue_config=None):
        self.config = purdue_config or PurdueConfig()
        self.assets = {}
        self.connections = defaultdict(lambda: {
            "count": 0, "protocols": set(), "ports": set(),
            "first_seen": None, "last_seen": None
        })
        self.protocol_stats = defaultdict(int)
        self.findings = []
        self.modbus_writes = []
        self.cross_zone_flows = []

    def process_packet(self, pkt):
        """Process a single packet for OT asset and protocol discovery."""
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = str(datetime.fromtimestamp(float(pkt.time)))

        # Discover or update assets
        for ip_addr in (src_ip, dst_ip):
            if ip_addr not in self.assets:
                mac = ""
                if pkt.haslayer(Ether):
                    mac = pkt[Ether].src if ip_addr == src_ip else pkt[Ether].dst
                self.assets[ip_addr] = OTAsset(
                    ip=ip_addr,
                    mac=mac,
                    purdue_level=classify_purdue_level(ip_addr, self.config),
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            self.assets[ip_addr].last_seen = timestamp

        # Extract port information
        dst_port = src_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport
            src_port = pkt[UDP].sport

        # Identify OT protocols
        if dst_port in OT_PROTOCOLS:
            proto_info = OT_PROTOCOLS[dst_port]
            proto_name = proto_info["name"]
            self.protocol_stats[proto_name] += 1

            asset_src = self.assets[src_ip]
            asset_dst = self.assets[dst_ip]

            if proto_name not in asset_src.protocols:
                asset_src.protocols.append(proto_name)
            if proto_name not in asset_dst.protocols:
                asset_dst.protocols.append(proto_name)

            if "master/client" not in asset_src.roles:
                asset_src.roles.append("master/client")
            if "slave/server" not in asset_dst.roles:
                asset_dst.roles.append("slave/server")

            if dst_port not in asset_dst.ports_open:
                asset_dst.ports_open.append(dst_port)

            if proto_info["vendor"] != "Open":
                asset_dst.vendor_hint = proto_info["vendor"]

        # Track Modbus write operations
        if dst_port == 502 and pkt.haslayer(TCP):
            payload = bytes(pkt[TCP].payload)
            if len(payload) > 7:
                func_code = payload[7]
                if func_code in MODBUS_WRITE_FUNCS:
                    self.modbus_writes.append({
                        "timestamp": timestamp,
                        "src": src_ip,
                        "dst": dst_ip,
                        "function_code": func_code,
                    })

        # Track connections
        conn_key = f"{src_ip}->{dst_ip}"
        conn = self.connections[conn_key]
        conn["count"] += 1
        if conn["first_seen"] is None:
            conn["first_seen"] = timestamp
        conn["last_seen"] = timestamp
        if dst_port:
            conn["ports"].add(dst_port)
            if dst_port in OT_PROTOCOLS:
                conn["protocols"].add(OT_PROTOCOLS[dst_port]["name"])

        # Detect cross-zone communication
        src_level = self.assets[src_ip].purdue_level
        dst_level = self.assets[dst_ip].purdue_level
        if src_level != dst_level and "Unknown" not in (src_level, dst_level):
            self.cross_zone_flows.append({
                "src": src_ip, "src_level": src_level,
                "dst": dst_ip, "dst_level": dst_level,
                "port": dst_port,
                "protocol": OT_PROTOCOLS.get(dst_port, {}).get("name", f"port/{dst_port}"),
                "timestamp": timestamp,
            })

    def analyze_pcap(self, pcap_file):
        """Analyze a pcap file for OT network discovery."""
        print(f"[*] Loading pcap: {pcap_file}")
        packets = rdpcap(pcap_file)
        print(f"[*] Processing {len(packets)} packets...")
        for pkt in packets:
            self.process_packet(pkt)
        print(f"[*] Discovery complete: {len(self.assets)} assets found")

    def live_capture(self, interface, duration):
        """Perform live passive capture on a network interface."""
        print(f"[*] Starting live capture on {interface} for {duration}s...")
        sniff(iface=interface, timeout=duration, prn=self.process_packet, store=0)
        print(f"[*] Capture complete: {len(self.assets)} assets found")

    def generate_findings(self):
        """Analyze discovered data and generate security findings."""
        finding_counter = 1

        # Finding: Direct enterprise-to-field communication
        for flow in self.cross_zone_flows:
            if "Level 4" in flow["src_level"] and "Level 0-1" in flow["dst_level"]:
                self.findings.append(Finding(
                    finding_id=f"OT-{finding_counter:03d}",
                    severity="critical",
                    title="Direct Enterprise-to-Field Device Communication",
                    description=(
                        f"Traffic observed from {flow['src']} ({flow['src_level']}) "
                        f"to {flow['dst']} ({flow['dst_level']}) via {flow['protocol']}. "
                        "This bypasses all intermediate security zones."
                    ),
                    affected_assets=[flow["src"], flow["dst"]],
                    iec_62443_ref="IEC 62443-3-3 SR 5.1 - Network Segmentation",
                    nist_800_82_ref="NIST SP 800-82r3 Section 5.3 - Network Architecture",
                    remediation="Block direct L4-to-L0/1 traffic. Route through DMZ and OT firewall.",
                ))
                finding_counter += 1

        # Finding: Enterprise bypassing DMZ to reach control
        for flow in self.cross_zone_flows:
            if "Level 4" in flow["src_level"] and "Level 2" in flow["dst_level"]:
                self.findings.append(Finding(
                    finding_id=f"OT-{finding_counter:03d}",
                    severity="critical",
                    title="Enterprise-to-Control Bypass of DMZ",
                    description=(
                        f"Traffic from {flow['src']} ({flow['src_level']}) reaches "
                        f"{flow['dst']} ({flow['dst_level']}) without traversing DMZ."
                    ),
                    affected_assets=[flow["src"], flow["dst"]],
                    iec_62443_ref="IEC 62443-3-3 SR 5.2 - Zone Boundary Protection",
                    nist_800_82_ref="NIST SP 800-82r3 Section 5.4 - DMZ Architecture",
                    remediation="Deploy DMZ between enterprise and control zones with bidirectional firewall.",
                ))
                finding_counter += 1

        # Finding: Unauthenticated Modbus write operations
        if self.modbus_writes:
            unique_targets = set(w["dst"] for w in self.modbus_writes)
            self.findings.append(Finding(
                finding_id=f"OT-{finding_counter:03d}",
                severity="critical",
                title="Unauthenticated Modbus/TCP Write Commands Detected",
                description=(
                    f"{len(self.modbus_writes)} Modbus write operations observed "
                    f"targeting {len(unique_targets)} devices. Modbus/TCP has no "
                    "native authentication; any network-connected device can modify registers."
                ),
                affected_assets=list(unique_targets),
                iec_62443_ref="IEC 62443-3-3 SR 1.1 - Human User Identification and Authentication",
                nist_800_82_ref="NIST SP 800-82r3 Section 6.2 - Access Control",
                remediation=(
                    "Deploy Modbus-aware firewall (e.g., Tofino, Claroty Edge) to restrict "
                    "write-capable source addresses. Implement allowlisting for Modbus function codes."
                ),
            ))
            finding_counter += 1

        # Finding: Unauthenticated industrial protocols
        for port, info in OT_PROTOCOLS.items():
            if not info["auth"] and info["name"] in self.protocol_stats:
                exposed_assets = [
                    ip for ip, asset in self.assets.items()
                    if port in asset.ports_open
                ]
                if exposed_assets:
                    self.findings.append(Finding(
                        finding_id=f"OT-{finding_counter:03d}",
                        severity="high",
                        title=f"Unauthenticated {info['name']} Protocol in Use",
                        description=(
                            f"{len(exposed_assets)} devices expose {info['name']} (port {port}) "
                            f"which lacks native authentication. Vendor: {info['vendor']}."
                        ),
                        affected_assets=exposed_assets,
                        iec_62443_ref="IEC 62443-3-3 SR 1.2 - Software Process Identification",
                        nist_800_82_ref="NIST SP 800-82r3 Section 6.2.1 - Protocol Security",
                        remediation=f"Deploy protocol-aware firewall for {info['name']} traffic inspection.",
                    ))
                    finding_counter += 1

        return self.findings

    def export_report(self, output_file):
        """Export full assessment results to JSON."""
        report = {
            "assessment_date": datetime.now().isoformat(),
            "summary": {
                "total_assets": len(self.assets),
                "total_connections": len(self.connections),
                "protocols_detected": dict(self.protocol_stats),
                "cross_zone_flows": len(self.cross_zone_flows),
                "modbus_write_operations": len(self.modbus_writes),
                "findings_critical": sum(1 for f in self.findings if f.severity == "critical"),
                "findings_high": sum(1 for f in self.findings if f.severity == "high"),
                "findings_medium": sum(1 for f in self.findings if f.severity == "medium"),
                "findings_low": sum(1 for f in self.findings if f.severity == "low"),
            },
            "assets": {ip: asdict(asset) for ip, asset in self.assets.items()},
            "findings": [asdict(f) for f in self.findings],
            "cross_zone_flows": self.cross_zone_flows[:100],
        }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] Report saved to: {output_file}")

    def print_summary(self):
        """Print assessment summary to console."""
        print("\n" + "=" * 70)
        print("OT NETWORK SECURITY ASSESSMENT - SUMMARY")
        print("=" * 70)

        print(f"\nAssets Discovered: {len(self.assets)}")
        level_counts = defaultdict(int)
        for asset in self.assets.values():
            level_counts[asset.purdue_level] += 1
        for level in sorted(level_counts.keys()):
            print(f"  {level}: {level_counts[level]} devices")

        print(f"\nProtocol Distribution:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: -x[1]):
            print(f"  {proto}: {count} packets")

        print(f"\nCross-Zone Flows: {len(self.cross_zone_flows)}")
        print(f"Modbus Write Operations: {len(self.modbus_writes)}")

        print(f"\nFindings:")
        severity_counts = defaultdict(int)
        for f in self.findings:
            severity_counts[f.severity] += 1
        for sev in ["critical", "high", "medium", "low"]:
            if severity_counts[sev]:
                print(f"  {sev.upper()}: {severity_counts[sev]}")

        if self.findings:
            print(f"\nTop Findings:")
            for f in self.findings[:10]:
                print(f"  [{f.finding_id}] [{f.severity.upper()}] {f.title}")


def main():
    parser = argparse.ArgumentParser(description="OT Network Security Assessment Tool")
    parser.add_argument("--pcap", help="Path to pcap file for analysis")
    parser.add_argument("--live-capture", action="store_true", help="Perform live capture")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--duration", type=int, default=300, help="Capture duration in seconds")
    parser.add_argument("--output", default="ot_assessment_report.json", help="Output report file")
    args = parser.parse_args()

    discovery = OTNetworkDiscovery()

    if args.pcap:
        discovery.analyze_pcap(args.pcap)
    elif args.live_capture and args.interface:
        discovery.live_capture(args.interface, args.duration)
    else:
        parser.print_help()
        sys.exit(1)

    discovery.generate_findings()
    discovery.print_summary()
    discovery.export_report(args.output)


if __name__ == "__main__":
    main()
