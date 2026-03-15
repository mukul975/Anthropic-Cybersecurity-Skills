#!/usr/bin/env python3
"""Agent for performing OT network security assessment based on Purdue model."""

import json
import argparse
import csv
import subprocess
from datetime import datetime
from collections import Counter


PURDUE_LEVELS = {
    0: "Physical Process (sensors, actuators)",
    1: "Basic Control (PLC, RTU, SIS)",
    2: "Area Supervisory (HMI, SCADA, DCS)",
    3: "Site Operations (Historian, Patch Mgmt)",
    3.5: "IT/OT DMZ (jump servers, data diode)",
    4: "Business Planning (ERP, Email)",
    5: "Enterprise Network (Internet, Cloud)",
}


def assess_asset_inventory(csv_file):
    """Assess OT asset inventory against Purdue model zones."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        assets = list(reader)
    by_level = {}
    by_vendor = Counter()
    by_protocol = Counter()
    findings = []
    for asset in assets:
        level = asset.get("purdue_level", asset.get("zone", "unknown"))
        by_level.setdefault(str(level), []).append(asset)
        by_vendor[asset.get("vendor", "unknown")] += 1
        proto = asset.get("protocol", asset.get("protocols", ""))
        for p in proto.split(","):
            if p.strip():
                by_protocol[p.strip()] += 1
        firmware = asset.get("firmware_version", "")
        if asset.get("end_of_life", "").lower() in ("yes", "true"):
            findings.append({"asset": asset.get("name", ""), "issue": "END_OF_LIFE", "severity": "HIGH"})
        if not firmware:
            findings.append({"asset": asset.get("name", ""), "issue": "UNKNOWN_FIRMWARE", "severity": "MEDIUM"})
    return {
        "total_assets": len(assets),
        "by_purdue_level": {k: len(v) for k, v in by_level.items()},
        "by_vendor": dict(by_vendor.most_common(10)),
        "protocols": dict(by_protocol.most_common(15)),
        "findings": findings[:20],
    }


def assess_network_segmentation(csv_file):
    """Check OT network segmentation and firewall rules."""
    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rules = list(reader)
    findings = []
    for rule in rules:
        src_zone = rule.get("src_zone", "")
        dst_zone = rule.get("dst_zone", "")
        action = rule.get("action", "").lower()
        protocol = rule.get("protocol", "")
        if action == "allow" and src_zone.startswith("IT") and dst_zone.startswith("OT"):
            findings.append({
                "rule": rule.get("name", rule.get("id", "")),
                "issue": "DIRECT_IT_TO_OT_ACCESS",
                "severity": "CRITICAL",
                "src_zone": src_zone, "dst_zone": dst_zone,
            })
        if action == "allow" and protocol.lower() in ("any", "all", "*"):
            findings.append({
                "rule": rule.get("name", rule.get("id", "")),
                "issue": "ALLOW_ANY_PROTOCOL",
                "severity": "HIGH",
            })
    return {
        "total_rules": len(rules),
        "allow_rules": sum(1 for r in rules if r.get("action", "").lower() == "allow"),
        "deny_rules": sum(1 for r in rules if r.get("action", "").lower() in ("deny", "drop")),
        "findings": findings[:20],
        "dmz_rules": sum(1 for r in rules if "dmz" in r.get("src_zone", "").lower() or "dmz" in r.get("dst_zone", "").lower()),
    }


def scan_ot_protocols(target_subnet):
    """Scan for common OT protocols on a subnet using nmap."""
    ot_ports = "102,502,2222,4840,20000,44818,47808"
    cmd = ["nmap", "-sV", "-p", ot_ports, target_subnet, "-oX", "-", "--open"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr = host.find("address").get("addr", "") if host.find("address") is not None else ""
            ports = []
            for port in host.findall(".//port"):
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid", 0)),
                    "protocol": service.get("name", "") if service is not None else "",
                    "product": service.get("product", "") if service is not None else "",
                })
            if ports:
                hosts.append({"ip": addr, "ot_services": ports})
        protocol_map = {502: "Modbus", 102: "S7Comm", 44818: "EtherNet/IP", 4840: "OPC-UA", 47808: "BACnet", 20000: "DNP3"}
        return {"subnet": target_subnet, "hosts_with_ot": len(hosts), "hosts": hosts, "protocol_reference": protocol_map}
    except FileNotFoundError:
        return {"error": "nmap not installed"}
    except Exception as e:
        return {"error": str(e)}


def generate_assessment_report(asset_csv, firewall_csv=None):
    """Generate comprehensive OT security assessment."""
    report = {
        "generated": datetime.utcnow().isoformat(),
        "frameworks": ["IEC 62443", "NIST SP 800-82", "NERC CIP"],
        "asset_assessment": assess_asset_inventory(asset_csv),
    }
    if firewall_csv:
        report["segmentation"] = assess_network_segmentation(firewall_csv)
    return report


def main():
    parser = argparse.ArgumentParser(description="OT Network Security Assessment Agent")
    sub = parser.add_subparsers(dest="command")
    a = sub.add_parser("assets", help="Assess OT asset inventory")
    a.add_argument("--csv", required=True)
    s = sub.add_parser("segmentation", help="Assess network segmentation")
    s.add_argument("--csv", required=True, help="Firewall rules CSV")
    p = sub.add_parser("protocols", help="Scan for OT protocols")
    p.add_argument("--subnet", required=True)
    r = sub.add_parser("report", help="Full assessment report")
    r.add_argument("--assets", required=True)
    r.add_argument("--firewall", help="Firewall rules CSV")
    args = parser.parse_args()
    if args.command == "assets":
        result = assess_asset_inventory(args.csv)
    elif args.command == "segmentation":
        result = assess_network_segmentation(args.csv)
    elif args.command == "protocols":
        result = scan_ot_protocols(args.subnet)
    elif args.command == "report":
        result = generate_assessment_report(args.assets, args.firewall)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
