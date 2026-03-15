#!/usr/bin/env python3
"""OT Network Segmentation Agent - audits IT/OT boundaries, firewall rules, and zone compliance."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PURDUE_ZONES = {
    "level_0": {"name": "Process", "description": "Field devices, sensors, actuators"},
    "level_1": {"name": "Control", "description": "PLCs, RTUs, safety systems"},
    "level_2": {"name": "Supervisory", "description": "HMI, SCADA, engineering workstations"},
    "level_3": {"name": "Operations", "description": "Historian, OT domain services"},
    "level_3.5": {"name": "DMZ", "description": "IT/OT demilitarized zone"},
    "level_4": {"name": "Enterprise", "description": "IT network, business systems"},
    "level_5": {"name": "External", "description": "Internet, cloud services"},
}


def scan_zone_hosts(subnet):
    """Discover hosts in an OT zone via nmap ping scan."""
    cmd = ["nmap", "-sn", subnet, "-oX", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    hosts = []
    import re
    for match in re.finditer(r'addr="(\d+\.\d+\.\d+\.\d+)"', result.stdout):
        hosts.append(match.group(1))
    return hosts


def check_firewall_rules(firewall_config_file):
    """Parse firewall rules for IT/OT boundary enforcement."""
    findings = []
    try:
        with open(firewall_config_file) as f:
            rules = json.load(f)
        for rule in rules:
            if rule.get("action") == "permit":
                src_zone = rule.get("source_zone", "")
                dst_zone = rule.get("destination_zone", "")
                if src_zone in ("enterprise", "external") and dst_zone in ("control", "process"):
                    findings.append({
                        "rule_id": rule.get("id", ""),
                        "issue": f"Direct access from {src_zone} to {dst_zone} zone",
                        "severity": "critical",
                        "recommendation": "Route through DMZ with application proxy",
                    })
                if rule.get("protocol") == "any" or rule.get("port") == "any":
                    findings.append({
                        "rule_id": rule.get("id", ""),
                        "issue": "Overly permissive rule (any protocol/port)",
                        "severity": "high",
                        "recommendation": "Restrict to specific OT protocols (Modbus/TCP 502, EtherNet/IP 44818)",
                    })
    except (FileNotFoundError, json.JSONDecodeError):
        findings.append({"issue": "Firewall config not found or invalid", "severity": "critical"})
    return findings


def check_ot_protocol_exposure(target_subnet):
    """Check for exposed OT protocols on the network."""
    ot_ports = {"502": "Modbus", "102": "S7comm", "44818": "EtherNet/IP",
                "20000": "DNP3", "4840": "OPC-UA", "2222": "EtherNet/IP-explicit"}
    port_list = ",".join(ot_ports.keys())
    cmd = ["nmap", "-sS", "-p", port_list, target_subnet, "--open", "-oX", "-"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    exposed = []
    import re
    current_host = ""
    for line in result.stdout.split("\n"):
        host_match = re.search(r'addr="(\d+\.\d+\.\d+\.\d+)"', line)
        if host_match:
            current_host = host_match.group(1)
        port_match = re.search(r'portid="(\d+)".*state="open"', line)
        if port_match and current_host:
            port = port_match.group(1)
            exposed.append({
                "host": current_host, "port": int(port),
                "protocol": ot_ports.get(port, "unknown"),
                "risk": "high" if port in ("502", "102") else "medium",
            })
    return exposed


def audit_zone_compliance(zone_config):
    """Audit zone assignment compliance against Purdue model."""
    findings = []
    for zone_id, zone_data in zone_config.items():
        if zone_id not in PURDUE_ZONES:
            findings.append({"zone": zone_id, "issue": "Non-standard zone", "severity": "medium"})
            continue
        hosts = zone_data.get("hosts", [])
        for host in hosts:
            if host.get("type") == "workstation" and zone_id in ("level_0", "level_1"):
                findings.append({"zone": zone_id, "host": host.get("ip"), "issue": "Workstation in control/process zone", "severity": "high"})
            if host.get("internet_access") and zone_id in ("level_0", "level_1", "level_2"):
                findings.append({"zone": zone_id, "host": host.get("ip"), "issue": "Internet access from OT zone", "severity": "critical"})
    return findings


def generate_report(fw_findings, ot_exposure, zone_findings, zone_config):
    all_findings = fw_findings + zone_findings
    critical = sum(1 for f in all_findings if f.get("severity") == "critical")
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "framework": "IEC 62443 / Purdue Model",
        "zones_defined": len(zone_config) if zone_config else 0,
        "firewall_findings": fw_findings,
        "ot_protocol_exposure": ot_exposure,
        "zone_compliance_findings": zone_findings,
        "total_findings": len(all_findings),
        "critical_findings": critical,
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="OT Network Segmentation Audit Agent")
    parser.add_argument("--firewall-config", help="JSON firewall rules config file")
    parser.add_argument("--zone-config", help="JSON zone configuration file")
    parser.add_argument("--scan-subnet", help="OT subnet to scan for protocol exposure")
    parser.add_argument("--output", default="ot_segmentation_report.json")
    args = parser.parse_args()

    fw_findings = check_firewall_rules(args.firewall_config) if args.firewall_config else []
    ot_exposure = check_ot_protocol_exposure(args.scan_subnet) if args.scan_subnet else []
    zone_config = {}
    zone_findings = []
    if args.zone_config:
        with open(args.zone_config) as f:
            zone_config = json.load(f)
        zone_findings = audit_zone_compliance(zone_config)
    report = generate_report(fw_findings, ot_exposure, zone_findings, zone_config)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("OT segmentation: %d findings (%d critical), %d exposed OT ports",
                report["total_findings"], report["critical_findings"], len(ot_exposure))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
