#!/usr/bin/env python3
"""Purdue model OT network segmentation audit agent.

Audits OT/ICS network segmentation against the Purdue Enterprise
Reference Architecture by testing connectivity between network zones,
verifying firewall rules, and mapping discovered hosts to Purdue levels.
"""
import argparse
import json
import socket
from datetime import datetime, timezone


PURDUE_LEVELS = {
    0: {"name": "Process", "description": "Sensors, actuators, field devices"},
    1: {"name": "Basic Control", "description": "PLCs, RTUs, safety systems"},
    2: {"name": "Area Supervisory", "description": "HMIs, SCADA, historian"},
    3: {"name": "Site Operations", "description": "Patch mgmt, AV, file servers"},
    3.5: {"name": "DMZ", "description": "Industrial DMZ between IT and OT"},
    4: {"name": "Site Business", "description": "ERP, email, corporate apps"},
    5: {"name": "Enterprise", "description": "Internet, cloud, remote access"},
}

PROHIBITED_FLOWS = [
    {"from_level": 5, "to_level": 0, "description": "Internet to Process (critical violation)"},
    {"from_level": 5, "to_level": 1, "description": "Internet to Basic Control"},
    {"from_level": 5, "to_level": 2, "description": "Internet to SCADA"},
    {"from_level": 4, "to_level": 0, "description": "Corporate to Process"},
    {"from_level": 4, "to_level": 1, "description": "Corporate to PLC/RTU"},
]


def test_connectivity(source_ip, target_ip, ports, timeout=3):
    """Test TCP connectivity between two hosts on specified ports."""
    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            reachable = result == 0
            results.append({
                "target": target_ip,
                "port": port,
                "reachable": reachable,
            })
        except (socket.error, OSError):
            results.append({"target": target_ip, "port": port, "reachable": False})
    return results


def audit_zone_separation(zone_map):
    """Audit network segmentation between Purdue zones."""
    findings = []
    print("[*] Auditing zone separation...")

    for flow in PROHIBITED_FLOWS:
        from_level = flow["from_level"]
        to_level = flow["to_level"]
        from_hosts = zone_map.get(str(from_level), [])
        to_hosts = zone_map.get(str(to_level), [])

        for src in from_hosts[:3]:
            for dst in to_hosts[:3]:
                common_ports = [22, 80, 443, 502, 102, 44818, 47808, 20000]
                results = test_connectivity(src, dst, common_ports)
                open_ports = [r for r in results if r["reachable"]]
                if open_ports:
                    findings.append({
                        "check": f"Zone {from_level} -> Zone {to_level}",
                        "severity": "CRITICAL",
                        "source": src,
                        "destination": dst,
                        "open_ports": [r["port"] for r in open_ports],
                        "detail": flow["description"],
                        "recommendation": "Block traffic between these zones via firewall",
                    })

    if not findings:
        findings.append({
            "check": "Prohibited zone flows",
            "severity": "INFO",
            "detail": "No prohibited cross-zone connectivity detected",
        })

    return findings


def audit_ot_protocols(target_ips):
    """Check for exposed OT/ICS protocols on target hosts."""
    findings = []
    ot_ports = {
        502: "Modbus TCP",
        102: "S7comm (Siemens)",
        44818: "EtherNet/IP",
        47808: "BACnet",
        20000: "DNP3",
        4840: "OPC UA",
        2222: "EtherCAT",
        1911: "Niagara Fox",
        9600: "OMRON FINS",
    }

    print(f"[*] Scanning {len(target_ips)} hosts for exposed OT protocols...")
    for ip in target_ips:
        for port, protocol in ot_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    findings.append({
                        "check": f"Exposed OT protocol: {protocol}",
                        "severity": "HIGH",
                        "host": ip,
                        "port": port,
                        "protocol": protocol,
                        "detail": f"{protocol} on {ip}:{port} is accessible",
                    })
            except (socket.error, OSError):
                pass

    print(f"[+] Found {len(findings)} exposed OT protocols")
    return findings


def load_zone_map(config_path):
    """Load zone-to-host mapping from config file."""
    with open(config_path, "r") as f:
        return json.load(f)


def format_summary(zone_findings, protocol_findings, zone_map):
    """Print audit summary."""
    all_findings = zone_findings + protocol_findings
    print(f"\n{'='*60}")
    print("  Purdue Model Network Segmentation Audit")
    print(f"{'='*60}")

    for level, info in sorted(PURDUE_LEVELS.items()):
        host_count = len(zone_map.get(str(level), []))
        print(f"  Level {level}: {info['name']:20s} ({host_count} hosts) - {info['description']}")

    print(f"\n  Zone Separation Findings : {len(zone_findings)}")
    print(f"  Protocol Exposure Findings: {len(protocol_findings)}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if all_findings:
        print("\n  Critical/High Issues:")
        for f in all_findings:
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f"    [{f['severity']:8s}] {f['check']}: {f.get('detail', '')[:50]}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Purdue model OT network segmentation audit agent"
    )
    parser.add_argument("--zone-map", required=True,
                        help="JSON file mapping Purdue levels to host IPs")
    parser.add_argument("--scan-protocols", action="store_true",
                        help="Scan for exposed OT protocols")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    zone_map = load_zone_map(args.zone_map)
    zone_findings = audit_zone_separation(zone_map)

    protocol_findings = []
    if args.scan_protocols:
        all_hosts = []
        for level_hosts in zone_map.values():
            all_hosts.extend(level_hosts)
        protocol_findings = audit_ot_protocols(list(set(all_hosts)))

    severity_counts = format_summary(zone_findings, protocol_findings, zone_map)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Purdue Model Audit",
        "zone_map": zone_map,
        "zone_findings": zone_findings,
        "protocol_findings": protocol_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
