#!/usr/bin/env python3
"""ARP poisoning detection agent for network traffic analysis."""

import json
import sys
import argparse
import subprocess
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import rdpcap, ARP, Ether
except ImportError:
    rdpcap = None


def analyze_pcap_arp(pcap_path):
    """Analyze PCAP file for ARP poisoning indicators."""
    if rdpcap is None:
        return [{"error": "Install scapy: pip install scapy"}]

    packets = rdpcap(pcap_path)
    arp_packets = [p for p in packets if ARP in p]

    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    gratuitous_arps = []
    arp_replies = []

    for pkt in arp_packets:
        arp = pkt[ARP]
        if arp.op == 2:  # ARP reply
            ip_to_macs[arp.psrc].add(arp.hwsrc)
            mac_to_ips[arp.hwsrc].add(arp.psrc)
            arp_replies.append({
                "src_mac": arp.hwsrc,
                "src_ip": arp.psrc,
                "dst_mac": arp.hwdst,
                "dst_ip": arp.pdst,
            })
        if arp.op == 2 and arp.pdst == arp.psrc:
            gratuitous_arps.append({
                "mac": arp.hwsrc,
                "ip": arp.psrc,
            })

    return {
        "total_arp_packets": len(arp_packets),
        "arp_replies": len(arp_replies),
        "gratuitous_arps": len(gratuitous_arps),
        "ip_to_macs": {ip: list(macs) for ip, macs in ip_to_macs.items()},
        "mac_to_ips": {mac: list(ips) for mac, ips in mac_to_ips.items()},
    }


def detect_arp_spoofing(arp_data):
    """Detect ARP spoofing from analyzed ARP traffic."""
    findings = []
    ip_to_macs = arp_data.get("ip_to_macs", {})
    mac_to_ips = arp_data.get("mac_to_ips", {})

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append({
                "indicator": "duplicate_mac_for_ip",
                "ip": ip,
                "macs": macs,
                "issue": f"IP {ip} associated with {len(macs)} different MACs — ARP spoofing likely",
                "severity": "CRITICAL",
            })

    for mac, ips in mac_to_ips.items():
        if len(ips) > 3:
            findings.append({
                "indicator": "mac_claiming_many_ips",
                "mac": mac,
                "ips": ips,
                "issue": f"MAC {mac} claims {len(ips)} IPs — possible ARP poisoning",
                "severity": "HIGH",
            })

    if arp_data.get("gratuitous_arps", 0) > 10:
        findings.append({
            "indicator": "excessive_gratuitous_arp",
            "count": arp_data["gratuitous_arps"],
            "issue": f"Excessive gratuitous ARPs ({arp_data['gratuitous_arps']}) — suspicious",
            "severity": "MEDIUM",
        })

    return findings


def check_arp_table():
    """Read current system ARP table and check for duplicates."""
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split("\n")
    except Exception as e:
        return {"error": str(e)}

    ip_mac_map = {}
    duplicates = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            ip = parts[0].strip("()")
            mac = parts[1] if ":" in parts[1] else (parts[3] if len(parts) > 3 and "-" in parts[3] else "")
            if mac and ip in ip_mac_map and ip_mac_map[ip] != mac:
                duplicates.append({
                    "ip": ip,
                    "mac_1": ip_mac_map[ip],
                    "mac_2": mac,
                    "issue": "Duplicate IP with different MACs in ARP table",
                    "severity": "CRITICAL",
                })
            if mac:
                ip_mac_map[ip] = mac

    return {"entries": len(ip_mac_map), "duplicates": duplicates}


def check_arpwatch_log(log_path="/var/lib/arpwatch/arp.dat"):
    """Parse arpwatch database for flip-flop entries."""
    entries = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    entries.append({
                        "mac": parts[0],
                        "ip": parts[1],
                        "timestamp": parts[2] if len(parts) > 2 else "",
                        "hostname": parts[3] if len(parts) > 3 else "",
                    })
    except FileNotFoundError:
        return {"error": f"arpwatch database not found at {log_path}"}
    except Exception as e:
        return {"error": str(e)}

    ip_history = defaultdict(list)
    for e in entries:
        ip_history[e["ip"]].append(e["mac"])

    flip_flops = {ip: macs for ip, macs in ip_history.items() if len(set(macs)) > 1}
    return {"total_entries": len(entries), "flip_flops": flip_flops}


def run_audit(args):
    """Execute ARP poisoning detection audit."""
    print(f"\n{'='*60}")
    print(f"  ARP POISONING DETECTION AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.pcap:
        arp_data = analyze_pcap_arp(args.pcap)
        report["arp_analysis"] = arp_data
        print(f"--- ARP TRAFFIC ANALYSIS ---")
        print(f"  Total ARP packets: {arp_data.get('total_arp_packets', 0)}")
        print(f"  ARP replies: {arp_data.get('arp_replies', 0)}")
        print(f"  Gratuitous ARPs: {arp_data.get('gratuitous_arps', 0)}")

        findings = detect_arp_spoofing(arp_data)
        report["findings"] = findings
        print(f"\n--- SPOOFING FINDINGS ({len(findings)}) ---")
        for f in findings:
            print(f"  [{f['severity']}] {f['issue']}")

    if args.check_table:
        table = check_arp_table()
        report["arp_table"] = table
        print(f"\n--- SYSTEM ARP TABLE ---")
        print(f"  Entries: {table.get('entries', 0)}")
        dups = table.get("duplicates", [])
        if dups:
            print(f"  DUPLICATES FOUND: {len(dups)}")
            for d in dups:
                print(f"    [{d['severity']}] {d['ip']}: {d['mac_1']} vs {d['mac_2']}")

    if args.arpwatch_db:
        aw = check_arpwatch_log(args.arpwatch_db)
        report["arpwatch"] = aw
        print(f"\n--- ARPWATCH DATABASE ---")
        ff = aw.get("flip_flops", {})
        print(f"  Flip-flop entries: {len(ff)}")
        for ip, macs in list(ff.items())[:10]:
            print(f"    {ip}: {macs}")

    return report


def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Detection Agent")
    parser.add_argument("--pcap", help="PCAP file to analyze for ARP spoofing")
    parser.add_argument("--check-table", action="store_true", help="Check system ARP table")
    parser.add_argument("--arpwatch-db", help="Path to arpwatch database")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
