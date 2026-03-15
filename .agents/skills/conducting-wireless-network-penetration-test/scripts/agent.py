#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Wireless Network Penetration Testing Agent - Tests WiFi security using Scapy and aircrack-ng."""

import json
import logging
import argparse
import subprocess
from datetime import datetime

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11Auth,
    sniff, RadioTap, sendp, conf,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def scan_access_points(interface, duration=30):
    """Scan for WiFi access points by capturing beacon frames."""
    access_points = {}

    def beacon_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if bssid not in access_points:
                ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
                stats = pkt[Dot11Beacon].network_stats()
                access_points[bssid] = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "channel": stats.get("channel", 0),
                    "crypto": list(stats.get("crypto", set())),
                    "signal": pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else None,
                }

    logger.info("Scanning for access points on %s for %ds", interface, duration)
    sniff(iface=interface, prn=beacon_handler, timeout=duration, store=False)
    logger.info("Discovered %d access points", len(access_points))
    return list(access_points.values())


def detect_rogue_aps(discovered_aps, known_ssids, known_bssids):
    """Detect rogue access points by comparing against known infrastructure."""
    rogues = []
    for ap in discovered_aps:
        if ap["ssid"] in known_ssids and ap["bssid"] not in known_bssids:
            ap["rogue_reason"] = "Known SSID with unknown BSSID (potential evil twin)"
            rogues.append(ap)
            logger.warning("ROGUE AP detected: SSID=%s BSSID=%s", ap["ssid"], ap["bssid"])
    return rogues


def detect_weak_encryption(access_points):
    """Identify access points using weak or no encryption."""
    weak = []
    for ap in access_points:
        crypto = ap.get("crypto", [])
        if not crypto or "OPN" in crypto:
            ap["weakness"] = "Open network - no encryption"
            weak.append(ap)
        elif "WEP" in str(crypto):
            ap["weakness"] = "WEP encryption - trivially crackable"
            weak.append(ap)
        elif "WPA" in str(crypto) and "WPA2" not in str(crypto):
            ap["weakness"] = "WPA1 only - vulnerable to TKIP attacks"
            weak.append(ap)
    logger.info("Found %d APs with weak encryption", len(weak))
    return weak


def capture_handshake(interface, target_bssid, channel, output_file, duration=60):
    """Capture WPA2 4-way handshake using airodump-ng."""
    set_channel_cmd = ["iwconfig", interface, "channel", str(channel)]
    subprocess.run(set_channel_cmd, capture_output=True)

    cmd = [
        "airodump-ng", "--bssid", target_bssid, "--channel", str(channel),
        "--write", output_file, "--output-format", "pcap",
        interface,
    ]
    logger.info("Capturing handshake for %s on channel %d", target_bssid, channel)
    try:
        subprocess.run(cmd, timeout=duration, capture_output=True)
    except subprocess.TimeoutExpired:
        pass
    return f"{output_file}-01.cap"


def send_deauth(interface, target_bssid, client_mac="FF:FF:FF:FF:FF:FF", count=5):
    """Send deauthentication frames to force client reconnection for handshake capture."""
    dot11 = Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid)
    frame = RadioTap() / dot11 / Dot11Auth(algo=0, seqnum=1, status=0)
    sendp(frame, iface=interface, count=count, inter=0.1, verbose=False)
    logger.info("Sent %d deauth frames to %s (client: %s)", count, target_bssid, client_mac)


def crack_handshake(cap_file, wordlist):
    """Attempt to crack WPA2 handshake using aircrack-ng."""
    cmd = ["aircrack-ng", "-w", wordlist, "-b", "target_bssid", cap_file]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if "KEY FOUND" in result.stdout:
        key_line = [l for l in result.stdout.split("\n") if "KEY FOUND" in l]
        if key_line:
            logger.info("WPA2 key cracked: %s", key_line[0])
            return {"cracked": True, "key": key_line[0]}
    return {"cracked": False}


def detect_client_probes(interface, duration=30):
    """Capture probe requests to identify client-side vulnerabilities."""
    probes = []

    def probe_handler(pkt):
        if pkt.haslayer(Dot11ProbeReq):
            ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore") if pkt.haslayer(Dot11Elt) else ""
            if ssid:
                probes.append({
                    "client_mac": pkt[Dot11].addr2,
                    "probed_ssid": ssid,
                })

    sniff(iface=interface, prn=probe_handler, timeout=duration, store=False)
    unique_clients = len(set(p["client_mac"] for p in probes))
    logger.info("Captured %d probe requests from %d clients", len(probes), unique_clients)
    return probes


def check_wps_enabled(interface, target_bssid):
    """Check if WPS is enabled on target AP using wash."""
    cmd = ["wash", "-i", interface, "-C"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if target_bssid.upper() in result.stdout.upper():
            logger.warning("WPS enabled on %s - vulnerable to Reaver attack", target_bssid)
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return False


def generate_report(access_points, rogues, weak_crypto, client_probes):
    """Generate wireless penetration test report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "access_points": access_points,
        "rogue_aps": rogues,
        "weak_encryption": weak_crypto,
        "client_probes": client_probes[:50],
        "summary": {
            "total_aps": len(access_points),
            "rogue_aps": len(rogues),
            "weak_crypto_aps": len(weak_crypto),
            "clients_probing": len(set(p["client_mac"] for p in client_probes)),
        },
    }
    print(f"WIRELESS PENTEST REPORT: {len(access_points)} APs, {len(rogues)} rogues, {len(weak_crypto)} weak")
    return report


def main():
    parser = argparse.ArgumentParser(description="Wireless Network Penetration Testing Agent")
    parser.add_argument("--interface", required=True, help="Wireless interface in monitor mode")
    parser.add_argument("--duration", type=int, default=30, help="Scan duration in seconds")
    parser.add_argument("--known-ssids", nargs="*", default=[], help="Known legitimate SSIDs")
    parser.add_argument("--known-bssids", nargs="*", default=[], help="Known legitimate BSSIDs")
    parser.add_argument("--output", default="wireless_pentest_report.json")
    args = parser.parse_args()

    aps = scan_access_points(args.interface, args.duration)
    rogues = detect_rogue_aps(aps, set(args.known_ssids), set(args.known_bssids))
    weak = detect_weak_encryption(aps)
    probes = detect_client_probes(args.interface, args.duration)

    report = generate_report(aps, rogues, weak, probes)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
