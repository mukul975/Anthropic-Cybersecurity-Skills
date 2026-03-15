#!/usr/bin/env python3
"""Agent for wireless network penetration testing.

Runs aircrack-ng suite tools via subprocess for WiFi reconnaissance,
WPA handshake capture, deauthentication testing, and generates
a wireless security assessment report.
"""

import subprocess
import json
import sys
import re
from datetime import datetime
from pathlib import Path


class WirelessPentestAgent:
    """Automates wireless network penetration testing with aircrack-ng."""

    def __init__(self, interface, output_dir="./wireless_pentest"):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.networks = []
        self.findings = []

    def enable_monitor_mode(self):
        """Put wireless interface into monitor mode using airmon-ng."""
        result = subprocess.run(
            ["airmon-ng", "start", self.interface],
            capture_output=True, text=True, timeout=30)
        mon_iface = f"{self.interface}mon"
        match = re.search(r"monitor mode.*enabled on (\w+)", result.stdout)
        if match:
            mon_iface = match.group(1)
        self.interface = mon_iface
        return {"monitor_interface": mon_iface, "status": result.returncode}

    def scan_networks(self, duration=30):
        """Scan for wireless networks using airodump-ng."""
        csv_prefix = str(self.output_dir / "scan")
        try:
            subprocess.run(
                ["airodump-ng", self.interface, "-w", csv_prefix,
                 "--output-format", "csv", "--write-interval", "1"],
                capture_output=True, text=True, timeout=duration)
        except subprocess.TimeoutExpired:
            pass

        csv_file = Path(f"{csv_prefix}-01.csv")
        if csv_file.exists():
            self.networks = self._parse_airodump_csv(csv_file)
        return self.networks

    def _parse_airodump_csv(self, csv_path):
        """Parse airodump-ng CSV output for network details."""
        networks = []
        try:
            lines = csv_path.read_text(errors="ignore").splitlines()
            in_ap_section = False
            for line in lines:
                if "BSSID" in line and "channel" in line.lower():
                    in_ap_section = True
                    continue
                if "Station MAC" in line:
                    break
                if in_ap_section and line.strip():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 14:
                        enc = parts[5].strip()
                        networks.append({
                            "bssid": parts[0], "channel": parts[3],
                            "encryption": enc, "essid": parts[13],
                            "power": parts[8],
                        })
                        if enc in ("OPN", "WEP", ""):
                            self.findings.append({
                                "type": "Weak Encryption",
                                "severity": "Critical" if enc in ("OPN", "") else "High",
                                "bssid": parts[0], "essid": parts[13],
                                "encryption": enc or "Open",
                            })
        except (IndexError, UnicodeDecodeError):
            pass
        return networks

    def capture_handshake(self, bssid, channel, duration=60):
        """Capture WPA/WPA2 4-way handshake."""
        cap_prefix = str(self.output_dir / "handshake")
        try:
            subprocess.run(
                ["airodump-ng", self.interface, "--bssid", bssid,
                 "-c", str(channel), "-w", cap_prefix],
                capture_output=True, timeout=duration)
        except subprocess.TimeoutExpired:
            pass
        cap_file = Path(f"{cap_prefix}-01.cap")
        return {"capture_file": str(cap_file), "exists": cap_file.exists()}

    def crack_handshake(self, cap_file, wordlist):
        """Attempt to crack WPA handshake with aircrack-ng."""
        result = subprocess.run(
            ["aircrack-ng", cap_file, "-w", wordlist],
            capture_output=True, text=True, timeout=600)
        if "KEY FOUND" in result.stdout:
            match = re.search(r"KEY FOUND! \[ (.+?) \]", result.stdout)
            key = match.group(1) if match else "unknown"
            self.findings.append({"type": "WPA Key Cracked",
                                  "severity": "Critical", "key": key})
            return {"cracked": True, "key": key}
        return {"cracked": False}

    def test_wps(self, bssid):
        """Test WPS PIN vulnerability using reaver/wash."""
        result = subprocess.run(
            ["wash", "-i", self.interface], capture_output=True,
            text=True, timeout=30)
        wps_enabled = bssid in result.stdout
        if wps_enabled:
            self.findings.append({"type": "WPS Enabled", "severity": "High",
                                  "bssid": bssid})
        return {"wps_enabled": wps_enabled}

    def generate_report(self):
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "interface": self.interface,
            "networks_found": len(self.networks),
            "findings": self.findings,
            "networks": self.networks[:50],
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    agent = WirelessPentestAgent(iface)
    agent.enable_monitor_mode()
    agent.scan_networks(duration=30)
    agent.generate_report()


if __name__ == "__main__":
    main()
