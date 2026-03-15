#!/usr/bin/env python3
"""Agent for wireless security assessment with Kismet.

Interfaces with Kismet's REST API for device enumeration,
rogue AP detection, channel analysis, and wireless threat
monitoring during security assessments.
"""

import requests
import json
import sys
from datetime import datetime
from collections import defaultdict


class KismetAssessmentAgent:
    """Uses Kismet REST API for wireless security assessment."""

    def __init__(self, kismet_url="http://localhost:2501",
                 api_key=None, username="kismet", password="kismet"):
        self.base_url = kismet_url.rstrip("/")
        self.session = requests.Session()
        if api_key:
            self.session.cookies.set("KISMET", api_key)
        else:
            self.session.post(f"{self.base_url}/session/check_login",
                              json={"username": username, "password": password})
        self.findings = []

    def _get(self, endpoint, params=None):
        resp = self.session.get(f"{self.base_url}{endpoint}",
                                params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint, data=None):
        resp = self.session.post(f"{self.base_url}{endpoint}",
                                 json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_system_status(self):
        """Get Kismet server status."""
        return self._get("/system/status.json")

    def get_all_devices(self, limit=500):
        """Retrieve all detected wireless devices."""
        return self._post("/devices/summary/devices.json",
                          data={"fields": [
                              "kismet.device.base.macaddr",
                              "kismet.device.base.name",
                              "kismet.device.base.type",
                              "kismet.device.base.manuf",
                              "kismet.device.base.channel",
                              "kismet.device.base.frequency",
                              "kismet.device.base.signal/kismet.common.signal.last_signal",
                              "kismet.device.base.crypt",
                              "kismet.device.base.first_time",
                              "kismet.device.base.last_time",
                          ], "limit": limit})

    def get_access_points(self):
        """Get all detected access points (802.11 AP type)."""
        devices = self.get_all_devices(limit=1000)
        aps = [d for d in devices if d.get("kismet.device.base.type") == "Wi-Fi AP"]
        return aps

    def detect_rogue_aps(self, authorized_bssids=None, authorized_ssids=None):
        """Identify rogue access points not in the authorized list."""
        authorized_bssids = set(b.upper() for b in (authorized_bssids or []))
        authorized_ssids = set(authorized_ssids or [])
        aps = self.get_access_points()
        rogues = []

        for ap in aps:
            bssid = ap.get("kismet.device.base.macaddr", "").upper()
            ssid = ap.get("kismet.device.base.name", "")

            if authorized_bssids and bssid not in authorized_bssids:
                rogues.append({"bssid": bssid, "ssid": ssid, "reason": "Unknown BSSID"})
            elif authorized_ssids and ssid in authorized_ssids and bssid not in authorized_bssids:
                rogues.append({"bssid": bssid, "ssid": ssid,
                               "reason": "Known SSID from unauthorized BSSID (Evil Twin)"})

        if rogues:
            self.findings.extend([
                {"type": "Rogue AP Detected", "severity": "Critical", **r}
                for r in rogues
            ])
        return rogues

    def analyze_encryption(self):
        """Analyze encryption types across detected APs."""
        aps = self.get_access_points()
        encryption_stats = defaultdict(int)
        weak_aps = []

        for ap in aps:
            crypt = ap.get("kismet.device.base.crypt", "unknown")
            encryption_stats[crypt] += 1
            if crypt in ("None", "WEP", ""):
                weak_aps.append({
                    "bssid": ap.get("kismet.device.base.macaddr", ""),
                    "ssid": ap.get("kismet.device.base.name", ""),
                    "encryption": crypt or "Open",
                })
                self.findings.append({
                    "type": "Weak Encryption", "severity": "High",
                    "bssid": ap.get("kismet.device.base.macaddr", ""),
                    "encryption": crypt or "Open",
                })
        return {"stats": dict(encryption_stats), "weak_aps": weak_aps}

    def analyze_channels(self):
        """Analyze channel utilization."""
        aps = self.get_access_points()
        channel_counts = defaultdict(int)
        for ap in aps:
            ch = ap.get("kismet.device.base.channel", "unknown")
            channel_counts[str(ch)] += 1
        return dict(channel_counts)

    def generate_report(self):
        enc = self.analyze_encryption()
        channels = self.analyze_channels()
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "kismet_url": self.base_url,
            "encryption_analysis": enc,
            "channel_utilization": channels,
            "findings": self.findings,
        }
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:2501"
    api_key = sys.argv[2] if len(sys.argv) > 2 else None
    agent = KismetAssessmentAgent(url, api_key=api_key)
    agent.generate_report()


if __name__ == "__main__":
    main()
