---
name: detecting-attacks-on-historian-servers
description: >
  Detect cyber attacks targeting OT historian servers (OSIsoft PI, Ignition,
  Wonderware) that sit at the IT/OT boundary and serve as pivot points for
  lateral movement between enterprise and control networks, including data
  manipulation, unauthorized queries, and exploitation of historian-specific
  vulnerabilities.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, historian, osisoft-pi, ignition, pivot-point, data-integrity, lateral-movement]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Attacks on Historian Servers

## When to Use

- When monitoring historian servers that bridge IT and OT networks for compromise indicators
- When detecting unauthorized queries or data manipulation in process historian databases
- When investigating lateral movement through historian servers between IT and OT zones
- When responding to alerts about exploitation of historian-specific vulnerabilities (CVE-2025-0921)
- When validating historian data integrity after a suspected OT security incident

**Do not use** for general database security monitoring (see database security skills), for historian deployment and configuration, or for IT-only data warehouse security.

## Prerequisites

- Historian server inventory (OSIsoft PI, Ignition, GE Proficy, Wonderware InSQL)
- Network monitoring on historian network segments (both IT-facing and OT-facing interfaces)
- Historian API access for data integrity validation
- Baseline of normal historian query patterns (which applications query which tags)
- Understanding of historian architecture (data sources, interfaces, client connections)

## Workflow

### Step 1: Monitor Historian for Attack Indicators

```python
#!/usr/bin/env python3
"""OT Historian Attack Detector.

Monitors historian servers for unauthorized access, data manipulation,
lateral movement indicators, and exploitation of historian-specific
vulnerabilities. Supports OSIsoft PI and Ignition platforms.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


class HistorianAttackDetector:
    """Detects attacks targeting OT historian servers."""

    def __init__(self, historian_type: str, historian_url: str,
                 api_credentials: dict, verify_ssl: bool = False):
        self.historian_type = historian_type
        self.historian_url = historian_url.rstrip("/")
        self.credentials = api_credentials
        self.verify_ssl = verify_ssl
        self.alerts = []
        self.authorized_clients = set()
        self.authorized_queries = {}

    def set_baseline(self, authorized_clients: List[str],
                     authorized_query_patterns: Dict[str, List[str]]):
        """Set baseline of authorized historian clients and query patterns."""
        self.authorized_clients = set(authorized_clients)
        self.authorized_queries = authorized_query_patterns

    def check_active_connections(self) -> List[dict]:
        """Check for unauthorized connections to historian."""
        connections = []

        if self.historian_type == "osisoft_pi":
            try:
                resp = requests.get(
                    f"{self.historian_url}/piwebapi/system/status",
                    auth=(self.credentials.get("username"), self.credentials.get("password")),
                    verify=self.verify_ssl,
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    connections = data.get("ConnectedClients", [])
            except requests.RequestException as e:
                print(f"[!] PI Web API error: {e}")

        elif self.historian_type == "ignition":
            try:
                resp = requests.get(
                    f"{self.historian_url}/data/status/connections",
                    headers={"Authorization": f"Bearer {self.credentials.get('token')}"},
                    verify=self.verify_ssl,
                    timeout=10,
                )
                if resp.status_code == 200:
                    connections = resp.json().get("connections", [])
            except requests.RequestException as e:
                print(f"[!] Ignition API error: {e}")

        # Check for unauthorized clients
        for conn in connections:
            client_ip = conn.get("client_ip", conn.get("address", ""))
            if self.authorized_clients and client_ip not in self.authorized_clients:
                self.alerts.append({
                    "severity": "HIGH",
                    "type": "UNAUTHORIZED_HISTORIAN_CLIENT",
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": client_ip,
                    "details": f"Unauthorized client {client_ip} connected to {self.historian_type} historian",
                    "mitre": "T0802 - Automated Collection",
                })

        return connections

    def check_data_integrity(self, tags: List[str], hours_back: int = 24):
        """Check historian data for manipulation indicators."""
        print(f"[*] Checking data integrity for {len(tags)} tags over last {hours_back}h")

        integrity_issues = []
        for tag in tags:
            try:
                if self.historian_type == "osisoft_pi":
                    resp = requests.get(
                        f"{self.historian_url}/piwebapi/streams/{tag}/recorded",
                        params={"startTime": f"*-{hours_back}h", "endTime": "*"},
                        auth=(self.credentials.get("username"), self.credentials.get("password")),
                        verify=self.verify_ssl,
                        timeout=15,
                    )
                    if resp.status_code == 200:
                        items = resp.json().get("Items", [])
                        # Check for suspicious patterns
                        if len(items) == 0:
                            integrity_issues.append({
                                "tag": tag, "issue": "NO_DATA",
                                "detail": "No data points in expected timeframe - possible deletion",
                            })
                        else:
                            values = [i.get("Value", 0) for i in items if isinstance(i.get("Value"), (int, float))]
                            if values and len(set(values)) == 1 and len(values) > 100:
                                integrity_issues.append({
                                    "tag": tag, "issue": "FLATLINE",
                                    "detail": f"Constant value {values[0]} for {len(values)} points - possible replay/spoofing",
                                })
            except requests.RequestException:
                pass

        for issue in integrity_issues:
            self.alerts.append({
                "severity": "HIGH",
                "type": f"DATA_INTEGRITY_{issue['issue']}",
                "timestamp": datetime.now().isoformat(),
                "tag": issue["tag"],
                "details": issue["detail"],
                "mitre": "T0809 - Data Destruction" if issue["issue"] == "NO_DATA" else "T0832 - Manipulation of View",
            })

        return integrity_issues

    def check_lateral_movement_indicators(self):
        """Check for indicators of historian being used as pivot point."""
        indicators = []

        # Check 1: Historian making outbound connections to Level 1 devices
        # (Historian should receive data, not initiate connections to PLCs)
        indicators.append({
            "check": "Outbound connections to PLC subnets",
            "description": "Historian initiating connections to Level 1 devices may indicate compromise",
            "detection": "Monitor firewall logs for historian IP connecting to PLC ports (502, 102, 44818)",
        })

        # Check 2: New processes or services on historian
        indicators.append({
            "check": "Unauthorized processes on historian server",
            "description": "Attackers may install tools on historian for lateral movement",
            "detection": "Monitor process creation events (Sysmon EventID 1) on historian",
        })

        # Check 3: Unusual authentication to historian
        indicators.append({
            "check": "Authentication from unexpected sources",
            "description": "Compromised IT systems authenticating to historian for pivoting",
            "detection": "Monitor Windows Security Event 4624 for logons from non-baseline sources",
        })

        return indicators

    def generate_report(self):
        """Generate historian attack detection report."""
        print(f"\n{'='*70}")
        print("HISTORIAN ATTACK DETECTION REPORT")
        print(f"{'='*70}")
        print(f"Historian Type: {self.historian_type}")
        print(f"Historian URL: {self.historian_url}")
        print(f"Report Time: {datetime.now().isoformat()}")
        print(f"Total Alerts: {len(self.alerts)}")

        if self.alerts:
            print(f"\n--- ALERTS ---")
            for alert in self.alerts:
                print(f"\n  [{alert['severity']}] {alert['type']}")
                print(f"    Time: {alert['timestamp']}")
                print(f"    Detail: {alert['details']}")
                print(f"    MITRE ICS: {alert.get('mitre', 'N/A')}")

        print(f"\n--- LATERAL MOVEMENT CHECKS ---")
        for indicator in self.check_lateral_movement_indicators():
            print(f"\n  Check: {indicator['check']}")
            print(f"    Risk: {indicator['description']}")
            print(f"    Detection: {indicator['detection']}")


if __name__ == "__main__":
    detector = HistorianAttackDetector(
        historian_type="osisoft_pi",
        historian_url="https://pi-server.plant.local",
        api_credentials={"username": "pi_reader", "password": "api_key_here"},
    )

    detector.set_baseline(
        authorized_clients=["10.10.2.10", "10.10.2.20", "10.10.3.50", "10.10.150.10"],
        authorized_query_patterns={},
    )

    detector.check_active_connections()
    detector.check_data_integrity(tags=["REACTOR_01.TEMP", "PUMP_03.FLOW"], hours_back=24)
    detector.generate_report()
```

## Key Concepts

| Term | Definition |
|------|------------|
| OT Historian | Database server (OSIsoft PI, Ignition, Wonderware) storing time-series process data from SCADA/DCS systems |
| Pivot Point | Historian's position between IT and OT networks makes it a prime target for attackers to move between zones |
| Data Replay Attack | Feeding historical data to an HMI to mask real-time process manipulation (Stuxnet technique) |
| OSIsoft PI | Most widely deployed OT historian, used by 65% of Global 500 process companies |
| Ignition | Inductive Automation SCADA platform with historian module, increasingly targeted due to Python scripting capabilities |
| CVE-2025-0921 | Ignition SCADA privileged file system vulnerability allowing escalation through malicious project files |

## Output Format

```
HISTORIAN ATTACK DETECTION REPORT
====================================
Historian: [type and hostname]
Date: YYYY-MM-DD

CONNECTION ANALYSIS:
  Authorized Clients: [count]
  Unauthorized Clients Detected: [count with IPs]

DATA INTEGRITY:
  Tags Checked: [count]
  Integrity Issues: [count]
  Flatline Detections: [count]
  Data Gaps: [count]

LATERAL MOVEMENT INDICATORS:
  Outbound PLC Connections: [found/not found]
  Unauthorized Processes: [found/not found]
  Anomalous Authentication: [found/not found]
```
