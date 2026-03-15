---
name: detecting-dnp3-protocol-anomalies
description: >
  Detect anomalies in DNP3 (Distributed Network Protocol 3) communications
  used in SCADA systems by monitoring for unauthorized control commands,
  firmware update attempts, protocol violations, and deviations from baseline
  traffic patterns using deep packet inspection and machine learning approaches.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, dnp3, scada, anomaly-detection, protocol-analysis, energy-sector, ids]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting DNP3 Protocol Anomalies

## When to Use

- When monitoring SCADA systems in the energy sector where DNP3 is the primary protocol
- When building detection rules for DNP3-based attacks against RTUs and substations
- When investigating suspected unauthorized control commands sent via DNP3
- When deploying IDS with DNP3 deep packet inspection at utility substations
- When responding to alerts from OT monitoring platforms about DNP3 traffic anomalies

**Do not use** for non-DNP3 protocol monitoring (see detecting-modbus-command-injection-attacks for Modbus), for DNP3 Secure Authentication configuration (separate implementation), or for protocol-agnostic network anomaly detection.

## Prerequisites

- Network TAP/SPAN on DNP3 communication segments (TCP port 20000 or serial)
- Baseline of normal DNP3 traffic patterns (masters, outstations, poll intervals, function codes)
- Suricata or Zeek with DNP3 protocol parser enabled
- Understanding of DNP3 function codes and object groups used in the environment
- DNP3 communication topology map (master-to-outstation relationships)

## Workflow

### Step 1: Analyze DNP3 Traffic for Anomalies

```python
#!/usr/bin/env python3
"""DNP3 Protocol Anomaly Detector.

Monitors DNP3 communications for unauthorized control commands,
protocol violations, and deviations from established baselines.
Supports both TCP and serial DNP3 deployments.
"""

import struct
import sys
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set

try:
    from scapy.all import rdpcap, IP, TCP
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)


# DNP3 Function Codes
DNP3_FUNCTIONS = {
    0x00: "Confirm", 0x01: "Read", 0x02: "Write",
    0x03: "Select", 0x04: "Operate", 0x05: "Direct Operate",
    0x06: "Direct Operate No Ack", 0x07: "Immediate Freeze",
    0x08: "Immediate Freeze No Ack", 0x09: "Freeze and Clear",
    0x0A: "Freeze and Clear No Ack", 0x0B: "Freeze at Time",
    0x0C: "Freeze at Time No Ack", 0x0D: "Cold Restart",
    0x0E: "Warm Restart", 0x0F: "Initialize Data",
    0x10: "Initialize Application", 0x11: "Start Application",
    0x12: "Stop Application", 0x13: "Save Configuration",
    0x14: "Enable Unsolicited", 0x15: "Disable Unsolicited",
    0x16: "Assign Class", 0x17: "Delay Measurement",
    0x18: "Record Current Time", 0x19: "Open File",
    0x1A: "Close File", 0x1B: "Delete File",
    0x1C: "Get File Info", 0x1D: "Authenticate File",
    0x1E: "Abort File", 0x81: "Response", 0x82: "Unsolicited Response",
}

# High-risk function codes that should trigger alerts
DNP3_CRITICAL_FUNCTIONS = {
    0x02,  # Write
    0x03, 0x04, 0x05, 0x06,  # Select/Operate/Direct Operate
    0x0D,  # Cold Restart
    0x0E,  # Warm Restart
    0x0F,  # Initialize Data
    0x10,  # Initialize Application
    0x12,  # Stop Application
    0x19, 0x1A, 0x1B,  # File operations (firmware update)
}


class DNP3AnomalyDetector:
    """Detects anomalies in DNP3 protocol communications."""

    def __init__(self, baseline_file: Optional[str] = None):
        self.alerts = []
        self.sessions = defaultdict(lambda: {
            "packet_count": 0,
            "function_codes": defaultdict(int),
            "control_commands": 0,
            "file_operations": 0,
            "restarts": 0,
        })
        self.packet_count = 0
        self.dnp3_count = 0

        self.authorized_masters: Set[str] = set()
        self.authorized_pairs: Dict[str, Set[str]] = defaultdict(set)
        self.baseline_functions: Dict[str, Set[int]] = defaultdict(set)

        if baseline_file:
            self.load_baseline(baseline_file)

    def load_baseline(self, filepath: str):
        """Load DNP3 communication baseline."""
        with open(filepath, "r") as f:
            baseline = json.load(f)

        for entry in baseline.get("authorized_communications", []):
            master = entry["master_ip"]
            outstation = entry["outstation_ip"]
            self.authorized_masters.add(master)
            self.authorized_pairs[master].add(outstation)
            self.baseline_functions[f"{master}->{outstation}"] = set(
                entry.get("expected_function_codes", [0x00, 0x01])
            )

    def parse_dnp3_header(self, payload: bytes) -> Optional[dict]:
        """Parse DNP3 data link layer and transport/application headers."""
        if len(payload) < 10:
            return None

        # DNP3 Data Link Layer: start(2) + length(1) + control(1) + dest(2) + source(2) + crc(2)
        start_bytes = struct.unpack(">H", payload[0:2])[0]
        if start_bytes != 0x0564:
            return None

        length = payload[2]
        control = payload[3]
        dest_addr = struct.unpack("<H", payload[4:6])[0]
        source_addr = struct.unpack("<H", payload[6:8])[0]

        direction = "Master->Outstation" if (control & 0x80) else "Outstation->Master"

        result = {
            "length": length,
            "control": control,
            "direction": direction,
            "dest_addr": dest_addr,
            "source_addr": source_addr,
            "is_master": bool(control & 0x80),
        }

        # Parse transport and application layer (after CRC bytes)
        if len(payload) >= 12:
            transport_header = payload[10]
            if len(payload) >= 13:
                app_control = payload[11]
                func_code = payload[12]
                result["function_code"] = func_code
                result["function_name"] = DNP3_FUNCTIONS.get(
                    func_code, f"Unknown (0x{func_code:02x})"
                )

        return result

    def analyze_packet(self, pkt):
        """Analyze a packet for DNP3 anomalies."""
        self.packet_count += 1

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        if tcp.dport != 20000 and tcp.sport != 20000:
            return

        payload = bytes(tcp.payload)
        if not payload:
            return

        dnp3 = self.parse_dnp3_header(payload)
        if not dnp3:
            return

        self.dnp3_count += 1
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        session_key = f"{src_ip}->{dst_ip}"
        session = self.sessions[session_key]
        session["packet_count"] += 1

        func_code = dnp3.get("function_code")
        if func_code is not None:
            session["function_codes"][func_code] += 1

            # Detection 1: Unauthorized DNP3 master
            if dnp3.get("is_master") and self.authorized_masters:
                if src_ip not in self.authorized_masters:
                    self.alerts.append({
                        "severity": "CRITICAL",
                        "type": "UNAUTHORIZED_DNP3_MASTER",
                        "src": src_ip, "dst": dst_ip,
                        "function": dnp3.get("function_name"),
                        "description": f"Unauthorized DNP3 master {src_ip} communicating with outstation {dst_ip}",
                        "mitre": "T0869 - Standard Application Layer Protocol",
                    })

            # Detection 2: Cold/Warm restart command
            if func_code in (0x0D, 0x0E):
                session["restarts"] += 1
                restart_type = "Cold" if func_code == 0x0D else "Warm"
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "DNP3_RESTART_COMMAND",
                    "src": src_ip, "dst": dst_ip,
                    "function": f"{restart_type} Restart",
                    "description": f"{restart_type} restart command sent to outstation {dst_ip} (addr {dnp3['dest_addr']})",
                    "mitre": "T0816 - Device Restart/Shutdown",
                })

            # Detection 3: File operations (potential firmware update)
            if func_code in (0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E):
                session["file_operations"] += 1
                self.alerts.append({
                    "severity": "CRITICAL",
                    "type": "DNP3_FILE_OPERATION",
                    "src": src_ip, "dst": dst_ip,
                    "function": dnp3.get("function_name"),
                    "description": f"File operation on outstation {dst_ip} - potential firmware update or PIPEDREAM indicator",
                    "mitre": "T0839 - Module Firmware",
                })

            # Detection 4: Control commands (Select/Operate)
            if func_code in (0x03, 0x04, 0x05, 0x06):
                session["control_commands"] += 1
                if session_key in self.baseline_functions:
                    if func_code not in self.baseline_functions[session_key]:
                        self.alerts.append({
                            "severity": "HIGH",
                            "type": "UNEXPECTED_CONTROL_COMMAND",
                            "src": src_ip, "dst": dst_ip,
                            "function": dnp3.get("function_name"),
                            "description": f"Control command {dnp3.get('function_name')} not in baseline for {session_key}",
                            "mitre": "T0855 - Unauthorized Command Message",
                        })

            # Detection 5: Anomalous function code for this pair
            if session_key in self.baseline_functions:
                if func_code not in self.baseline_functions[session_key]:
                    if func_code not in (0x00, 0x81, 0x82):  # Exclude common response codes
                        self.alerts.append({
                            "severity": "MEDIUM",
                            "type": "ANOMALOUS_FUNCTION_CODE",
                            "src": src_ip, "dst": dst_ip,
                            "function": dnp3.get("function_name"),
                            "description": f"Function code 0x{func_code:02x} not in baseline",
                            "mitre": "T0855 - Unauthorized Command Message",
                        })

    def generate_report(self):
        """Generate DNP3 anomaly detection report."""
        print(f"\n{'='*70}")
        print("DNP3 PROTOCOL ANOMALY DETECTION REPORT")
        print(f"{'='*70}")
        print(f"Analysis Time: {datetime.now().isoformat()}")
        print(f"Total Packets: {self.packet_count}")
        print(f"DNP3 Packets: {self.dnp3_count}")
        print(f"Alerts: {len(self.alerts)}")

        print(f"\n--- DNP3 SESSION SUMMARY ---")
        for key, session in self.sessions.items():
            print(f"\n  {key}")
            print(f"    Packets: {session['packet_count']}")
            funcs = [DNP3_FUNCTIONS.get(f, f"0x{f:02x}") for f in session["function_codes"]]
            print(f"    Functions: {', '.join(funcs)}")
            print(f"    Control Commands: {session['control_commands']}")
            print(f"    File Operations: {session['file_operations']}")
            print(f"    Restart Commands: {session['restarts']}")

        if self.alerts:
            print(f"\n--- ALERTS ---")
            for alert in self.alerts:
                print(f"\n  [{alert['severity']}] {alert['type']}")
                print(f"    {alert['src']} -> {alert['dst']}")
                print(f"    Function: {alert['function']}")
                print(f"    Detail: {alert['description']}")
                print(f"    MITRE ICS: {alert.get('mitre', 'N/A')}")


if __name__ == "__main__":
    detector = DNP3AnomalyDetector(
        baseline_file=sys.argv[2] if len(sys.argv) > 2 else None
    )

    if len(sys.argv) >= 2:
        print(f"[*] Analyzing: {sys.argv[1]}")
        packets = rdpcap(sys.argv[1])
        for pkt in packets:
            detector.analyze_packet(pkt)
        detector.generate_report()
    else:
        print("Usage: python dnp3_detector.py <capture.pcap> [baseline.json]")
```

## Key Concepts

| Term | Definition |
|------|------------|
| DNP3 | Distributed Network Protocol version 3, the predominant SCADA protocol in the energy sector for communication between masters and outstations |
| Outstation | DNP3 slave device (typically an RTU or IED) that responds to master station polls and commands |
| Select-Before-Operate | DNP3 safety mechanism requiring a Select command before an Operate, preventing accidental control actions |
| Cold Restart (FC 0x0D) | DNP3 command that fully restarts an outstation, resetting all configuration -- a high-risk denial-of-service operation |
| DNP3 Secure Authentication | Optional DNP3 extension (SA v5) adding HMAC-based authentication to prevent command spoofing |
| PIPEDREAM | ICS attack framework with DNP3 capabilities for manipulating outstations and performing firmware updates |

## Output Format

```
DNP3 ANOMALY DETECTION REPORT
================================
Analysis Period: [start] to [end]
Monitoring Point: [substation/segment]

TRAFFIC SUMMARY:
  DNP3 Packets: [count]
  Unique Master-Outstation Pairs: [count]
  Control Commands: [count]
  File Operations: [count]

ALERTS:
  [CRITICAL] Unauthorized DNP3 master [IP]
  [CRITICAL] Cold restart command to outstation [addr]
  [HIGH] Unexpected control command from [IP]

RECOMMENDATIONS:
  1. Deploy DNP3 Secure Authentication (SA v5)
  2. Block unauthorized sources at firewall
  3. Enable DNP3 DPI on industrial firewall
```
