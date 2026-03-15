---
name: detecting-modbus-protocol-anomalies
description: >
  This skill covers detecting anomalies in Modbus/TCP and Modbus RTU communications
  in industrial control systems. It addresses function code monitoring, register
  range validation, timing analysis, unauthorized client detection, and deep packet
  inspection for malformed Modbus frames. The skill leverages Zeek with Modbus protocol
  analyzers, Suricata IDS with OT rules, and custom Python-based detection using
  Markov chain models for normal Modbus transaction sequences.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, modbus, protocol-anomaly]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Modbus Protocol Anomalies

## When to Use

- When deploying Modbus-specific intrusion detection in an OT environment
- When building baseline models for deterministic Modbus polling patterns
- When investigating suspicious Modbus traffic flagged by OT monitoring tools
- When implementing function code allowlisting on industrial firewalls
- When detecting unauthorized Modbus write commands that could manipulate process setpoints

**Do not use** for securing Modbus communications end-to-end (Modbus has no native security; see implementing-network-segmentation-for-ot for firewall-based controls), for non-Modbus protocol monitoring (see detecting-anomalies-in-industrial-control-systems for multi-protocol), or for active fuzzing of Modbus implementations (see performing-plc-firmware-security-analysis).

## Prerequisites

- Network SPAN/TAP access to monitor Modbus/TCP traffic (port 502)
- Zeek (formerly Bro) with Modbus protocol analyzer or Suricata with OT rulesets
- Python 3.9+ with scapy and pymodbus for custom analysis
- Baseline capture of normal Modbus traffic (minimum 1-2 weeks)
- Documentation of authorized Modbus clients, function codes, and register maps

## Workflow

### Step 1: Capture and Parse Modbus Traffic

Deploy passive monitoring to capture all Modbus/TCP traffic and parse it into structured records for analysis.

```python
#!/usr/bin/env python3
"""Modbus Protocol Anomaly Detection System.

Monitors Modbus/TCP traffic for anomalies including unauthorized
function codes, unusual register access, timing deviations,
and rogue client devices.
"""

import json
import struct
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from statistics import mean, stdev

try:
    from scapy.all import sniff, rdpcap, IP, TCP
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)


MODBUS_FUNCTION_CODES = {
    1: ("Read Coils", "read"),
    2: ("Read Discrete Inputs", "read"),
    3: ("Read Holding Registers", "read"),
    4: ("Read Input Registers", "read"),
    5: ("Write Single Coil", "write"),
    6: ("Write Single Register", "write"),
    7: ("Read Exception Status", "diagnostic"),
    8: ("Diagnostics", "diagnostic"),
    11: ("Get Comm Event Counter", "diagnostic"),
    12: ("Get Comm Event Log", "diagnostic"),
    15: ("Write Multiple Coils", "write"),
    16: ("Write Multiple Registers", "write"),
    17: ("Report Slave ID", "diagnostic"),
    22: ("Mask Write Register", "write"),
    23: ("Read/Write Multiple Registers", "read_write"),
    43: ("Encapsulated Interface Transport", "diagnostic"),
}


@dataclass
class ModbusAnomaly:
    timestamp: str
    anomaly_type: str
    severity: str
    src_ip: str
    dst_ip: str
    unit_id: int
    func_code: int
    detail: str
    mitre_technique: str = ""


@dataclass
class ModbusSession:
    """Tracks state for a Modbus master-slave session."""
    src_ip: str
    dst_ip: str
    func_codes_seen: dict = field(default_factory=lambda: defaultdict(int))
    register_ranges: set = field(default_factory=set)
    intervals: list = field(default_factory=lambda: deque(maxlen=500))
    last_timestamp: float = 0
    request_count: int = 0
    write_count: int = 0


class ModbusAnomalyDetector:
    """Detects anomalies in Modbus/TCP traffic."""

    def __init__(self):
        self.sessions = {}
        self.baseline_sessions = {}
        self.anomalies = []
        self.authorized_clients = set()
        self.authorized_func_codes = {}  # per-session allowed FCs
        self.packet_count = 0

    def set_authorized_clients(self, clients):
        """Set list of authorized Modbus client IPs."""
        self.authorized_clients = set(clients)

    def set_authorized_func_codes(self, session_key, func_codes):
        """Set allowed function codes for a specific session."""
        self.authorized_func_codes[session_key] = set(func_codes)

    def load_baseline(self, baseline_file):
        """Load baseline profiles from previous capture analysis."""
        with open(baseline_file) as f:
            baseline = json.load(f)
        for key, data in baseline.get("modbus_baselines", {}).items():
            self.baseline_sessions[key] = data
            self.authorized_func_codes[key] = set(data.get("allowed_function_codes", []))
        print(f"[*] Loaded {len(self.baseline_sessions)} Modbus baselines")

    def process_packet(self, pkt):
        """Process a single packet for Modbus anomaly detection."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        # Check for Modbus/TCP (port 502)
        if pkt[TCP].dport != 502 and pkt[TCP].sport != 502:
            return

        payload = bytes(pkt[TCP].payload)
        if len(payload) < 8:
            return

        self.packet_count += 1
        timestamp = float(pkt.time)
        ts_str = datetime.fromtimestamp(timestamp).isoformat()

        # Parse MBAP header
        try:
            trans_id = struct.unpack(">H", payload[0:2])[0]
            proto_id = struct.unpack(">H", payload[2:4])[0]
            length = struct.unpack(">H", payload[4:6])[0]
            unit_id = payload[6]
            func_code = payload[7]
        except (IndexError, struct.error):
            return

        # Determine direction
        if pkt[TCP].dport == 502:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            is_request = True
        else:
            src_ip = pkt[IP].dst
            dst_ip = pkt[IP].src
            is_request = False

        if not is_request:
            return  # Only analyze requests

        session_key = f"{src_ip}->{dst_ip}"

        # Get or create session
        if session_key not in self.sessions:
            self.sessions[session_key] = ModbusSession(src_ip=src_ip, dst_ip=dst_ip)

        session = self.sessions[session_key]
        session.request_count += 1
        session.func_codes_seen[func_code] += 1

        # ── Anomaly Detection Rules ──

        # Rule 1: Unauthorized Modbus client
        if self.authorized_clients and src_ip not in self.authorized_clients:
            self.anomalies.append(ModbusAnomaly(
                timestamp=ts_str,
                anomaly_type="UNAUTHORIZED_CLIENT",
                severity="critical",
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=unit_id, func_code=func_code,
                detail=f"Modbus request from unauthorized client {src_ip}",
                mitre_technique="T0886 - Remote Services",
            ))

        # Rule 2: Unauthorized function code
        allowed_fcs = self.authorized_func_codes.get(session_key)
        if allowed_fcs and func_code not in allowed_fcs:
            fc_info = MODBUS_FUNCTION_CODES.get(func_code, (f"Unknown FC{func_code}", "unknown"))
            severity = "critical" if fc_info[1] == "write" else "high"
            self.anomalies.append(ModbusAnomaly(
                timestamp=ts_str,
                anomaly_type="UNAUTHORIZED_FUNCTION_CODE",
                severity=severity,
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=unit_id, func_code=func_code,
                detail=f"FC {func_code} ({fc_info[0]}) not in allowlist {sorted(allowed_fcs)}",
                mitre_technique="T0855 - Unauthorized Command Message",
            ))

        # Rule 3: Write operation detection
        if func_code in (5, 6, 15, 16, 22, 23):
            session.write_count += 1
            fc_name = MODBUS_FUNCTION_CODES.get(func_code, ("Unknown", ""))[0]

            # Extract register address
            if len(payload) >= 10:
                register_addr = struct.unpack(">H", payload[8:10])[0]
                session.register_ranges.add((func_code, register_addr))

                self.anomalies.append(ModbusAnomaly(
                    timestamp=ts_str,
                    anomaly_type="WRITE_OPERATION",
                    severity="high",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=unit_id, func_code=func_code,
                    detail=f"Write: {fc_name} to register {register_addr} from {src_ip}",
                    mitre_technique="T0836 - Modify Parameter",
                ))

        # Rule 4: Timing anomaly
        if session.last_timestamp > 0:
            interval = (timestamp - session.last_timestamp) * 1000  # ms
            session.intervals.append(interval)

            baseline = self.baseline_sessions.get(session_key)
            if baseline and len(session.intervals) > 10:
                expected_interval = baseline.get("polling_interval_avg_sec", 0) * 1000
                expected_std = baseline.get("polling_interval_stddev", 0) * 1000

                if expected_std > 0:
                    z_score = abs(interval - expected_interval) / expected_std
                    if z_score > 5.0:
                        self.anomalies.append(ModbusAnomaly(
                            timestamp=ts_str,
                            anomaly_type="TIMING_ANOMALY",
                            severity="medium",
                            src_ip=src_ip, dst_ip=dst_ip,
                            unit_id=unit_id, func_code=func_code,
                            detail=(
                                f"Interval {interval:.0f}ms vs baseline "
                                f"{expected_interval:.0f}ms (z={z_score:.1f})"
                            ),
                            mitre_technique="T0831 - Manipulation of Control",
                        ))

        # Rule 5: Protocol violation - invalid protocol ID
        if proto_id != 0:
            self.anomalies.append(ModbusAnomaly(
                timestamp=ts_str,
                anomaly_type="PROTOCOL_VIOLATION",
                severity="high",
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=unit_id, func_code=func_code,
                detail=f"Non-standard protocol ID {proto_id} (expected 0)",
                mitre_technique="T0830 - Man in the Middle",
            ))

        # Rule 6: Broadcast write (unit ID 0)
        if unit_id == 0 and func_code in (5, 6, 15, 16):
            self.anomalies.append(ModbusAnomaly(
                timestamp=ts_str,
                anomaly_type="BROADCAST_WRITE",
                severity="critical",
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=unit_id, func_code=func_code,
                detail="Broadcast write command (unit ID 0) affects ALL slaves",
                mitre_technique="T0855 - Unauthorized Command Message",
            ))

        session.last_timestamp = timestamp

    def analyze_pcap(self, pcap_file):
        """Analyze pcap file for Modbus anomalies."""
        print(f"[*] Analyzing {pcap_file}...")
        packets = rdpcap(pcap_file)
        for pkt in packets:
            self.process_packet(pkt)
        print(f"[*] Processed {self.packet_count} Modbus packets")

    def generate_report(self):
        """Generate anomaly detection report."""
        print(f"\n{'='*70}")
        print("MODBUS PROTOCOL ANOMALY DETECTION REPORT")
        print(f"{'='*70}")
        print(f"Packets analyzed: {self.packet_count}")
        print(f"Sessions tracked: {len(self.sessions)}")
        print(f"Anomalies detected: {len(self.anomalies)}")

        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        for a in self.anomalies:
            severity_counts[a.severity] += 1
            type_counts[a.anomaly_type] += 1

        print(f"\nBy Severity:")
        for sev in ["critical", "high", "medium", "low"]:
            if severity_counts[sev]:
                print(f"  {sev.upper()}: {severity_counts[sev]}")

        print(f"\nBy Type:")
        for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {atype}: {count}")

        print(f"\nTop Anomalies:")
        for a in self.anomalies[:15]:
            print(f"  [{a.severity.upper()}] {a.anomaly_type}: {a.detail}")


if __name__ == "__main__":
    detector = ModbusAnomalyDetector()

    if len(sys.argv) > 1:
        # Load baseline if provided
        if len(sys.argv) > 2:
            detector.load_baseline(sys.argv[2])
        detector.analyze_pcap(sys.argv[1])
        detector.generate_report()
    else:
        print("Usage: python modbus_detector.py <pcap_file> [baseline.json]")
```

## Key Concepts

| Term | Definition |
|------|------------|
| Modbus/TCP | Industrial protocol running on TCP port 502, consisting of an MBAP header and PDU with function code and data |
| Function Code | Modbus command identifier (FC1-4: reads, FC5-6/15-16: writes, FC8: diagnostics) determining the operation type |
| MBAP Header | Modbus Application Protocol header containing transaction ID, protocol ID (0x0000), length, and unit ID |
| Unit ID | Modbus address (0-247) identifying the target slave device; unit ID 0 is broadcast to all slaves |
| Register Map | Vendor-specific mapping of Modbus register addresses to process variables (e.g., register 40001 = reactor temperature) |
| Function Code Allowlist | Security policy defining which Modbus function codes are permitted from each source IP to each target device |

## Tools & Systems

- **Zeek Modbus Analyzer**: Network security monitor with built-in Modbus/TCP protocol analysis and logging
- **Suricata with ET Open ICS rules**: IDS/IPS with Modbus-specific detection rules for command injection and anomalies
- **Wireshark Modbus Dissector**: Protocol analyzer with full Modbus/TCP and Modbus RTU decoding
- **PyModbus**: Python Modbus library for building custom monitoring and testing tools

## Output Format

```
Modbus Protocol Anomaly Detection Report
==========================================
Capture Period: YYYY-MM-DD to YYYY-MM-DD
Packets Analyzed: [N]
Sessions: [N]

ANOMALIES: [N]
  UNAUTHORIZED_CLIENT: [N]
  UNAUTHORIZED_FUNCTION_CODE: [N]
  WRITE_OPERATION: [N]
  TIMING_ANOMALY: [N]
  BROADCAST_WRITE: [N]
```
