---
name: detecting-modbus-command-injection-attacks
description: >
  Detect command injection attacks against Modbus TCP/RTU protocol in ICS
  environments by monitoring for unauthorized write operations, anomalous function
  codes, malformed frames, and deviations from established communication baselines
  using ICS-aware IDS and protocol deep packet inspection.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, modbus, command-injection, protocol-analysis, ids, scada, threat-detection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Modbus Command Injection Attacks

## When to Use

- When deploying intrusion detection for environments using Modbus TCP (port 502) or Modbus RTU
- When investigating suspected unauthorized modifications to PLC registers or coils
- When building detection analytics for OT SOC monitoring Modbus-heavy environments
- When responding to FrostyGoop-style attacks that leverage Modbus TCP for operational impact
- When performing baseline validation after a suspected compromise of a Modbus master

**Do not use** for detecting attacks on non-Modbus protocols (see detecting-dnp3-protocol-anomalies for DNP3), for general IT network intrusion detection, or for Modbus device configuration (see performing-ot-vulnerability-scanning-safely).

## Prerequisites

- Network SPAN/TAP on the segment carrying Modbus TCP traffic (typically port 502)
- Baseline of normal Modbus communication patterns (masters, slaves, function codes, register ranges, polling intervals)
- Suricata, Zeek, or commercial OT IDS deployed with Modbus protocol parsers enabled
- Understanding of Modbus function codes used in the environment (read vs write operations)
- Access to PLC programming documentation to validate expected register ranges

## Workflow

### Step 1: Build Modbus Communication Baseline

Capture and analyze normal Modbus traffic to establish what constitutes legitimate communication patterns.

```python
#!/usr/bin/env python3
"""Modbus Command Injection Detector.

Monitors Modbus TCP traffic for unauthorized write operations, anomalous
function codes, and deviations from established communication baselines.
Detects attacks like FrostyGoop that use Modbus TCP for operational impact.
"""

import json
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    from scapy.all import sniff, IP, TCP
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)


# Modbus function code definitions
MODBUS_READ_FUNCTIONS = {1, 2, 3, 4}
MODBUS_WRITE_FUNCTIONS = {5, 6, 15, 16}
MODBUS_DIAGNOSTIC_FUNCTIONS = {8, 17, 43}

MODBUS_FUNC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs",
    3: "Read Holding Registers", 4: "Read Input Registers",
    5: "Write Single Coil", 6: "Write Single Register",
    8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Slave ID",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}


class ModbusAlert:
    """Represents a detected Modbus anomaly."""

    def __init__(self, severity: str, alert_type: str, src_ip: str,
                 dst_ip: str, unit_id: int, func_code: int,
                 description: str, mitre_technique: str = ""):
        self.timestamp = datetime.now().isoformat()
        self.severity = severity
        self.alert_type = alert_type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.unit_id = unit_id
        self.func_code = func_code
        self.func_name = MODBUS_FUNC_NAMES.get(func_code, f"Unknown FC {func_code}")
        self.description = description
        self.mitre_technique = mitre_technique

    def __str__(self):
        return (
            f"[{self.severity}] {self.alert_type} | {self.src_ip} -> {self.dst_ip} "
            f"| Unit {self.unit_id} | {self.func_name} | {self.description}"
        )


class ModbusInjectionDetector:
    """Detects Modbus command injection attacks."""

    def __init__(self, baseline_file: Optional[str] = None):
        self.alerts: List[ModbusAlert] = []
        self.packet_count = 0
        self.modbus_count = 0

        # Baseline data
        self.authorized_masters: Set[str] = set()
        self.authorized_pairs: Set[Tuple[str, str]] = set()
        self.allowed_write_sources: Set[str] = set()
        self.allowed_function_codes: Dict[str, Set[int]] = defaultdict(set)
        self.allowed_register_ranges: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        self.polling_intervals: Dict[str, float] = {}
        self.last_seen: Dict[str, float] = {}

        # Counters for rate detection
        self.write_counts: Dict[str, List[float]] = defaultdict(list)

        if baseline_file:
            self.load_baseline(baseline_file)

    def load_baseline(self, filepath: str):
        """Load established Modbus communication baseline."""
        with open(filepath, "r") as f:
            baseline = json.load(f)

        for session_key, data in baseline.get("modbus_baselines", {}).items():
            src, dst = session_key.split("->")
            self.authorized_pairs.add((src.strip(), dst.strip()))
            self.authorized_masters.add(src.strip())

            fc_set = set(data.get("allowed_function_codes", []))
            self.allowed_function_codes[session_key] = fc_set

            if fc_set & MODBUS_WRITE_FUNCTIONS:
                self.allowed_write_sources.add(src.strip())

            for reg_range in data.get("register_ranges", []):
                self.allowed_register_ranges[session_key].append(
                    (reg_range["start"], reg_range["end"])
                )

            if data.get("polling_interval_avg_sec"):
                self.polling_intervals[session_key] = data["polling_interval_avg_sec"]

        print(f"[*] Baseline loaded: {len(self.authorized_pairs)} authorized pairs, "
              f"{len(self.allowed_write_sources)} authorized write sources")

    def parse_modbus_mbap(self, payload: bytes) -> Optional[dict]:
        """Parse Modbus TCP MBAP header and PDU."""
        if len(payload) < 8:
            return None

        transaction_id = struct.unpack(">H", payload[0:2])[0]
        protocol_id = struct.unpack(">H", payload[2:4])[0]
        length = struct.unpack(">H", payload[4:6])[0]
        unit_id = payload[6]
        func_code = payload[7]

        if protocol_id != 0:  # Not Modbus
            return None

        result = {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "length": length,
            "unit_id": unit_id,
            "func_code": func_code,
        }

        # Parse register address and count for read/write operations
        if len(payload) >= 12 and func_code in (1, 2, 3, 4, 5, 6, 15, 16):
            result["start_address"] = struct.unpack(">H", payload[8:10])[0]
            result["quantity"] = struct.unpack(">H", payload[10:12])[0]

        return result

    def analyze_packet(self, pkt):
        """Analyze a network packet for Modbus command injection."""
        self.packet_count += 1

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        if tcp.dport != 502 and tcp.sport != 502:
            return

        payload = bytes(tcp.payload)
        if not payload:
            return

        modbus = self.parse_modbus_mbap(payload)
        if not modbus:
            return

        self.modbus_count += 1
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        session_key = f"{src_ip}->{dst_ip}"
        now = time.time()

        # Detection Rule 1: Unauthorized Modbus master
        if self.authorized_masters and src_ip not in self.authorized_masters:
            if tcp.dport == 502:
                self.alerts.append(ModbusAlert(
                    severity="CRITICAL",
                    alert_type="UNAUTHORIZED_MASTER",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=modbus["unit_id"],
                    func_code=modbus["func_code"],
                    description=f"Unauthorized device {src_ip} sending Modbus commands to {dst_ip}",
                    mitre_technique="T0843 - Program Download",
                ))

        # Detection Rule 2: Unauthorized write operation
        if modbus["func_code"] in MODBUS_WRITE_FUNCTIONS:
            if self.allowed_write_sources and src_ip not in self.allowed_write_sources:
                self.alerts.append(ModbusAlert(
                    severity="CRITICAL",
                    alert_type="UNAUTHORIZED_WRITE",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=modbus["unit_id"],
                    func_code=modbus["func_code"],
                    description=f"Write command from non-authorized source {src_ip}",
                    mitre_technique="T0855 - Unauthorized Command Message",
                ))

            # Track write frequency for rate anomaly detection
            self.write_counts[src_ip].append(now)
            recent_writes = [t for t in self.write_counts[src_ip] if now - t < 60]
            self.write_counts[src_ip] = recent_writes
            if len(recent_writes) > 20:
                self.alerts.append(ModbusAlert(
                    severity="HIGH",
                    alert_type="WRITE_FLOOD",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=modbus["unit_id"],
                    func_code=modbus["func_code"],
                    description=f"Excessive write rate: {len(recent_writes)} writes in 60s from {src_ip}",
                    mitre_technique="T0836 - Modify Parameter",
                ))

        # Detection Rule 3: Anomalous function code
        if session_key in self.allowed_function_codes:
            if modbus["func_code"] not in self.allowed_function_codes[session_key]:
                self.alerts.append(ModbusAlert(
                    severity="HIGH",
                    alert_type="ANOMALOUS_FUNCTION_CODE",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=modbus["unit_id"],
                    func_code=modbus["func_code"],
                    description=(
                        f"Function code {modbus['func_code']} ({MODBUS_FUNC_NAMES.get(modbus['func_code'], 'Unknown')}) "
                        f"not in baseline for {session_key}"
                    ),
                    mitre_technique="T0855 - Unauthorized Command Message",
                ))

        # Detection Rule 4: Broadcast write (unit ID 0)
        if modbus["unit_id"] == 0 and modbus["func_code"] in MODBUS_WRITE_FUNCTIONS:
            self.alerts.append(ModbusAlert(
                severity="CRITICAL",
                alert_type="BROADCAST_WRITE",
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=0,
                func_code=modbus["func_code"],
                description="Broadcast write command (unit ID 0) affects ALL Modbus devices on segment",
                mitre_technique="T0855 - Unauthorized Command Message",
            ))

        # Detection Rule 5: Out-of-range register access
        if "start_address" in modbus and session_key in self.allowed_register_ranges:
            addr = modbus["start_address"]
            qty = modbus.get("quantity", 1)
            in_range = any(
                start <= addr and addr + qty <= end
                for start, end in self.allowed_register_ranges[session_key]
            )
            if not in_range:
                self.alerts.append(ModbusAlert(
                    severity="HIGH",
                    alert_type="OUT_OF_RANGE_REGISTER",
                    src_ip=src_ip, dst_ip=dst_ip,
                    unit_id=modbus["unit_id"],
                    func_code=modbus["func_code"],
                    description=f"Register access {addr}-{addr+qty} outside baseline ranges",
                    mitre_technique="T0836 - Modify Parameter",
                ))

        # Detection Rule 6: Diagnostic/restart commands
        if modbus["func_code"] in MODBUS_DIAGNOSTIC_FUNCTIONS:
            self.alerts.append(ModbusAlert(
                severity="HIGH",
                alert_type="DIAGNOSTIC_COMMAND",
                src_ip=src_ip, dst_ip=dst_ip,
                unit_id=modbus["unit_id"],
                func_code=modbus["func_code"],
                description=f"Diagnostic function code {modbus['func_code']} detected - potential DoS or reconnaissance",
                mitre_technique="T0814 - Denial of Service",
            ))

    def print_report(self):
        """Print detection report."""
        print(f"\n{'='*70}")
        print(f"MODBUS COMMAND INJECTION DETECTION REPORT")
        print(f"{'='*70}")
        print(f"Analysis Time: {datetime.now().isoformat()}")
        print(f"Total Packets Analyzed: {self.packet_count}")
        print(f"Modbus Packets: {self.modbus_count}")
        print(f"Alerts Generated: {len(self.alerts)}")

        if self.alerts:
            severity_counts = defaultdict(int)
            for alert in self.alerts:
                severity_counts[alert.severity] += 1

            print(f"\nSeverity Distribution:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in severity_counts:
                    print(f"  {sev}: {severity_counts[sev]}")

            print(f"\nDetailed Alerts:")
            for alert in self.alerts:
                print(f"\n  [{alert.severity}] {alert.alert_type}")
                print(f"    Time: {alert.timestamp}")
                print(f"    Source: {alert.src_ip} -> {alert.dst_ip}")
                print(f"    Unit ID: {alert.unit_id}")
                print(f"    Function: {alert.func_name} (FC {alert.func_code})")
                print(f"    Detail: {alert.description}")
                if alert.mitre_technique:
                    print(f"    MITRE ATT&CK ICS: {alert.mitre_technique}")

    def start_live_monitoring(self, interface: str, duration: int = 0):
        """Start live Modbus traffic monitoring."""
        print(f"[*] Starting Modbus monitoring on {interface}...")
        print(f"[*] Press Ctrl+C to stop")
        try:
            sniff(
                iface=interface,
                filter="tcp port 502",
                prn=self.analyze_packet,
                timeout=duration if duration > 0 else None,
            )
        except KeyboardInterrupt:
            pass
        self.print_report()


if __name__ == "__main__":
    detector = ModbusInjectionDetector(
        baseline_file=sys.argv[2] if len(sys.argv) > 2 else None
    )

    if len(sys.argv) >= 2:
        if sys.argv[1].endswith(".pcap") or sys.argv[1].endswith(".pcapng"):
            from scapy.all import rdpcap
            print(f"[*] Analyzing capture file: {sys.argv[1]}")
            packets = rdpcap(sys.argv[1])
            for pkt in packets:
                detector.analyze_packet(pkt)
            detector.print_report()
        else:
            detector.start_live_monitoring(sys.argv[1])
    else:
        print("Usage:")
        print("  Live:    python modbus_detector.py <interface> [baseline.json]")
        print("  Offline: python modbus_detector.py <capture.pcap> [baseline.json]")
```

### Step 2: Deploy Suricata Rules for Modbus Attack Detection

```yaml
# Suricata IDS Rules for Modbus Command Injection Detection
# Reference: MITRE ATT&CK for ICS, FrostyGoop analysis

# Unauthorized Modbus write from non-engineering workstation
alert modbus !$MODBUS_AUTHORIZED_WRITERS any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Unauthorized write operation detected";
  modbus_func:write_single_coil;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:4000001; rev:1; priority:1;
)

alert modbus !$MODBUS_AUTHORIZED_WRITERS any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Unauthorized write multiple registers";
  modbus_func:write_multiple_registers;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:4000002; rev:1; priority:1;
)

# Modbus broadcast write affecting all slaves
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Broadcast write command (Unit ID 0)";
  modbus_unit_id:0;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:4000003; rev:1; priority:1;
)

# Excessive Modbus write rate (potential automated attack)
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Excessive write rate - possible automated attack";
  modbus_func:write_multiple_registers;
  flow:to_server,established;
  threshold:type threshold, track by_src, count 20, seconds 60;
  classtype:attempted-admin;
  sid:4000004; rev:1;
)

# Modbus diagnostics/restart command
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Diagnostics function code detected";
  modbus_func:diagnostics;
  flow:to_server,established;
  classtype:attempted-dos;
  sid:4000005; rev:1;
)

# FrostyGoop-pattern: write to specific register ranges used for heating control
alert modbus any any -> $OT_PLC_SUBNET 502 (
  msg:"MODBUS-INJECT Potential FrostyGoop - write to heating control registers";
  modbus_func:write_multiple_registers;
  content:"|00 10|"; offset:8; depth:2;
  flow:to_server,established;
  classtype:attempted-admin;
  sid:4000010; rev:1; priority:1;
)
```

## Key Concepts

| Term | Definition |
|------|------------|
| Modbus TCP | Industrial protocol operating on TCP port 502, lacking authentication or encryption, making it vulnerable to command injection |
| Function Code | Single byte in Modbus PDU specifying the operation (read coils, write registers, diagnostics); monitoring for unauthorized function codes is key to detection |
| MBAP Header | Modbus Application Protocol header in TCP variant containing transaction ID, protocol ID, length, and unit ID |
| FrostyGoop | First known malware using Modbus TCP for real-world operational impact, disrupted Ukrainian district heating in 2024 |
| Unit ID | Address of the target Modbus slave device; Unit ID 0 is a broadcast affecting all slaves |
| Register Range | Specific memory addresses in the PLC; legitimate operations access known ranges; out-of-range access indicates reconnaissance or manipulation |

## Common Scenarios

### Scenario: FrostyGoop-Style Heating Control Attack

**Context**: A building automation system uses Modbus TCP to control HVAC equipment. Monitoring detects unexpected write commands to heating control registers from an IP not associated with any authorized BMS controller.

**Approach**:
1. Verify the source IP against the authorized Modbus master list
2. Check if any authorized maintenance or configuration change is in progress
3. Capture full Modbus transaction including register addresses and values being written
4. Compare written values against safe operating ranges for the heating equipment
5. If unauthorized, immediately block the source IP at the industrial firewall
6. Inspect the source device for compromise indicators (malware, unauthorized remote access)
7. Verify current setpoints on all affected controllers against known-good values
8. Restore safe setpoints if manipulation is confirmed

**Pitfalls**: Modbus lacks authentication, so the source IP is the only identifier -- attackers can spoof IPs if ARP protections are not in place. Do not assume all writes are malicious; legitimate SCADA operations include writes. Always verify against the change management log before escalating.

## Output Format

```
MODBUS INJECTION DETECTION REPORT
====================================
Analysis Period: [start] to [end]
Monitoring Point: [interface/SPAN description]

TRAFFIC SUMMARY:
  Total Modbus Packets: [count]
  Read Operations: [count]
  Write Operations: [count]
  Unauthorized Writes Detected: [count]

ALERTS:
  [CRITICAL] Unauthorized write from [IP] to PLC [IP]
    Function: Write Multiple Registers (FC 16)
    Registers: [start]-[end]
    MITRE: T0855 - Unauthorized Command Message

BASELINE DEVIATIONS:
  New Modbus masters: [list]
  Unusual function codes: [list]
  Out-of-range register access: [list]

RECOMMENDED ACTIONS:
  1. Verify source [IP] authorization status
  2. Block unauthorized sources at industrial firewall
  3. Validate PLC register values against known-good state
```
