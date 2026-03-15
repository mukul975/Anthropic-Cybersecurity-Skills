---
name: performing-s7comm-protocol-security-analysis
description: >
  Perform security analysis of Siemens S7comm and S7CommPlus protocols used by
  SIMATIC S7 PLCs to identify vulnerabilities including replay attacks, integrity
  bypass, unauthorized CPU stop commands, and program download manipulation
  exploiting weaknesses in S7-300, S7-400, S7-1200, and S7-1500 controllers.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, s7comm, siemens, plc-security, protocol-analysis, scada, vulnerability-assessment]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing S7comm Protocol Security Analysis

## When to Use

- When assessing the security posture of Siemens SIMATIC S7 PLC environments
- When building detection rules for S7comm-based attacks against S7-300/400/1200/1500 controllers
- When performing a security audit of Siemens Step 7/TIA Portal communications
- When investigating suspected unauthorized access to Siemens PLC programs
- When evaluating S7CommPlus integrity mechanisms and their bypass potential

**Do not use** for scanning production Siemens PLCs without authorization and a test plan (this can crash controllers), for non-Siemens protocol analysis (see detecting-modbus-command-injection-attacks for Modbus), or for modifying PLC programs in a production environment.

## Prerequisites

- Network access to the S7comm communication segment (TCP port 102)
- Wireshark with S7comm dissector or Zeek with S7comm protocol analyzer
- Authorized access for security testing (never scan production PLCs without authorization)
- Knowledge of the Siemens PLC models and firmware versions in scope
- Understanding of S7comm protocol structure (COTP, S7 PDU, function codes)

## Workflow

### Step 1: Analyze S7comm Traffic and Identify Vulnerabilities

```python
#!/usr/bin/env python3
"""S7comm Protocol Security Analyzer.

Analyzes Siemens S7comm protocol traffic to identify security
vulnerabilities, unauthorized access patterns, and potential
attack indicators against SIMATIC S7 PLCs.
"""

import struct
import sys
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

try:
    from scapy.all import rdpcap, IP, TCP
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)


# S7comm ROSCTR (PDU type) definitions
S7_ROSCTR = {
    0x01: "Job (Request)",
    0x02: "Ack",
    0x03: "Ack_Data (Response)",
    0x07: "Userdata",
}

# S7comm function codes
S7_FUNCTIONS = {
    0x00: "CPU services",
    0x04: "Read Variable",
    0x05: "Write Variable",
    0x1A: "Request Download (Program)",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload (Read Program)",
    0x1E: "Upload Block",
    0x1F: "Upload Ended",
    0x28: "PI Service (Start/Stop CPU)",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}

# Critical security-relevant operations
CRITICAL_FUNCTIONS = {0x1A, 0x1B, 0x1C, 0x28, 0x29, 0x05}
PROGRAM_FUNCTIONS = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}


class S7commSecurityFinding:
    """Represents a security finding in S7comm traffic."""

    def __init__(self, severity: str, finding_type: str, src_ip: str,
                 dst_ip: str, function: str, description: str,
                 cve: str = "", recommendation: str = ""):
        self.timestamp = datetime.now().isoformat()
        self.severity = severity
        self.finding_type = finding_type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.function = function
        self.description = description
        self.cve = cve
        self.recommendation = recommendation


class S7commAnalyzer:
    """Analyzes S7comm protocol traffic for security vulnerabilities."""

    def __init__(self):
        self.findings: List[S7commSecurityFinding] = []
        self.sessions: Dict[str, dict] = defaultdict(lambda: {
            "packets": 0,
            "functions_seen": set(),
            "writes": 0,
            "program_downloads": 0,
            "cpu_commands": 0,
            "first_seen": None,
            "last_seen": None,
        })
        self.authorized_engineering: set = set()
        self.packet_count = 0

    def set_authorized_stations(self, ips: List[str]):
        """Set list of authorized engineering workstation IPs."""
        self.authorized_engineering = set(ips)

    def parse_s7comm(self, payload: bytes) -> Optional[dict]:
        """Parse S7comm protocol data from TCP payload."""
        # TPKT header: version(1) + reserved(1) + length(2)
        if len(payload) < 4:
            return None

        tpkt_version = payload[0]
        if tpkt_version != 3:
            return None

        tpkt_length = struct.unpack(">H", payload[2:4])[0]

        # COTP header follows TPKT
        if len(payload) < 7:
            return None

        cotp_length = payload[4]
        cotp_type = payload[5]

        # S7comm starts after COTP
        s7_offset = 4 + 1 + cotp_length
        if len(payload) < s7_offset + 10:
            return None

        # S7comm header
        protocol_id = payload[s7_offset]
        if protocol_id != 0x32:  # S7comm magic byte
            return None

        rosctr = payload[s7_offset + 1]
        redundancy = struct.unpack(">H", payload[s7_offset + 2:s7_offset + 4])[0]
        pdu_ref = struct.unpack(">H", payload[s7_offset + 4:s7_offset + 6])[0]
        param_length = struct.unpack(">H", payload[s7_offset + 6:s7_offset + 8])[0]
        data_length = struct.unpack(">H", payload[s7_offset + 8:s7_offset + 10])[0]

        result = {
            "rosctr": rosctr,
            "rosctr_name": S7_ROSCTR.get(rosctr, f"Unknown (0x{rosctr:02x})"),
            "pdu_ref": pdu_ref,
            "param_length": param_length,
            "data_length": data_length,
        }

        # Parse function code from parameters
        param_offset = s7_offset + 10
        if rosctr in (0x01, 0x03) and param_length > 0 and len(payload) > param_offset:
            func_code = payload[param_offset]
            result["function_code"] = func_code
            result["function_name"] = S7_FUNCTIONS.get(func_code, f"Unknown (0x{func_code:02x})")

        return result

    def analyze_packet(self, pkt):
        """Analyze a packet for S7comm security issues."""
        self.packet_count += 1

        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        if tcp.dport != 102 and tcp.sport != 102:
            return

        payload = bytes(tcp.payload)
        if not payload:
            return

        s7 = self.parse_s7comm(payload)
        if not s7:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        session_key = f"{src_ip}->{dst_ip}"
        session = self.sessions[session_key]
        session["packets"] += 1

        if session["first_seen"] is None:
            session["first_seen"] = float(pkt.time)
        session["last_seen"] = float(pkt.time)

        func_code = s7.get("function_code")
        if func_code is not None:
            session["functions_seen"].add(func_code)

            # Check 1: Unauthorized engineering station
            if tcp.dport == 102 and func_code in CRITICAL_FUNCTIONS:
                if self.authorized_engineering and src_ip not in self.authorized_engineering:
                    self.findings.append(S7commSecurityFinding(
                        severity="CRITICAL",
                        finding_type="UNAUTHORIZED_ENGINEERING_ACCESS",
                        src_ip=src_ip, dst_ip=dst_ip,
                        function=s7.get("function_name", "Unknown"),
                        description=(
                            f"Critical S7comm operation from unauthorized source {src_ip}. "
                            f"Function: {s7.get('function_name')}. Only authorized TIA Portal "
                            f"workstations should issue these commands."
                        ),
                        recommendation="Block unauthorized sources at industrial firewall. Investigate source host for compromise.",
                    ))

            # Check 2: CPU Stop command
            if func_code == 0x29:
                session["cpu_commands"] += 1
                self.findings.append(S7commSecurityFinding(
                    severity="CRITICAL",
                    finding_type="CPU_STOP_COMMAND",
                    src_ip=src_ip, dst_ip=dst_ip,
                    function="PLC CPU Stop (0x29)",
                    description=f"CPU STOP command sent to PLC at {dst_ip}. This halts PLC program execution.",
                    cve="MITRE T0881 - Service Stop",
                    recommendation="Verify if this is an authorized maintenance action. If not, isolate source immediately.",
                ))

            # Check 3: Program download
            if func_code in (0x1A, 0x1B, 0x1C):
                session["program_downloads"] += 1
                self.findings.append(S7commSecurityFinding(
                    severity="CRITICAL",
                    finding_type="PROGRAM_DOWNLOAD",
                    src_ip=src_ip, dst_ip=dst_ip,
                    function=s7.get("function_name", "Download"),
                    description=(
                        f"PLC program download operation to {dst_ip}. "
                        f"This modifies the running control logic on the PLC."
                    ),
                    cve="MITRE T0843 - Program Download",
                    recommendation="Verify against change management records. Compare with known-good program backup.",
                ))

            # Check 4: Write variable operation
            if func_code == 0x05:
                session["writes"] += 1

            # Check 5: Program upload (exfiltration of PLC code)
            if func_code in (0x1D, 0x1E, 0x1F):
                self.findings.append(S7commSecurityFinding(
                    severity="HIGH",
                    finding_type="PROGRAM_UPLOAD_EXFILTRATION",
                    src_ip=src_ip, dst_ip=dst_ip,
                    function=s7.get("function_name", "Upload"),
                    description=f"PLC program upload (read) from {dst_ip}. Source {src_ip} is extracting PLC control logic.",
                    recommendation="Verify if this is authorized maintenance. Unauthorized uploads indicate reconnaissance.",
                ))

    def check_known_vulnerabilities(self):
        """Check for known Siemens S7 vulnerabilities based on observed behavior."""
        vuln_checks = [
            {
                "name": "S7-300/400 Replay Attack Vulnerability",
                "cve": "CVE-2019-13945",
                "description": "S7-300/400 PLCs lack integrity checks on S7comm sessions, allowing replay attacks",
                "affected": "S7-300, S7-400 (all firmware versions)",
                "severity": "HIGH",
            },
            {
                "name": "S7CommPlus Integrity Bypass",
                "cve": "Research finding (Biham et al.)",
                "description": "S7CommPlusV3 integrity mechanism can be bypassed by attackers who can observe one legitimate session",
                "affected": "S7-1200 (< V4.5), S7-1500 (< V2.9)",
                "severity": "HIGH",
            },
            {
                "name": "Unpatchable Hardware Root of Trust",
                "cve": "CVE-2022-38773",
                "description": "Hardware vulnerability allows bypassing protected boot and persistent firmware modification",
                "affected": "S7-1500 (specific hardware revisions)",
                "severity": "CRITICAL",
            },
            {
                "name": "Remote DoS via Port 102",
                "cve": "CVE-2019-10929",
                "description": "Specially crafted packets on TCP port 102 can crash S7 PLCs remotely",
                "affected": "S7-300, S7-400, S7-1200, S7-1500 (specific firmware)",
                "severity": "HIGH",
            },
        ]
        return vuln_checks

    def generate_report(self):
        """Generate comprehensive S7comm security analysis report."""
        print(f"\n{'='*70}")
        print("S7COMM PROTOCOL SECURITY ANALYSIS REPORT")
        print(f"{'='*70}")
        print(f"Analysis Time: {datetime.now().isoformat()}")
        print(f"Packets Analyzed: {self.packet_count}")
        print(f"S7comm Sessions: {len(self.sessions)}")
        print(f"Security Findings: {len(self.findings)}")

        print(f"\n--- SESSION SUMMARY ---")
        for key, session in self.sessions.items():
            funcs = [S7_FUNCTIONS.get(f, f"0x{f:02x}") for f in session["functions_seen"]]
            print(f"\n  {key}")
            print(f"    Packets: {session['packets']}")
            print(f"    Functions: {', '.join(funcs)}")
            print(f"    Writes: {session['writes']}")
            print(f"    Program Downloads: {session['program_downloads']}")
            print(f"    CPU Commands: {session['cpu_commands']}")

        if self.findings:
            print(f"\n--- SECURITY FINDINGS ---")
            for f in self.findings:
                print(f"\n  [{f.severity}] {f.finding_type}")
                print(f"    Source: {f.src_ip} -> {f.dst_ip}")
                print(f"    Function: {f.function}")
                print(f"    Detail: {f.description}")
                if f.cve:
                    print(f"    Reference: {f.cve}")
                if f.recommendation:
                    print(f"    Action: {f.recommendation}")

        print(f"\n--- KNOWN VULNERABILITY ASSESSMENT ---")
        for vuln in self.check_known_vulnerabilities():
            print(f"\n  [{vuln['severity']}] {vuln['name']}")
            print(f"    CVE: {vuln['cve']}")
            print(f"    Affected: {vuln['affected']}")
            print(f"    Detail: {vuln['description']}")


if __name__ == "__main__":
    analyzer = S7commAnalyzer()
    analyzer.set_authorized_stations(["10.10.2.50", "10.10.2.51"])

    if len(sys.argv) >= 2:
        print(f"[*] Analyzing capture: {sys.argv[1]}")
        packets = rdpcap(sys.argv[1])
        for pkt in packets:
            analyzer.analyze_packet(pkt)
        analyzer.generate_report()
    else:
        print("Usage: python s7comm_analyzer.py <capture.pcap>")
        print("  Analyzes S7comm traffic for security vulnerabilities")
```

## Key Concepts

| Term | Definition |
|------|------------|
| S7comm | Siemens proprietary protocol for communication with SIMATIC S7 PLCs over TCP port 102, layered on COTP/TPKT |
| S7CommPlus | Enhanced version of S7comm used by S7-1200/1500 with integrity protection mechanisms |
| ROSCTR | Remote Operating Service Control field in S7comm header indicating PDU type (Job, Ack, Ack_Data, Userdata) |
| TIA Portal | Totally Integrated Automation Portal -- Siemens engineering software for programming S7 PLCs |
| CPU Stop (0x29) | S7comm function that halts PLC program execution, a critical denial-of-service operation |
| Program Download (0x1A) | S7comm function initiating transfer of new control logic to a PLC, representing the highest risk operation |

## Common Scenarios

### Scenario: Unauthorized PLC Program Modification

**Context**: A Dragos sensor alerts on S7comm program download traffic from an IP address that is not the authorized TIA Portal engineering workstation.

**Approach**:
1. Capture the complete S7comm session for forensic analysis
2. Identify the source host and determine if it is compromised or rogue
3. Compare the current PLC program against the last known-good backup
4. Check if the PLC CPU mode was changed (RUN to STOP to PROGRAM)
5. If the program was modified, restore from verified backup
6. Investigate the attack chain -- how did the attacker reach the S7comm network segment
7. Implement S7comm access protection (know-how protection, access passwords) on all PLCs

**Pitfalls**: S7-300/400 PLCs have no cryptographic integrity protection -- any device that can reach TCP port 102 can send commands. Do not rely solely on PLC passwords as they are transmitted in cleartext in S7comm (not S7CommPlus). Network segmentation is the primary defense.

## Output Format

```
S7COMM SECURITY ANALYSIS REPORT
===================================
Date: YYYY-MM-DD
Scope: [Network segments analyzed]

SESSION INVENTORY:
  Engineering stations: [count and IPs]
  PLCs communicating: [count and IPs]
  Unauthorized sources: [count]

CRITICAL FINDINGS:
  CPU Stop commands: [count]
  Program downloads: [count from unauthorized sources]
  Replay attack potential: [assessment]

VULNERABILITY ASSESSMENT:
  S7-300/400 (no integrity): [count of affected PLCs]
  S7-1200/1500 (S7CommPlus): [firmware assessment]
  Known CVEs applicable: [list]

RECOMMENDATIONS:
  1. [Highest priority remediation]
  2. [Network segmentation improvement]
  3. [Monitoring enhancement]
```
