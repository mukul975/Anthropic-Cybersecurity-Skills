---
name: performing-plc-firmware-security-analysis
description: >
  This skill covers analyzing Programmable Logic Controller (PLC) firmware for security
  vulnerabilities including hardcoded credentials, insecure update mechanisms, backdoor
  functions, memory corruption flaws, and undocumented debug interfaces. It addresses
  firmware extraction from common PLC platforms (Siemens S7, Allen-Bradley, Schneider
  Modicon), static analysis of firmware images, dynamic analysis in emulated environments,
  and comparison against known-good baselines to detect tampering.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, firmware-analysis, plc-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing PLC Firmware Security Analysis

## When to Use

- When assessing PLC security as part of an IEC 62443 component security evaluation (IEC 62443-4-2)
- When validating firmware integrity after a suspected compromise or supply chain attack
- When evaluating the security of a new PLC platform before deployment in critical infrastructure
- When performing vulnerability research on industrial control system devices in an authorized lab
- When responding to an incident where PLC logic or firmware tampering is suspected

**Do not use** on live production PLCs without explicit authorization and safety controls in place. Firmware extraction and analysis should be performed on lab devices or offline backups. Never upload PLC firmware to public analysis services. See performing-ics-penetration-testing for authorized live testing procedures.

## Prerequisites

- Isolated lab environment with the target PLC hardware or an emulated environment
- PLC programming software for the target platform (Siemens TIA Portal, Rockwell Studio 5000, Schneider EcoStruxure)
- Firmware extraction tools (binwalk, firmware-mod-kit, JTAG/SWD debugger)
- Static analysis tools (Ghidra, IDA Pro, Binary Ninja with ARM/MIPS/PowerPC support)
- Understanding of PLC architecture (real-time OS, ladder logic execution, I/O scanning)
- Reference copy of known-good firmware for integrity comparison

## Workflow

### Step 1: Acquire PLC Firmware for Analysis

Extract or obtain PLC firmware through authorized methods. This can be done by downloading from the vendor, extracting from a lab device, or obtaining from a project backup.

```python
#!/usr/bin/env python3
"""PLC Firmware Acquisition and Integrity Verification.

Supports firmware extraction from project files, network downloads,
and binary image comparison against known-good baselines.
"""

import hashlib
import json
import os
import struct
import sys
import zipfile
from datetime import datetime
from pathlib import Path


class PLCFirmwareAcquisition:
    """Handles PLC firmware acquisition from various sources."""

    def __init__(self, output_dir="firmware_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.manifest = {
            "acquisition_date": datetime.now().isoformat(),
            "firmware_samples": [],
        }

    def extract_from_siemens_project(self, project_path):
        """Extract firmware/program blocks from Siemens TIA Portal project.

        TIA Portal projects (.ap16/.ap17) are ZIP archives containing
        XML-encoded PLC program blocks and system configuration.
        """
        print(f"[*] Analyzing Siemens project: {project_path}")
        results = {"platform": "Siemens", "blocks": []}

        if zipfile.is_zipfile(project_path):
            with zipfile.ZipFile(project_path, "r") as zf:
                for info in zf.infolist():
                    # Program blocks are stored as XML in specific paths
                    if "ProgramBlocks" in info.filename or "SystemBlocks" in info.filename:
                        block_data = zf.read(info.filename)
                        block_hash = hashlib.sha256(block_data).hexdigest()

                        block_path = self.output_dir / info.filename.replace("/", "_")
                        block_path.write_bytes(block_data)

                        results["blocks"].append({
                            "name": info.filename,
                            "size": info.file_size,
                            "sha256": block_hash,
                            "extracted_to": str(block_path),
                        })
                        print(f"  [+] Extracted: {info.filename} ({info.file_size} bytes)")

        self.manifest["firmware_samples"].append(results)
        return results

    def extract_from_rockwell_project(self, acd_path):
        """Extract program data from Rockwell Studio 5000 ACD file.

        ACD files contain controller program, tags, and configuration.
        """
        print(f"[*] Analyzing Rockwell project: {acd_path}")
        results = {"platform": "Rockwell/Allen-Bradley", "blocks": []}

        with open(acd_path, "rb") as f:
            header = f.read(256)
            # ACD files have a specific signature
            if b"RSLogix" in header or b"Studio 5000" in header:
                f.seek(0)
                full_data = f.read()
                file_hash = hashlib.sha256(full_data).hexdigest()

                results["blocks"].append({
                    "name": os.path.basename(acd_path),
                    "size": len(full_data),
                    "sha256": file_hash,
                    "header_signature": header[:16].hex(),
                })
                print(f"  [+] Project hash: {file_hash}")

        self.manifest["firmware_samples"].append(results)
        return results

    def compute_firmware_hash(self, firmware_path):
        """Compute multiple hashes of a firmware image for integrity tracking."""
        data = Path(firmware_path).read_bytes()
        return {
            "file": str(firmware_path),
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    def compare_firmware_integrity(self, current_fw, baseline_fw):
        """Compare current firmware against known-good baseline."""
        current_hash = self.compute_firmware_hash(current_fw)
        baseline_hash = self.compute_firmware_hash(baseline_fw)

        match = current_hash["sha256"] == baseline_hash["sha256"]

        result = {
            "comparison_date": datetime.now().isoformat(),
            "current_firmware": current_hash,
            "baseline_firmware": baseline_hash,
            "integrity_match": match,
            "verdict": "PASS - Firmware matches baseline" if match else "FAIL - Firmware modified!",
        }

        if not match:
            # Find the offset where files diverge
            current_data = Path(current_fw).read_bytes()
            baseline_data = Path(baseline_fw).read_bytes()
            min_len = min(len(current_data), len(baseline_data))

            first_diff = None
            diff_count = 0
            for i in range(min_len):
                if current_data[i] != baseline_data[i]:
                    if first_diff is None:
                        first_diff = i
                    diff_count += 1

            result["first_difference_offset"] = f"0x{first_diff:08x}" if first_diff else None
            result["total_different_bytes"] = diff_count
            result["size_difference"] = len(current_data) - len(baseline_data)

        return result

    def save_manifest(self):
        """Save acquisition manifest."""
        manifest_path = self.output_dir / "acquisition_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(self.manifest, f, indent=2)
        print(f"\n[*] Manifest saved: {manifest_path}")


if __name__ == "__main__":
    acq = PLCFirmwareAcquisition()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python process.py extract-siemens <project.ap17>")
        print("  python process.py extract-rockwell <project.acd>")
        print("  python process.py compare <current.bin> <baseline.bin>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "extract-siemens" and len(sys.argv) > 2:
        acq.extract_from_siemens_project(sys.argv[2])
    elif cmd == "extract-rockwell" and len(sys.argv) > 2:
        acq.extract_from_rockwell_project(sys.argv[2])
    elif cmd == "compare" and len(sys.argv) > 3:
        result = acq.compare_firmware_integrity(sys.argv[2], sys.argv[3])
        print(json.dumps(result, indent=2))
    else:
        print("Invalid command")
        sys.exit(1)

    acq.save_manifest()
```

### Step 2: Perform Static Analysis of Firmware Image

Use binwalk for firmware unpacking and Ghidra for disassembly to identify security issues in the firmware binary.

```bash
# Step 2a: Unpack firmware image with binwalk
binwalk -e firmware.bin
# Output: _firmware.bin.extracted/

# Identify firmware components
binwalk firmware.bin
# Look for: file system images, compressed sections, bootloader, RTOS kernel

# Extract strings for credential and configuration analysis
strings -n 8 firmware.bin > firmware_strings.txt

# Search for hardcoded credentials
grep -iE "(password|passwd|pwd|secret|key|credential|login|admin|root)" firmware_strings.txt

# Search for network configuration
grep -iE "(http|ftp|telnet|ssh|snmp|modbus|192\.168|10\.|172\.)" firmware_strings.txt

# Search for debug/backdoor indicators
grep -iE "(debug|backdoor|test_mode|factory|service_port|hidden)" firmware_strings.txt

# Search for cryptographic material
grep -iE "(BEGIN RSA|BEGIN CERTIFICATE|AES|DES|private.key)" firmware_strings.txt

# Step 2b: Entropy analysis to detect encrypted/compressed sections
binwalk -E firmware.bin
# High entropy sections may contain encrypted payloads or compressed data

# Step 2c: Analyze with Ghidra (headless mode)
analyzeHeadless /tmp/ghidra_project PLC_FW \
  -import firmware.bin \
  -processor ARM:LE:32:Cortex \
  -postScript FindCryptoConstants.java \
  -postScript FindHardcodedStrings.java \
  -log /tmp/ghidra_analysis.log
```

### Step 3: Analyze PLC Communication Stack Security

Examine how the PLC handles industrial protocol requests, focusing on authentication bypass, buffer overflows in packet parsing, and command injection vulnerabilities.

```python
#!/usr/bin/env python3
"""PLC Protocol Security Analyzer.

Tests PLC protocol implementation for common vulnerabilities
including authentication bypass, malformed packet handling,
and function code access control.

WARNING: Only run against lab/test PLCs, never production systems.
"""

import socket
import struct
import sys
import time
from dataclasses import dataclass


@dataclass
class ProtocolTestResult:
    test_name: str
    target: str
    protocol: str
    result: str  # PASS, FAIL, ERROR
    severity: str
    detail: str


class ModbusSecurityTester:
    """Tests Modbus/TCP implementation security."""

    def __init__(self, target_ip, target_port=502):
        self.target = target_ip
        self.port = target_port
        self.results = []

    def _send_modbus(self, unit_id, func_code, data=b""):
        """Send a Modbus/TCP request and return response."""
        # MBAP Header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
        mbap = struct.pack(">HHHB", 0x0001, 0x0000, len(data) + 2, unit_id)
        pdu = struct.pack("B", func_code) + data

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(mbap + pdu)
            response = sock.recv(1024)
            sock.close()
            return response
        except Exception as e:
            return None

    def test_authentication_required(self):
        """Test if PLC requires authentication for read/write operations."""
        # Test unauthenticated read
        read_data = struct.pack(">HH", 0, 10)  # Read 10 registers from address 0
        response = self._send_modbus(1, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="Modbus Authentication - Read",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC accepts unauthenticated Modbus read commands. No authentication required.",
            ))

        # Test unauthenticated write
        write_data = struct.pack(">HH", 100, 0)  # Write 0 to register 100
        response = self._send_modbus(1, 6, write_data)

        if response and len(response) > 8 and response[7] != 0x86:
            self.results.append(ProtocolTestResult(
                test_name="Modbus Authentication - Write",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="critical",
                detail="PLC accepts unauthenticated Modbus WRITE commands. Any host can modify registers.",
            ))

    def test_function_code_access_control(self):
        """Test if PLC restricts dangerous function codes."""
        dangerous_funcs = {
            8: "Diagnostics (can restart communications)",
            17: "Report Slave ID (information disclosure)",
            43: "Encapsulated Interface Transport (device identification)",
        }

        for fc, desc in dangerous_funcs.items():
            response = self._send_modbus(1, fc, b"\x00\x00")
            if response and len(response) > 8:
                error_code = response[7]
                if error_code != (fc | 0x80):  # Not an exception response
                    self.results.append(ProtocolTestResult(
                        test_name=f"Function Code Access - FC{fc}",
                        target=self.target,
                        protocol="Modbus/TCP",
                        result="FAIL",
                        severity="medium",
                        detail=f"PLC responds to FC{fc} ({desc}) without access control",
                    ))

    def test_invalid_unit_id(self):
        """Test PLC response to broadcast and invalid unit IDs."""
        # Broadcast (unit ID 0) - should be carefully handled
        read_data = struct.pack(">HH", 0, 1)
        response = self._send_modbus(0, 3, read_data)

        if response and len(response) > 8 and response[7] != 0x83:
            self.results.append(ProtocolTestResult(
                test_name="Broadcast Unit ID Handling",
                target=self.target,
                protocol="Modbus/TCP",
                result="FAIL",
                severity="high",
                detail="PLC responds to broadcast unit ID 0. This enables broadcast write attacks.",
            ))

    def test_malformed_packet_handling(self):
        """Test PLC resilience against malformed Modbus packets."""
        # Oversized length field
        malformed = struct.pack(">HHH", 0x0001, 0x0000, 0xFFFF) + b"\x01\x03\x00\x00\x00\x01"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            sock.send(malformed)
            time.sleep(1)

            # Verify PLC is still responsive
            read_data = struct.pack(">HH", 0, 1)
            response = self._send_modbus(1, 3, read_data)
            sock.close()

            if response is None:
                self.results.append(ProtocolTestResult(
                    test_name="Malformed Packet - Oversized Length",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="FAIL",
                    severity="critical",
                    detail="PLC became unresponsive after receiving oversized length field. Possible DoS vulnerability.",
                ))
            else:
                self.results.append(ProtocolTestResult(
                    test_name="Malformed Packet - Oversized Length",
                    target=self.target,
                    protocol="Modbus/TCP",
                    result="PASS",
                    severity="info",
                    detail="PLC correctly handles oversized length field without crashing",
                ))
        except Exception as e:
            pass

    def run_all_tests(self):
        """Run all Modbus security tests."""
        print(f"\n{'='*60}")
        print(f"PLC MODBUS SECURITY ANALYSIS - {self.target}:{self.port}")
        print(f"{'='*60}")

        self.test_authentication_required()
        self.test_function_code_access_control()
        self.test_invalid_unit_id()
        self.test_malformed_packet_handling()

        for r in self.results:
            icon = "[FAIL]" if r.result == "FAIL" else "[PASS]"
            print(f"\n  {icon} {r.test_name}")
            print(f"    Severity: {r.severity}")
            print(f"    Detail: {r.detail}")

        return self.results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python plc_protocol_tester.py <target_plc_ip> [port]")
        print("WARNING: Only use against lab/test PLCs!")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502

    tester = ModbusSecurityTester(target, port)
    tester.run_all_tests()
```

## Key Concepts

| Term | Definition |
|------|------------|
| PLC Firmware | The embedded software running on a Programmable Logic Controller, including the real-time operating system, protocol stacks, and I/O drivers |
| Ladder Logic | Graphical programming language for PLCs that represents relay logic circuits, stored as program blocks in PLC memory |
| Function Block | Reusable PLC programming element that encapsulates logic with defined inputs/outputs, can be analyzed for malicious modifications |
| Firmware Integrity | Verification that PLC firmware has not been modified from the vendor-supplied or approved version using cryptographic hash comparison |
| IEC 62443-4-2 | Component security requirements in the IEC 62443 standard, defining security capabilities required for IACS components including PLCs |
| JTAG/SWD | Hardware debug interfaces (Joint Test Action Group / Serial Wire Debug) used for firmware extraction and low-level analysis |

## Tools & Systems

- **Binwalk**: Firmware analysis tool for scanning, extracting, and analyzing embedded firmware images
- **Ghidra**: NSA-developed reverse engineering framework supporting ARM, MIPS, PowerPC architectures common in PLCs
- **EMUX/FIRMADYNE**: Firmware emulation frameworks for dynamic analysis of embedded device firmware
- **PLCinject**: Research tool for analyzing PLC logic injection vulnerabilities (use only in authorized lab settings)
- **OpenPLC**: Open-source PLC platform useful as a test target for security research

## Output Format

```
PLC Firmware Security Analysis Report
=======================================
Device: [PLC Model and Firmware Version]
Analysis Date: YYYY-MM-DD
Methodology: Static + Dynamic Analysis

FIRMWARE INTEGRITY:
  SHA-256: [hash]
  Baseline Match: [Yes/No]
  Vendor Signature Valid: [Yes/No/Not Signed]

VULNERABILITIES FOUND:
  [PLC-001] [Severity] [Title]
    CWE: [CWE-ID]
    Detail: [Technical description]
    Impact: [Operational impact]
    Remediation: [Fix or mitigation]
```
