---
name: detecting-stuxnet-style-attacks
description: >
  This skill covers detecting sophisticated cyber-physical attacks that follow the
  Stuxnet attack pattern of modifying PLC logic while spoofing sensor readings to
  hide the manipulation from operators. It addresses PLC logic integrity monitoring,
  physics-based process anomaly detection, engineering workstation compromise indicators,
  USB-borne attack vectors, and multi-stage attack chain detection spanning IT-to-OT
  lateral movement through to process manipulation.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, stuxnet, plc-integrity, apt]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Stuxnet-Style Attacks

## When to Use

- When implementing advanced threat detection for high-value OT targets (nuclear, chemical, critical infrastructure)
- When building detection for APT-style attacks targeting PLC logic and process manipulation
- When establishing PLC logic integrity monitoring to detect unauthorized modifications
- When investigating suspected process anomalies that may indicate cyber-physical attacks
- When designing defense-in-depth strategies against nation-state level OT threats

**Do not use** for basic OT intrusion detection (see detecting-attacks-on-scada-systems), for malware analysis of Stuxnet samples (see malware reverse engineering skills), or for PLC programming and logic development.

## Prerequisites

- Detailed understanding of the Stuxnet attack chain and MITRE ATT&CK for ICS framework
- PLC logic backup repository with known-good baseline copies of all PLC programs
- Engineering workstation monitoring (EDR with OT awareness)
- Physics-based process models for the controlled physical process
- Network monitoring for industrial protocol traffic analysis

## Workflow

### Step 1: Understand the Stuxnet Attack Chain

Map detection opportunities across the multi-stage Stuxnet-style attack chain.

```yaml
# Stuxnet-Style Attack Chain and Detection Points
attack_chain:
  stage_1_initial_access:
    technique: "USB-borne malware targeting air-gapped network"
    mitre_ics: "T0847 - Replication Through Removable Media"
    detection:
      - "USB device connection logging on engineering workstations"
      - "Removable media scanning with OT-approved AV"
      - "Application allowlisting blocking unauthorized executables"
      - "Windows autorun disabled via Group Policy"
    indicators:
      - "New USB device connections to engineering workstations"
      - "Execution of unsigned binaries from removable media"
      - "LNK file exploitation patterns"

  stage_2_lateral_movement:
    technique: "Exploitation of Windows vulnerabilities for network propagation"
    mitre_ics: "T0866 - Exploitation of Remote Services"
    detection:
      - "Network IDS detecting exploit traffic (MS08-067, MS10-061)"
      - "Unusual SMB traffic between engineering workstations"
      - "Windows event logs showing privilege escalation"
      - "New scheduled tasks or services created"
    indicators:
      - "Lateral movement between Level 3-4 Windows systems"
      - "WMI/PsExec execution from unexpected sources"
      - "Pass-the-hash authentication patterns"

  stage_3_ews_compromise:
    technique: "Compromise of engineering workstation with PLC programming software"
    mitre_ics: "T0862 - Supply Chain Compromise (Step-7 hooking)"
    detection:
      - "File integrity monitoring on Step-7/TIA Portal directories"
      - "DLL injection detection in PLC programming software"
      - "Monitoring s7otbxdx.dll for Stuxnet-specific hook"
      - "Unexpected modifications to PLC project files"
    indicators:
      - "Modified DLLs in Siemens STEP 7 installation directory"
      - "Rootkit hiding files on engineering workstation"
      - "PLC programming software behaving abnormally"

  stage_4_plc_logic_modification:
    technique: "Injecting malicious OB/FC blocks into PLC program"
    mitre_ics: "T0839 - Module Firmware / T0833 - Modify Control Logic"
    detection:
      - "PLC logic integrity comparison against known-good baseline"
      - "S7comm upload/download traffic from unauthorized sources"
      - "New OB/FC/FB blocks appearing in PLC program"
      - "Modification of OB1 (main scan) or OB35 (cyclic interrupt)"
    indicators:
      - "PLC program block count changes"
      - "PLC program size changes"
      - "Upload of unknown program blocks"

  stage_5_process_manipulation:
    technique: "Manipulating physical process while spoofing sensor readings"
    mitre_ics: "T0836 - Modify Parameter / T0856 - Spoof Reporting Message"
    detection:
      - "Physics-based anomaly detection (process model deviation)"
      - "Cross-validation of independent sensors"
      - "Vibration analysis and mechanical signature monitoring"
      - "Comparison of PLC-reported values vs independent measurements"
    indicators:
      - "Motor/pump operating outside normal parameters"
      - "Sensor readings diverging from physics model predictions"
      - "Process efficiency metrics deviating unexpectedly"
```

### Step 2: Implement PLC Logic Integrity Monitoring

Continuously monitor PLC program integrity by comparing running logic against known-good baselines.

```python
#!/usr/bin/env python3
"""PLC Logic Integrity Monitor.

Periodically retrieves PLC program block information and compares
against known-good baselines to detect unauthorized modifications
(Stuxnet-style logic injection).
"""

import hashlib
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class PLCBlock:
    """Represents a PLC program block."""
    block_type: str  # OB, FC, FB, DB
    block_number: int
    name: str
    size_bytes: int
    checksum: str
    last_modified: str
    author: str = ""


@dataclass
class IntegrityAlert:
    alert_id: str
    timestamp: str
    severity: str
    plc_name: str
    plc_ip: str
    alert_type: str
    description: str
    baseline_value: str
    current_value: str
    mitre_technique: str


class PLCIntegrityMonitor:
    """Monitors PLC program integrity against baselines."""

    def __init__(self):
        self.baselines = {}  # plc_name -> list of PLCBlock
        self.alerts = []
        self.alert_counter = 1

    def load_baseline(self, plc_name, baseline_file):
        """Load known-good PLC program baseline."""
        with open(baseline_file) as f:
            data = json.load(f)
        blocks = [PLCBlock(**b) for b in data.get("blocks", [])]
        self.baselines[plc_name] = {
            "blocks": {f"{b.block_type}{b.block_number}": b for b in blocks},
            "total_blocks": len(blocks),
            "loaded_at": datetime.now().isoformat(),
        }
        print(f"[*] Loaded baseline for {plc_name}: {len(blocks)} blocks")

    def check_integrity(self, plc_name, plc_ip, current_blocks):
        """Compare current PLC program against baseline."""
        baseline = self.baselines.get(plc_name)
        if not baseline:
            print(f"[WARN] No baseline for {plc_name}")
            return

        baseline_blocks = baseline["blocks"]
        current_block_map = {f"{b.block_type}{b.block_number}": b for b in current_blocks}

        # Check 1: New blocks added (potential logic injection)
        for key, block in current_block_map.items():
            if key not in baseline_blocks:
                self.alerts.append(IntegrityAlert(
                    alert_id=f"INT-{self.alert_counter:04d}",
                    timestamp=datetime.now().isoformat(),
                    severity="critical",
                    plc_name=plc_name,
                    plc_ip=plc_ip,
                    alert_type="NEW_BLOCK_DETECTED",
                    description=(
                        f"New program block {key} ({block.name}) found in PLC "
                        f"that does not exist in baseline. Size: {block.size_bytes} bytes."
                    ),
                    baseline_value="Block does not exist in baseline",
                    current_value=f"{key}: {block.size_bytes} bytes, checksum {block.checksum}",
                    mitre_technique="T0839 - Module Firmware / T0833 - Modify Control Logic",
                ))
                self.alert_counter += 1

        # Check 2: Blocks removed
        for key in baseline_blocks:
            if key not in current_block_map:
                self.alerts.append(IntegrityAlert(
                    alert_id=f"INT-{self.alert_counter:04d}",
                    timestamp=datetime.now().isoformat(),
                    severity="high",
                    plc_name=plc_name,
                    plc_ip=plc_ip,
                    alert_type="BLOCK_REMOVED",
                    description=f"Program block {key} removed from PLC",
                    baseline_value=f"{key}: {baseline_blocks[key].size_bytes} bytes",
                    current_value="Block not found",
                    mitre_technique="T0833 - Modify Control Logic",
                ))
                self.alert_counter += 1

        # Check 3: Block content modified (checksum mismatch)
        for key in baseline_blocks:
            if key in current_block_map:
                baseline_block = baseline_blocks[key]
                current_block = current_block_map[key]

                if baseline_block.checksum != current_block.checksum:
                    self.alerts.append(IntegrityAlert(
                        alert_id=f"INT-{self.alert_counter:04d}",
                        timestamp=datetime.now().isoformat(),
                        severity="critical",
                        plc_name=plc_name,
                        plc_ip=plc_ip,
                        alert_type="BLOCK_MODIFIED",
                        description=(
                            f"Program block {key} checksum mismatch. "
                            f"Logic has been modified since baseline was established."
                        ),
                        baseline_value=f"Checksum: {baseline_block.checksum}, Size: {baseline_block.size_bytes}",
                        current_value=f"Checksum: {current_block.checksum}, Size: {current_block.size_bytes}",
                        mitre_technique="T0833 - Modify Control Logic",
                    ))
                    self.alert_counter += 1

        # Check 4: Block count change
        if len(current_blocks) != baseline["total_blocks"]:
            self.alerts.append(IntegrityAlert(
                alert_id=f"INT-{self.alert_counter:04d}",
                timestamp=datetime.now().isoformat(),
                severity="high",
                plc_name=plc_name,
                plc_ip=plc_ip,
                alert_type="BLOCK_COUNT_CHANGE",
                description=f"Total block count changed from {baseline['total_blocks']} to {len(current_blocks)}",
                baseline_value=str(baseline["total_blocks"]),
                current_value=str(len(current_blocks)),
                mitre_technique="T0833 - Modify Control Logic",
            ))
            self.alert_counter += 1

    def generate_report(self):
        """Generate integrity monitoring report."""
        print(f"\n{'='*70}")
        print("PLC LOGIC INTEGRITY MONITORING REPORT")
        print(f"{'='*70}")
        print(f"Baselines loaded: {len(self.baselines)}")
        print(f"Alerts: {len(self.alerts)}")

        for a in self.alerts:
            print(f"\n  [{a.severity.upper()}] {a.alert_type}")
            print(f"    PLC: {a.plc_name} ({a.plc_ip})")
            print(f"    {a.description}")
            print(f"    Baseline: {a.baseline_value}")
            print(f"    Current: {a.current_value}")
            print(f"    MITRE: {a.mitre_technique}")


if __name__ == "__main__":
    monitor = PLCIntegrityMonitor()
    print("PLC Logic Integrity Monitor")
    print("Load baselines and call check_integrity() periodically")
```

### Step 3: Deploy Physics-Based Process Anomaly Detection

Monitor physical process behavior using models that predict expected sensor values based on the laws of physics. Deviations indicate either equipment failure or cyber-physical attack.

```python
#!/usr/bin/env python3
"""Physics-Based Cyber-Physical Attack Detector.

Uses simplified physics models to detect process manipulation
attacks where the attacker modifies the physical process while
spoofing sensor readings (the core Stuxnet attack pattern).
"""

import math
from dataclasses import dataclass
from datetime import datetime


@dataclass
class PhysicsAlert:
    timestamp: str
    severity: str
    alert_type: str
    sensor_tag: str
    reported_value: float
    predicted_value: float
    deviation_percent: float
    description: str


class CentrifugePhysicsModel:
    """Physics model for a centrifuge system (Stuxnet target analog).

    Detects manipulation by cross-correlating:
    - Motor frequency (Hz) vs reported RPM
    - RPM vs vibration signature
    - Power consumption vs rotational speed
    """

    def __init__(self, rated_rpm=1200, rated_frequency=50, rated_power_kw=75):
        self.rated_rpm = rated_rpm
        self.rated_frequency = rated_frequency
        self.rated_power_kw = rated_power_kw
        self.alerts = []

    def check_frequency_rpm_correlation(self, frequency_hz, reported_rpm):
        """Verify motor frequency matches reported RPM.

        For an induction motor: RPM = 120 * frequency / poles
        If RPM is being spoofed, it won't match the actual frequency.
        """
        # Assuming 4-pole motor with typical 3% slip
        expected_rpm = (120 * frequency_hz / 4) * 0.97
        deviation = abs(reported_rpm - expected_rpm) / expected_rpm * 100

        if deviation > 5.0:
            self.alerts.append(PhysicsAlert(
                timestamp=datetime.now().isoformat(),
                severity="critical",
                alert_type="FREQUENCY_RPM_MISMATCH",
                sensor_tag="MOTOR.RPM vs VFD.FREQ",
                reported_value=reported_rpm,
                predicted_value=round(expected_rpm, 1),
                deviation_percent=round(deviation, 1),
                description=(
                    f"Motor RPM ({reported_rpm}) does not match VFD frequency "
                    f"({frequency_hz} Hz). Expected ~{expected_rpm:.0f} RPM. "
                    f"Possible RPM sensor spoofing while frequency is manipulated."
                ),
            ))

    def check_power_speed_correlation(self, rpm, power_kw):
        """Verify power consumption matches rotational speed.

        Power scales approximately with RPM^3 for centrifugal loads.
        """
        speed_ratio = rpm / self.rated_rpm
        expected_power = self.rated_power_kw * (speed_ratio ** 3)
        deviation = abs(power_kw - expected_power) / max(expected_power, 0.1) * 100

        if deviation > 15.0:
            self.alerts.append(PhysicsAlert(
                timestamp=datetime.now().isoformat(),
                severity="high",
                alert_type="POWER_SPEED_MISMATCH",
                sensor_tag="MOTOR.POWER vs MOTOR.RPM",
                reported_value=power_kw,
                predicted_value=round(expected_power, 1),
                deviation_percent=round(deviation, 1),
                description=(
                    f"Power consumption ({power_kw} kW) inconsistent with RPM ({rpm}). "
                    f"Expected ~{expected_power:.1f} kW. May indicate hidden speed changes."
                ),
            ))

    def check_vibration_anomaly(self, rpm, vibration_mm_s):
        """Check if vibration signature is consistent with operating speed.

        Abnormal vibration at reported 'normal' speed may indicate actual
        speed is different from what sensors report.
        """
        # Normal vibration increases linearly with speed for balanced rotor
        speed_ratio = rpm / self.rated_rpm
        expected_vibration = 2.0 * speed_ratio  # mm/s baseline
        deviation = abs(vibration_mm_s - expected_vibration) / max(expected_vibration, 0.1) * 100

        if vibration_mm_s > 7.0:  # ISO 10816 alert threshold
            self.alerts.append(PhysicsAlert(
                timestamp=datetime.now().isoformat(),
                severity="critical",
                alert_type="ABNORMAL_VIBRATION",
                sensor_tag="MOTOR.VIBRATION",
                reported_value=vibration_mm_s,
                predicted_value=round(expected_vibration, 1),
                deviation_percent=round(deviation, 1),
                description=(
                    f"Vibration ({vibration_mm_s} mm/s) at ISO alert level while "
                    f"RPM reports normal ({rpm}). Actual speed may differ from reported."
                ),
            ))

    def report(self):
        if self.alerts:
            print(f"\n{'='*60}")
            print("PHYSICS-BASED ANOMALY DETECTION ALERTS")
            print(f"{'='*60}")
            for a in self.alerts:
                print(f"\n  [{a.severity.upper()}] {a.alert_type}")
                print(f"    {a.description}")
                print(f"    Reported: {a.reported_value} | Predicted: {a.predicted_value}")
                print(f"    Deviation: {a.deviation_percent}%")


if __name__ == "__main__":
    model = CentrifugePhysicsModel(rated_rpm=1200, rated_frequency=50, rated_power_kw=75)

    # Normal operation - no alerts expected
    model.check_frequency_rpm_correlation(50.0, 1164)
    model.check_power_speed_correlation(1164, 72.0)

    # Stuxnet-style attack: frequency increased but RPM spoofed as normal
    model.check_frequency_rpm_correlation(84.0, 1164)  # freq up, RPM spoofed
    model.check_power_speed_correlation(1164, 180.0)    # power reveals true speed

    model.report()
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cyber-Physical Attack | Attack that manipulates both the cyber system (PLC logic, sensor readings) and the physical process simultaneously |
| Logic Injection | Inserting malicious code blocks into PLC programs to alter physical process behavior |
| Sensor Spoofing | Replaying or fabricating sensor readings to hide process manipulation from operators |
| Physics-Based Detection | Using mathematical models of physical processes to detect when reported sensor values are inconsistent with actual physics |
| PLC Logic Baseline | Known-good copy of PLC program blocks (OB, FC, FB, DB) used for integrity comparison |
| Air-Gap Bridging | Technique of crossing air-gapped networks via USB drives, as used by Stuxnet's initial access method |

## Tools & Systems

- **Claroty xDome**: Continuous PLC logic monitoring with baseline comparison and change detection
- **SIGA OT Solutions**: Physical signal monitoring at the electrical level for detecting process manipulation
- **Nozomi Guardian**: OT monitoring with PLC program change detection capabilities
- **Siemens SINEMA Remote Connect**: Secure remote access with PLC project version tracking

## Output Format

```
Stuxnet-Style Attack Detection Report
========================================
Monitored PLCs: [N]
Monitoring Period: YYYY-MM-DD to YYYY-MM-DD

PLC INTEGRITY:
  Baselines verified: [N]/[N]
  Logic modifications detected: [N]
  New blocks detected: [N]

PHYSICS ANOMALIES:
  Sensor correlation violations: [N]
  Process model deviations: [N]

ENGINEERING WORKSTATION:
  Unauthorized modifications: [N]
  USB connections: [N]
```
