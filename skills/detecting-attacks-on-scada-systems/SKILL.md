---
name: detecting-attacks-on-scada-systems
description: Detects cyber attacks targeting Supervisory Control and Data Acquisition (SCADA) systems including man-in-the-middle attacks on industrial protocols, unauthorized command injection into PLCs, HMI compromise, historian data manipulation, and denial-of-service against control system communications, leveraging OT-specific intrusion detection systems, industrial protocol anomaly detection, and process data analytics to identify attacks that traditional IT security tools miss. Use when detecting man-in-the-middle, command injection, HMI compromise, or denial-of-service attacks against SCADA control systems. Do not use for proactively assessing SCADA HMI security posture - use performing-scada-hmi-security-assessment.
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- scada
- industrial-control
- iec62443
- intrusion-detection
- threat-detection
version: 1.0.0
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T0846
- T0836
- T0831
- T0814
- T0832
---

# Detecting Attacks on SCADA Systems

## When to Use

- When deploying intrusion detection capabilities in a SCADA environment for the first time
- When investigating suspected cyber attacks against industrial control systems
- When building detection rules for OT-specific attack patterns (Stuxnet, TRITON, Industroyer)
- When integrating OT network monitoring with an enterprise SOC for unified threat visibility
- When responding to alerts from OT security monitoring tools (Dragos, Nozomi, Claroty)

**Do not use** for detecting attacks on IT-only networks without SCADA/ICS components, for building generic network IDS rules (see building-detection-rules-with-sigma), or for incident response procedures after an attack is confirmed (see performing-ot-incident-response).

## Prerequisites

- Passive network monitoring sensors deployed on SPAN/TAP ports at OT network boundaries
- OT intrusion detection system (Dragos Platform, Nozomi Guardian, Claroty xDome, or Suricata with OT rulesets)
- Understanding of industrial protocols in use (Modbus, DNP3, OPC UA, EtherNet/IP, S7comm)
- Baseline of normal SCADA communication patterns (polling intervals, function codes, register ranges)
- Access to process historian data for physical process anomaly correlation

## Workflow

### Step 1: Establish SCADA Communication Baselines

Before detecting anomalies, establish what normal SCADA traffic looks like. Industrial protocols are highly deterministic - the same master polls the same slaves at the same intervals reading the same registers.

The `SCADABaselineBuilder` parses pcap captures to profile Modbus/TCP sessions - allowed function codes, register ranges, polling intervals (mean and stddev), and communication pairs - then exports a JSON baseline used by later detection steps.

See the full baseline-builder script in [references/detection-code.md](references/detection-code.md#step-1-scada-communication-baseline-builder).

### Step 2: Deploy OT-Specific Detection Rules

Create detection rules for known SCADA attack patterns including those used by TRITON, Industroyer/CrashOverride, and PIPEDREAM/INCONTROLLER.

The rule pack covers Modbus (unauthorized writes, diagnostics/restart, broadcast writes), S7comm (CPU STOP, program download), DNP3 (cold restart, firmware update), and network anomalies (unauthorized devices, OT port scans).

See the full Suricata OT ruleset in [references/detection-code.md](references/detection-code.md#step-2-ot-specific-suricata-detection-rules).

### Step 3: Implement Process Data Anomaly Detection

Monitor physical process data from the historian to detect attacks that manipulate the process while hiding their effects from operators (the Stuxnet attack pattern).

The `ProcessAnomalyDetector` polls the historian API and applies four detection rules per process variable: out-of-range (engineering limits), rate-of-change violation, flatline detection (Stuxnet-style frozen sensor), and z-score statistical anomaly. Each anomaly is tagged with a candidate attack pattern.

See the full process-anomaly detector script in [references/detection-code.md](references/detection-code.md#step-3-scada-process-data-anomaly-detector).

### Step 4: Detect Known ICS Malware Indicators

Monitor for indicators of compromise (IOCs) associated with known ICS-targeting malware families.

The signature catalog covers TRITON/TRISIS (Triconex SIS), Industroyer/CrashOverride (IEC 60870-5-104, IEC 61850, OPC DA), and PIPEDREAM/INCONTROLLER (CODESYS, OPC UA, Modbus), each with network indicators, host indicators, and a Suricata detection rule.

See the full ICS malware signature catalog in [references/detection-code.md](references/detection-code.md#step-4-known-ics-malware-detection-signatures).

## Key Concepts

| Term | Definition |
|------|------------|
| SCADA | Supervisory Control and Data Acquisition - architecture for remote monitoring and control of industrial processes via RTUs and communication infrastructure |
| IDS/IPS for OT | Intrusion Detection/Prevention Systems designed for industrial protocols, using both signature-based and anomaly-based detection methods |
| Process Anomaly | Deviation in physical process behavior (temperature, pressure, flow) that may indicate cyber manipulation of control systems |
| Man-in-the-Middle (MITM) | Attack intercepting communication between SCADA master and field devices to modify commands or spoof sensor readings |
| Replay Attack | Capturing legitimate SCADA traffic and replaying it to mask malicious changes to the process (used by Stuxnet) |
| Protocol Anomaly | Deviation from expected industrial protocol behavior including unauthorized function codes, unusual polling patterns, or command sequences |

## Tools & Systems

- **Dragos Platform**: OT cybersecurity platform with threat detection powered by Dragos threat intelligence on ICS-targeting activity groups
- **Nozomi Networks Guardian**: OT/IoT visibility and threat detection using asset intelligence, anomaly detection, and vulnerability assessment
- **Claroty xDome**: Cyber-physical systems protection with continuous threat monitoring and alert prioritization
- **Suricata with ET Open ICS rules**: Open-source IDS/IPS with community-maintained rules for industrial protocol detection
- **Zeek (Bro) with OT scripts**: Network security monitor with protocol analyzers for Modbus, DNP3, and BACnet

## Common Scenarios

### Scenario: Detecting TRITON-Style Attack on Safety Systems

**Context**: An OT security monitoring system alerts on unusual TriStation protocol traffic to a Triconex safety controller from an IP address that is not the authorized SIS engineering workstation.

**Approach**:
1. Immediately verify the source IP of the TriStation traffic - is it the authorized SIS engineering workstation or a compromised host?
2. Check if there is an authorized maintenance activity scheduled for the SIS controllers
3. Capture full packet payload of the TriStation communication for forensic analysis
4. Alert the process safety team - SIS compromise is a safety-critical event
5. If unauthorized, isolate the source host from the network immediately
6. Verify SIS controller logic integrity by comparing running logic against known-good backup
7. Check all engineering workstations in the facility for TRITON indicators (trilog.exe, inject.bin)

**Pitfalls**: Never assume SIS traffic anomalies are false positives - TRITON demonstrated that sophisticated attackers specifically target safety systems. Do not restart the SIS controller without first verifying firmware and logic integrity. Avoid alerting only the IT SOC; the process safety team must be immediately engaged for any SIS-related incident.

## Output Format

```
SCADA Attack Detection Report
===============================
Detection Time: YYYY-MM-DD HH:MM:SS UTC
Detection Source: [IDS/Anomaly Detector/Process Monitor]

ALERT DETAILS:
  Alert ID: [unique identifier]
  Severity: Critical/High/Medium/Low
  Attack Category: [Protocol Anomaly/Process Manipulation/Unauthorized Access]
  MITRE ATT&CK for ICS: [Technique ID and name]

  Source: [IP/hostname]
  Target: [IP/hostname - device type]
  Protocol: [Modbus/DNP3/S7comm/etc]
  Detail: [Specific finding description]

BASELINE COMPARISON:
  Normal: [Expected behavior]
  Observed: [Actual behavior that triggered alert]
  Deviation: [How the observed differs from baseline]

RECOMMENDED RESPONSE:
  1. [Immediate containment action]
  2. [Verification step]
  3. [Escalation path]
```
