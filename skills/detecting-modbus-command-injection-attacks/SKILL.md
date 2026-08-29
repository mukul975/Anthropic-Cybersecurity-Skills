---
name: detecting-modbus-command-injection-attacks
description: Detect command injection against Modbus TCP/RTU in ICS/SCADA environments by monitoring unauthorized writes, anomalous function codes, malformed frames, and deviations from communication baselines using ICS-aware IDS and deep packet inspection. Use when deploying IDS for Modbus OT networks, investigating unauthorized PLC register/coil changes, or responding to FrostyGoop-style Modbus attacks. Do not use for broad Modbus traffic baselining and anomaly monitoring covering reconnaissance and denial-of-service - use monitoring-scada-modbus-traffic-anomalies.
domain: cybersecurity
subdomain: ot-ics-security
tags:
- ot-security
- ics
- modbus
- command-injection
- protocol-analysis
- ids
- scada
- threat-detection
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
- GV.OC-02
mitre_attack:
- T1078
- T1190
- T1059
- T1055
- T0816
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

See [references/detection-script.md](references/detection-script.md) for the full `ModbusInjectionDetector` script (MBAP parsing plus six detection rules, live and offline capture modes).


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
