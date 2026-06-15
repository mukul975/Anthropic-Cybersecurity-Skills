---
name: detecting-bluetooth-low-energy-attacks
description: 'Detects and analyzes Bluetooth Low Energy (BLE) security attacks including
  sniffing, replay attacks, GATT enumeration abuse, and Man-in-the-Middle interception.
  Uses Ubertooth One and nRF52840 sniffers for packet capture, the bleak Python library
  for GATT service enumeration, and crackle for BLE encryption cracking. Use when
  assessing IoT device BLE security, monitoring for BLE-based attacks on wireless
  infrastructure, or performing authorized BLE penetration testing. Activates for
  requests involving BLE security assessment, Ubertooth sniffing, GATT enumeration,
  or BLE replay detection.

  '
domain: cybersecurity
subdomain: wireless-security
author: mukul975
tags:
- ble
- bluetooth
- ubertooth
- nrf-sniffer
- gatt
- wireless-security
- iot-security
- replay-attack
version: 1.0.0
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
mitre_attack:
- T1011.001
- T1557
- T1040
- T1200
---
# Detecting Bluetooth Low Energy Attacks

## Disclaimer

This skill is intended for authorized security testing, penetration testing engagements, CTF competitions, and educational purposes only. Sniffing, intercepting, or manipulating Bluetooth communications without authorization may violate federal wiretapping laws and local regulations. Always obtain explicit written permission before conducting any wireless security assessment.

## When to Use

Use this skill when:
- Performing authorized BLE security assessments of IoT devices, medical devices, or smart locks
- Monitoring a wireless environment for BLE-based replay attacks, spoofing, or unauthorized enumeration
- Analyzing BLE packet captures to detect Man-in-the-Middle attacks or pairing exploitation
- Enumerating GATT services and characteristics to identify insecure read/write permissions on BLE peripherals
- Assessing BLE encryption strength and testing for crackable pairing exchanges
- Building BLE intrusion detection capabilities for wireless security monitoring

**Do not use** for intercepting BLE communications without explicit authorization. Do not deploy BLE scanning tools in environments where wireless monitoring is prohibited.

## Prerequisites

- Ubertooth One hardware for passive BLE sniffing, or Nordic nRF52840 USB Dongle with nRF Sniffer firmware
- Python 3.10+ with pip
- bleak library: `pip install bleak` (cross-platform BLE GATT client)
- Wireshark with BLE dissector plugins for packet analysis
- crackle tool for BLE encryption analysis: built from source at github.com/mikeryan/crackle
- ubertooth-btle CLI tools: `apt install ubertooth` (Linux) or build from source
- Bluetooth 4.0+ adapter on the host system for bleak-based scanning
- Linux recommended for full Ubertooth/nRF sniffer support

## Workflow

### Step 1: BLE Environment Discovery and Device Scanning

Scan the environment to identify BLE devices and their advertising data:

```bash
# Scan for BLE devices using bleak (cross-platform)
python -c "
import asyncio
from bleak import BleakScanner

async def scan():
    devices = await BleakScanner.discover(timeout=10.0)
    for d in devices:
        print(f'{d.address} | RSSI: {d.rssi} | Name: {d.name or \"Unknown\"}')
        for uuid in d.metadata.get('uuids', []):
            print(f'  Service: {uuid}')

asyncio.run(scan())
"

# Passive BLE sniffing with Ubertooth One (promiscuous mode)
ubertooth-btle -p -r capture.pcapng

# Follow a specific BLE connection
ubertooth-btle -f -t AA:BB:CC:DD:EE:FF -r connection.pcapng

# Use nRF Sniffer with Wireshark (via extcap interface)
wireshark -i nRF_Sniffer -k
```

### Step 2: GATT Service and Characteristic Enumeration

Connect to target BLE peripherals and enumerate their GATT profile:

```bash
# Enumerate all services, characteristics, and descriptors
python -c "
import asyncio
from bleak import BleakClient

async def enum_gatt(address):
    async with BleakClient(address) as client:
        print(f'Connected: {client.is_connected}')
        for service in client.services:
            print(f'Service: {service.uuid} - {service.description}')
            for char in service.characteristics:
                props = ','.join(char.properties)
                print(f'  Char: {char.uuid} | Props: {props}')
                for desc in char.descriptors:
                    val = await client.read_gatt_descriptor(desc.handle)
                    print(f'    Desc: {desc.uuid} = {val}')

asyncio.run(enum_gatt('AA:BB:CC:DD:EE:FF'))
"
```

Security-relevant findings during GATT enumeration:
- Characteristics with `write-without-response` or `write` without authentication
- Readable characteristics exposing device configuration, credentials, or firmware versions
- Missing Client Characteristic Configuration Descriptor (CCCD) protection on notification characteristics

### Step 3: BLE Packet Capture and Analysis

Capture BLE traffic for offline analysis:

```bash
# Capture with Ubertooth in PcapNG format (recommended)
ubertooth-btle -f -r capture.pcapng

# Capture in PCAP/PPI format for crackle compatibility
ubertooth-btle -f -c capture_ppi.pcap

# Analyze capture in Wireshark
wireshark capture.pcapng
# Apply display filter: btle
# Filter connection requests: btle.advertising_header.pdu_type == 0x05
# Filter data packets: btle.data_header

# Extract pairing information with tshark
tshark -r capture.pcapng -Y "btle.control_opcode == 0x01" -T fields \
  -e btle.master_bd_addr -e btle.slave_bd_addr
```

### Step 4: BLE Encryption Analysis with Crackle

Analyze captured pairing exchanges to test encryption strength:

```bash
# Crack BLE Legacy Pairing (Just Works / passkey)
crackle -i capture_ppi.pcap -o decrypted.pcap

# Crack with known Temporary Key (TK)
crackle -i capture_ppi.pcap -o decrypted.pcap -l 000000

# Analyze decrypted traffic
wireshark decrypted.pcap
```

BLE Legacy Pairing with Just Works mode uses a TK of all zeros, making it trivially
crackable. Passkey entry uses a 6-digit PIN (000000-999999) that can be brute-forced
in under a second. Only BLE Secure Connections (LE Secure Connections with ECDH)
provides adequate protection against passive eavesdropping.

### Step 5: Replay Attack Detection and Testing

Monitor for and test BLE replay attack susceptibility:

```bash
# Capture characteristic write operations
# Record the raw bytes written to a target characteristic
# Then replay the exact same bytes to test if the device accepts stale commands

python -c "
import asyncio
from bleak import BleakClient

TARGET = 'AA:BB:CC:DD:EE:FF'
CHAR_UUID = '0000fff1-0000-1000-8000-00805f9b34fb'

async def replay_test():
    async with BleakClient(TARGET) as client:
        # Step 1: Read current state
        val = await client.read_gatt_char(CHAR_UUID)
        print(f'Current value: {val.hex()}')

        # Step 2: Write a command (captured from previous session)
        captured_command = bytes.fromhex('0102030405')
        await client.write_gatt_char(CHAR_UUID, captured_command)
        print('Replayed captured command')

        # Step 3: Verify if command was accepted
        new_val = await client.read_gatt_char(CHAR_UUID)
        print(f'New value: {new_val.hex()}')
        if new_val != val:
            print('VULNERABLE: Device accepted replayed command')

asyncio.run(replay_test())
"
```

Indicators of replay vulnerability:
- Device accepts previously captured write commands without freshness validation
- No sequence number, timestamp, or challenge-response mechanism in the protocol
- Device state changes in response to replayed commands

### Step 6: Man-in-the-Middle Detection

Detect BLE MITM attacks by monitoring for anomalous behavior:

```bash
# Monitor for BLE address spoofing (device impersonation)
# Compare advertising data fingerprints over time

# Monitor for unexpected connection parameter changes
tshark -r capture.pcapng -Y "btle.control_opcode == 0x00" -T fields \
  -e btle.control.interval.min -e btle.control.interval.max

# Detect GATTacker/BTLEjuice MITM patterns:
# - Cloned advertising data with different BD_ADDR
# - Rapid connect/disconnect cycles on the same channel
# - Duplicate service UUIDs from different addresses

# Monitor for suspicious pairing requests
tshark -r capture.pcapng -Y "btl2cap.cid == 0x0006" -T fields \
  -e btsmp.opcode -e btsmp.io_capability -e btsmp.auth_req
```

### Step 7: Continuous BLE Security Monitoring

Deploy ongoing BLE monitoring for threat detection:

```bash
# Run the agent in monitoring mode
python agent.py --mode monitor --duration 3600 --output ble_alerts.json

# Combine with Ubertooth for passive monitoring
ubertooth-btle -p -r - | python agent.py --mode analyze --pcap-stdin

# Alert on specific threat indicators
python agent.py --mode monitor --alert-on replay,spoofing,weak-pairing
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **BLE (Bluetooth Low Energy)** | Low-power wireless protocol (Bluetooth 4.0+) optimized for IoT devices, operating on 2.4 GHz with 40 channels (3 advertising, 37 data) |
| **GATT (Generic Attribute Profile)** | BLE data model organizing device capabilities into services, characteristics, and descriptors; the primary interface for reading/writing BLE device data |
| **Ubertooth One** | Open-source 2.4 GHz wireless development platform capable of passive BLE and Bluetooth Classic sniffing across all BLE channels |
| **nRF Sniffer** | Nordic Semiconductor firmware for nRF52840 USB dongle that enables BLE packet capture with Wireshark integration via extcap |
| **Replay Attack** | Attack where previously captured BLE commands are retransmitted to a device to trigger unauthorized actions without knowledge of encryption keys |
| **Just Works Pairing** | BLE Legacy Pairing method using TK=0 with no user confirmation, providing zero protection against passive eavesdropping and MITM attacks |
| **LE Secure Connections** | BLE 4.2+ pairing mode using ECDH key exchange (P-256 curve) that provides protection against passive eavesdropping; recommended over Legacy Pairing |
| **Crackle** | Open-source tool that exploits weaknesses in BLE Legacy Pairing to recover the Long Term Key (LTK) and decrypt captured BLE traffic |
| **GATTacker** | BLE MITM framework that clones a peripheral's GATT profile and advertising data, then relays traffic between the real device and the victim central |

## Tools & Systems

- **Ubertooth One + ubertooth-btle**: Hardware sniffer and CLI tool for passive BLE packet capture in pcapng/pcap format
- **nRF52840 USB Dongle + nRF Sniffer**: Nordic Semiconductor BLE sniffer with native Wireshark extcap integration
- **bleak**: Cross-platform Python asyncio BLE GATT client library for device scanning, connection, and characteristic read/write
- **crackle**: BLE Legacy Pairing encryption cracker that recovers LTK from captured pairing exchanges
- **Wireshark**: Network protocol analyzer with BLE/BTLE dissectors for packet-level inspection of captured traffic
- **GATTacker / BTLEjuice**: BLE Man-in-the-Middle frameworks for intercepting and modifying BLE traffic between central and peripheral
- **tshark**: Command-line Wireshark for scripted BLE packet extraction and field analysis

## Common Pitfalls

- **Ubertooth channel hopping limitations**: Ubertooth follows one connection at a time. If multiple BLE connections are active, you must target a specific device address with `-t` to follow its data channels.
- **BLE 5.0 extended advertising**: Devices using BLE 5.0 extended advertising on secondary channels may not be captured by older Ubertooth firmware. Update to the latest firmware.
- **bleak platform differences**: BLE scanning behavior varies across OS backends. On Linux, scanning requires root or appropriate capabilities. On macOS, device addresses are randomized UUIDs.
- **crackle requires Legacy Pairing**: crackle only works against BLE Legacy Pairing (Bluetooth 4.0/4.1). LE Secure Connections (4.2+) use ECDH and cannot be cracked with this approach.
- **BLE address randomization**: Many modern BLE devices use random resolvable private addresses (RPA) that rotate periodically, making device tracking and connection following more difficult.
- **Capture format matters**: Use PCAP with PPI headers (`-c` flag) for crackle compatibility. PcapNG (`-r` flag) is recommended for Wireshark analysis but not supported by crackle.

## Output Format

```
## Finding: BLE Smart Lock Accepts Replayed Unlock Commands

**ID**: BLE-001
**Severity**: Critical (CVSS 9.3)
**Device**: SmartLock-Pro (AA:BB:CC:DD:EE:FF)
**Attack Type**: Replay Attack

**Description**:
The BLE smart lock accepts previously captured GATT write commands
on characteristic 0000fff1-0000-1000-8000-00805f9b34fb without
any freshness validation. An attacker who captures a single unlock
command can replay it indefinitely to unlock the device.

**Proof of Concept**:
1. Capture unlock command: ubertooth-btle -f -t AA:BB:CC:DD:EE:FF -r capture.pcap
2. Extract write payload from characteristic fff1: 01 42 A3 7F 00
3. Replay via bleak: await client.write_gatt_char(CHAR_UUID, bytes.fromhex('0142a37f00'))
4. Lock disengages without re-authentication

**Impact**:
Any attacker within BLE range (~100m with directional antenna) who
captures a single unlock event can replay it to gain physical access
to the protected area indefinitely.

**Remediation**:
Implement challenge-response authentication with per-session nonces.
Each command should include a server-generated challenge that expires
after use. Use LE Secure Connections for pairing to prevent passive
capture of the pairing exchange.
```
