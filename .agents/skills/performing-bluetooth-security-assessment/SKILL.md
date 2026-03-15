---
name: performing-bluetooth-security-assessment
description: Assess Bluetooth Low Energy device security by scanning, enumerating GATT services, and detecting vulnerabilities
domain: cybersecurity
subdomain: wireless-security
tags: [bluetooth, ble, gatt, wireless-security]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Overview

This skill covers performing Bluetooth Low Energy (BLE) security assessments using the Python bleak library. BLE devices are ubiquitous in IoT, healthcare, fitness, and smart home applications, and many ship with weak or absent security controls. This assessment identifies unencrypted GATT characteristics, devices broadcasting sensitive data, known vulnerable device fingerprints, and improperly secured pairing configurations.

The agent uses bleak's asyncio API to discover nearby BLE devices, connect to target devices, enumerate all GATT services and characteristics, and analyze security properties of each characteristic. It flags characteristics that allow unauthenticated read/write access to sensitive data and identifies devices matching known vulnerable profiles.

## Prerequisites

- Python 3.9 or later
- bleak library (`pip install bleak`)
- Bluetooth adapter supporting BLE (Bluetooth 4.0+)
- Linux: BlueZ 5.43+ with D-Bus permissions
- Windows: Windows 10 version 1709+ with Bluetooth support
- macOS: macOS 10.15+ with CoreBluetooth

## Steps

1. **Scan for BLE devices**: Use BleakScanner to discover all advertising BLE devices within range. Capture device name, address (MAC), RSSI signal strength, and advertised service UUIDs.

2. **Identify target devices**: Filter discovered devices by name pattern, address, or minimum signal strength. Flag devices broadcasting default or well-known vulnerable names.

3. **Connect and enumerate GATT services**: Use BleakClient to connect to the target device and iterate over all GATT services. For each service, record the UUID, description, and contained characteristics.

4. **Analyze characteristic properties**: For each characteristic, examine its properties (read, write, write-without-response, notify, indicate). Flag characteristics that expose read or write access without requiring authentication or encryption.

5. **Check for known vulnerable UUIDs**: Compare discovered service and characteristic UUIDs against a database of known vulnerable or sensitive services (Heart Rate, Blood Pressure, Device Information, Battery Level) that should require encryption.

6. **Detect unencrypted data exposure**: Attempt to read characteristics that should be protected. Successful unauthenticated reads of sensitive data indicate missing security controls.

7. **Generate security report**: Compile all findings into a structured JSON report with severity classifications and remediation recommendations.

## Expected Output

```json
{
  "assessment_type": "ble_security_audit",
  "target_device": {
    "name": "SmartBand-XR",
    "address": "AA:BB:CC:DD:EE:FF",
    "rssi": -42
  },
  "services_found": 5,
  "characteristics_found": 18,
  "findings": [
    {
      "severity": "high",
      "finding": "Heart Rate Measurement readable without encryption",
      "uuid": "00002a37-0000-1000-8000-00805f9b34fb",
      "properties": ["read", "notify"],
      "remediation": "Enable encryption requirement on characteristic"
    }
  ],
  "risk_score": 7.5
}
```
