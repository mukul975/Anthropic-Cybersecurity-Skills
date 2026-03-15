---
name: performing-wireless-security-assessment-with-kismet
description: Conduct wireless network security assessments using Kismet to detect rogue access points, hidden SSIDs, weak encryption, and unauthorized clients through passive RF monitoring.
domain: cybersecurity
subdomain: network-security
tags: [kismet, wireless-security, wifi-assessment, rogue-ap, 802.11, wardriving, wids, wireless-ids, rf-monitoring]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Wireless Security Assessment with Kismet

## Overview

Kismet is an open-source wireless network detector, packet sniffer, and wireless intrusion detection system (WIDS) supporting 802.11a/b/g/n/ac/ax. Unlike active scanners, Kismet operates in passive monitor mode, making it undetectable to the networks being assessed. It captures raw 802.11 frames, identifies access points, clients, probe requests, and encryption types without transmitting any packets. This skill covers deploying Kismet for comprehensive wireless security assessments, identifying rogue access points, detecting weak encryption, mapping hidden networks, and analyzing client behavior.

## Prerequisites

- Linux system (Kali Linux, Ubuntu 22.04+) with Kismet 2023+ installed
- Wireless adapter supporting monitor mode (e.g., Alfa AWUS036ACH, TP-Link TL-WN722N v1)
- Written authorization for wireless assessment (legal requirement)
- GPS receiver (optional, for geolocation mapping)
- Target environment wireless network documentation

## Core Concepts

### Kismet Architecture

Kismet uses a client-server architecture:

- **kismet** - Main server process that captures and processes packets
- **kismet_cap_linux_wifi** - Capture source for Linux WiFi interfaces
- **kismet_cap_linux_bluetooth** - Capture source for Bluetooth
- **Web UI** - Browser-based interface at http://localhost:2501

### Wireless Frame Types

| Frame Type | Purpose | Security Relevance |
|------------|---------|-------------------|
| Beacon | AP announces its presence | SSID, encryption, vendor |
| Probe Request | Client searches for networks | Reveals preferred networks |
| Probe Response | AP responds to client probe | Hidden SSID disclosure |
| Authentication | Client authenticates to AP | Auth type identification |
| Deauthentication | Disconnects client from AP | Potential attack indicator |
| Association | Client joins network | Client-AP relationship |

### Encryption Assessment

| Encryption | Status | Risk |
|------------|--------|------|
| Open (No encryption) | Insecure | Critical - all traffic visible |
| WEP | Broken | Critical - crackable in minutes |
| WPA-TKIP | Deprecated | High - known vulnerabilities |
| WPA2-PSK (CCMP) | Acceptable | Medium - depends on passphrase strength |
| WPA2-Enterprise (802.1X) | Recommended | Low - certificate-based |
| WPA3-SAE | Best practice | Low - resistant to offline attacks |

## Implementation Steps

### Step 1: Prepare Wireless Adapter

```bash
# Identify wireless interfaces
iwconfig

# Check adapter capabilities
iw list | grep -A 10 "Supported interface modes"

# Kill processes that may interfere
sudo airmon-ng check kill

# Enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

# Verify monitor mode
iw dev wlan0 info | grep type
```

### Step 2: Configure and Launch Kismet

Edit `/etc/kismet/kismet.conf`:

```ini
# Data sources
source=wlan0:name=WiFi-Monitor,channel_hop=true,channel_hoprate=5/sec

# Logging configuration
log_types=kismet,pcapng
log_prefix=/opt/kismet/logs/assessment

# Enable all 802.11 channels (2.4GHz and 5GHz)
channel_hop_speed=5
channel_list=IEEE80211:1,2,3,4,5,6,7,8,9,10,11,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165

# GPS configuration (if available)
gps=gpsd:host=localhost,port=2947

# Alert configuration
alert=ADVCRYPTCHANGE,5/min,1/sec
alert=BSSTIMESTAMP,5/min,1/sec
alert=CRYPTODROP,5/min,1/sec
alert=DISASSOCTRAFFIC,10/min,1/sec
alert=DEAUTHFLOOD,10/min,2/sec
alert=PROBENOMFP,5/min,1/sec
```

Launch Kismet:

```bash
# Start Kismet server
sudo kismet -c wlan0

# Access web interface
# Open browser to http://localhost:2501
# Default credentials: kismet / kismet (change immediately)
```

### Step 3: Conduct Assessment Scans

**Rogue Access Point Detection:**

```bash
# Export device list via Kismet REST API
curl -u kismet:kismet http://localhost:2501/devices/summary/devices.json | \
    python3 -m json.tool > all_devices.json

# Filter for access points
curl -u kismet:kismet \
    'http://localhost:2501/devices/summary/devices.json' \
    -d 'json={"fields":["kismet.device.base.macaddr","kismet.device.base.name","kismet.device.base.type","kismet.device.base.crypt","kismet.device.base.channel","kismet.device.base.manuf","dot11.device/dot11.device.advertised_ssid_map/dot11.advertisedssid.ssid"]}' \
    > access_points.json
```

**Client Probe Analysis:**

Probe requests reveal networks that clients have previously connected to, which can indicate:
- Corporate devices connecting to insecure home networks
- Devices searching for known-evil SSIDs (evil twin susceptibility)
- Unauthorized personal devices in corporate space

### Step 4: Analyze Results

Python analysis script for Kismet database:

```python
#!/usr/bin/env python3
"""Analyze Kismet capture database for wireless security findings."""

import sqlite3
import json
import sys
from collections import defaultdict


def analyze_kismet_db(db_path: str):
    """Analyze Kismet SQLite database for security issues."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    findings = []

    # Query all devices
    cursor.execute("""
        SELECT devmac, type, device
        FROM devices
    """)

    devices = cursor.fetchall()
    ap_count = 0
    client_count = 0
    open_networks = []
    wep_networks = []
    wpa_tkip_networks = []
    hidden_networks = []
    all_aps = []

    for mac, dev_type, device_json in devices:
        try:
            device = json.loads(device_json)
        except json.JSONDecodeError:
            continue

        base = device.get('kismet.device.base.type', '')

        if 'Wi-Fi AP' in base or 'Wi-Fi Device' in base:
            ap_count += 1
            ssid_map = device.get('dot11.device', {}).get(
                'dot11.device.advertised_ssid_map', []
            )
            crypt = device.get('kismet.device.base.crypt', '')
            name = device.get('kismet.device.base.name', 'Unknown')
            channel = device.get('kismet.device.base.channel', '')
            manuf = device.get('kismet.device.base.manuf', 'Unknown')

            ap_info = {
                'mac': mac,
                'ssid': name,
                'encryption': crypt,
                'channel': channel,
                'manufacturer': manuf,
            }
            all_aps.append(ap_info)

            if 'None' in crypt or crypt == '':
                open_networks.append(ap_info)
            elif 'WEP' in crypt:
                wep_networks.append(ap_info)
            elif 'WPA+TKIP' in crypt and 'AES' not in crypt:
                wpa_tkip_networks.append(ap_info)

            for ssid_entry in ssid_map:
                if isinstance(ssid_entry, dict):
                    ssid = ssid_entry.get('dot11.advertisedssid.ssid', '')
                    if ssid == '' or ssid is None:
                        hidden_networks.append(ap_info)

        elif 'Wi-Fi Client' in base:
            client_count += 1

    # Generate findings
    print(f"\n{'='*70}")
    print("WIRELESS SECURITY ASSESSMENT REPORT")
    print(f"{'='*70}")
    print(f"\nTotal Access Points Detected: {ap_count}")
    print(f"Total Clients Detected: {client_count}")

    if open_networks:
        print(f"\n[CRITICAL] Open Networks (No Encryption): {len(open_networks)}")
        for net in open_networks:
            print(f"  - SSID: {net['ssid']}, MAC: {net['mac']}, "
                  f"Channel: {net['channel']}, Vendor: {net['manufacturer']}")

    if wep_networks:
        print(f"\n[CRITICAL] WEP-Encrypted Networks: {len(wep_networks)}")
        for net in wep_networks:
            print(f"  - SSID: {net['ssid']}, MAC: {net['mac']}, "
                  f"Channel: {net['channel']}")

    if wpa_tkip_networks:
        print(f"\n[HIGH] WPA-TKIP Networks (Deprecated): {len(wpa_tkip_networks)}")
        for net in wpa_tkip_networks:
            print(f"  - SSID: {net['ssid']}, MAC: {net['mac']}, "
                  f"Channel: {net['channel']}")

    if hidden_networks:
        print(f"\n[MEDIUM] Hidden SSIDs Detected: {len(hidden_networks)}")
        for net in hidden_networks:
            print(f"  - MAC: {net['mac']}, Channel: {net['channel']}, "
                  f"Vendor: {net['manufacturer']}")

    # Channel utilization analysis
    channel_usage = defaultdict(int)
    for ap in all_aps:
        ch = ap.get('channel', 'Unknown')
        channel_usage[ch] += 1

    print(f"\n[INFO] Channel Utilization:")
    for ch, count in sorted(channel_usage.items()):
        print(f"  Channel {ch}: {count} APs")

    conn.close()


if __name__ == '__main__':
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'Kismet-*.kismet'
    analyze_kismet_db(db_path)
```

### Step 5: Detect Rogue Access Points

Compare discovered APs against authorized inventory:

```python
#!/usr/bin/env python3
"""Detect rogue access points by comparing against authorized AP list."""

import json
import sys


def load_authorized_aps(filepath: str) -> set:
    """Load authorized AP MAC addresses from file."""
    authorized = set()
    with open(filepath, 'r') as f:
        for line in f:
            mac = line.strip().lower()
            if mac and not mac.startswith('#'):
                authorized.add(mac)
    return authorized


def detect_rogues(kismet_json: str, authorized_file: str):
    """Compare discovered APs against authorized list."""
    authorized = load_authorized_aps(authorized_file)

    with open(kismet_json, 'r') as f:
        devices = json.load(f)

    rogues = []
    for device in devices:
        mac = device.get('kismet.device.base.macaddr', '').lower()
        dev_type = device.get('kismet.device.base.type', '')

        if 'AP' in dev_type and mac not in authorized:
            rogues.append({
                'mac': mac,
                'ssid': device.get('kismet.device.base.name', 'Unknown'),
                'encryption': device.get('kismet.device.base.crypt', ''),
                'channel': device.get('kismet.device.base.channel', ''),
                'manufacturer': device.get('kismet.device.base.manuf', ''),
                'signal': device.get('kismet.device.base.signal', {}).get(
                    'kismet.common.signal.last_signal', 0),
            })

    if rogues:
        print(f"\n[ALERT] {len(rogues)} ROGUE ACCESS POINTS DETECTED\n")
        for rogue in rogues:
            print(f"  MAC: {rogue['mac']}")
            print(f"  SSID: {rogue['ssid']}")
            print(f"  Encryption: {rogue['encryption']}")
            print(f"  Channel: {rogue['channel']}")
            print(f"  Vendor: {rogue['manufacturer']}")
            print(f"  Signal: {rogue['signal']} dBm")
            print()
    else:
        print("No rogue access points detected.")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python detect_rogues.py <kismet_devices.json> <authorized_aps.txt>")
        sys.exit(1)
    detect_rogues(sys.argv[1], sys.argv[2])
```

## Assessment Checklist

- [ ] All authorized APs identified and verified
- [ ] Rogue/unauthorized APs identified and located
- [ ] Encryption types documented for all SSIDs
- [ ] Hidden SSIDs discovered and documented
- [ ] Client probe requests analyzed for sensitive patterns
- [ ] Evil twin susceptibility assessed
- [ ] WPS status checked on all APs
- [ ] Signal coverage boundaries mapped
- [ ] Guest network isolation verified
- [ ] Management interfaces not exposed on wireless

## Best Practices

- **Written Authorization** - Always obtain signed authorization before performing wireless assessments
- **Passive Only** - Use Kismet in passive mode; do not transmit deauth frames or probe requests
- **Comprehensive Channel Coverage** - Scan both 2.4GHz and 5GHz bands including DFS channels
- **Multiple Locations** - Perform captures from multiple physical locations for complete coverage
- **Time Duration** - Capture for at least 30-60 minutes to observe intermittent devices
- **GPS Mapping** - Use GPS to create heat maps for signal boundary analysis
- **Baseline Comparison** - Maintain an authorized AP inventory and compare against each assessment

## References

- [Kismet Documentation](https://www.kismetwireless.net/docs/)
- [CISA Kismet Resources](https://www.cisa.gov/resources-tools/services/kismet)
- [NIST SP 800-153 - Wireless Network Security](https://csrc.nist.gov/publications/detail/sp/800-153/final)
- [Wi-Fi Alliance WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)
