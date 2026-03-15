# API Reference: Wireless Network Penetration Testing Agent

## Overview

Tests WiFi security: scans access points via beacon capture, detects rogue APs and evil twins, identifies weak encryption, captures WPA2 handshakes, and analyzes client probe requests. For authorized testing only.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| scapy | >=2.5 | Beacon/probe capture, deauth frames |
| aircrack-ng | >=1.7 | Handshake capture and cracking (subprocess) |

## CLI Usage

```bash
# Enable monitor mode first
sudo airmon-ng start wlan0

# Run wireless pentest
python agent.py --interface wlan0mon --duration 60 \
  --known-ssids "CorpWiFi" "GuestWiFi" \
  --known-bssids "AA:BB:CC:DD:EE:FF" --output report.json
```

## Key Functions

### `scan_access_points(interface, duration)`
Captures Dot11Beacon frames to discover APs with SSID, BSSID, channel, and crypto type.

### `detect_rogue_aps(discovered_aps, known_ssids, known_bssids)`
Compares discovered APs against known infrastructure to detect evil twin attacks.

### `detect_weak_encryption(access_points)`
Flags open networks, WEP, and WPA1-only configurations as weak.

### `capture_handshake(interface, target_bssid, channel, output_file, duration)`
Uses airodump-ng to capture the WPA2 4-way handshake.

### `send_deauth(interface, target_bssid, client_mac, count)`
Sends deauthentication frames via Scapy to force client reconnection.

### `crack_handshake(cap_file, wordlist)`
Attempts dictionary attack on captured handshake using aircrack-ng.

### `detect_client_probes(interface, duration)`
Captures Dot11ProbeReq frames to identify SSIDs clients are seeking.

### `check_wps_enabled(interface, target_bssid)`
Uses wash to detect WPS-enabled access points vulnerable to Reaver attacks.

## Scapy 802.11 Layers Used

| Layer | Purpose |
|-------|---------|
| `Dot11Beacon` | Access point beacon frames |
| `Dot11ProbeReq` | Client probe request frames |
| `Dot11Auth` | Deauthentication frames |
| `Dot11Elt` | Information elements (SSID, rates) |
| `RadioTap` | Radio layer metadata |

## External Tools Used

| Tool | Purpose |
|------|---------|
| airmon-ng | Enable monitor mode |
| airodump-ng | Capture handshakes |
| aircrack-ng | Crack WPA2 PSK |
| wash | Detect WPS-enabled APs |
