# API Reference: WiFi Password Cracking with Aircrack Agent

## Overview

Automates WPA/WPA2 wireless security assessment: monitor mode management, network scanning, handshake/PMKID capture, and offline cracking via aircrack-ng and hashcat subprocess wrappers.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| subprocess | stdlib | Aircrack-ng suite and hashcat execution |

## External Tools Required

| Tool | Purpose |
|------|---------|
| airmon-ng | Monitor mode enable/disable |
| airodump-ng | Wireless network scanning and capture |
| aireplay-ng | Deauthentication for handshake capture |
| aircrack-ng | WPA dictionary attack (CPU) |
| hashcat | WPA cracking with GPU acceleration |
| hcxdumptool | PMKID capture (optional) |
| hcxpcapngtool | PMKID hash extraction (optional) |

## Core Functions

### `enable_monitor_mode(iface)`
Kills interfering processes and enables monitor mode.
- **Returns**: `dict` with `monitor_interface`

### `scan_networks(mon_iface, duration, output_prefix)`
Scans for nearby wireless networks, parses CSV output.
- **Returns**: `list[dict]` - BSSID, channel, encryption, ESSID, power

### `capture_handshake(mon_iface, bssid, channel, output_prefix, timeout)`
Captures 4-way WPA handshake using targeted deauthentication.
- **Returns**: `dict` with `capture_file`, `handshake_captured`

### `try_pmkid_capture(mon_iface, bssid, channel, timeout)`
Attempts PMKID-based capture (no client needed).
- **Returns**: `dict` with `pmkid_captured`, `hash_file`

### `crack_with_aircrack(cap_file, wordlist)`
CPU-based dictionary attack using aircrack-ng.
- **Default wordlist**: `/usr/share/wordlists/rockyou.txt`
- **Returns**: `dict` with `cracked`, `key`

### `crack_with_hashcat(hash_file, wordlist, hash_mode)`
GPU-accelerated cracking. Mode 22000 for WPA-PBKDF2-PMKID+EAPOL.
- **Returns**: `dict` with `cracked`, `result`

### `disable_monitor_mode(mon_iface)`
Restores managed mode and restarts NetworkManager.

## Hashcat Modes

| Mode | Hash Type |
|------|-----------|
| 22000 | WPA-PBKDF2-PMKID+EAPOL |
| 22001 | WPA-PMK-PMKID+EAPOL |
| 2500 | WPA-EAPOL-PBKDF2 (legacy) |

## Requirements

- Root/sudo privileges
- Monitor mode capable wireless adapter
- Written authorization for target networks

## Usage

```bash
sudo python agent.py wlan0
```
