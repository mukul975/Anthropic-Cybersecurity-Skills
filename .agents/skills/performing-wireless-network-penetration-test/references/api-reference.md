# API Reference: Wireless Network Penetration Testing

## Aircrack-ng Suite

| Tool | Description |
|------|-------------|
| `airmon-ng start <iface>` | Enable monitor mode |
| `airodump-ng <mon_iface>` | Scan for wireless networks |
| `airodump-ng --bssid <bssid> -c <ch> -w <prefix> <iface>` | Capture handshake |
| `aireplay-ng -0 5 -a <bssid> <iface>` | Deauthentication attack |
| `aircrack-ng <cap> -w <wordlist>` | Crack WPA/WPA2 handshake |
| `wash -i <iface>` | Detect WPS-enabled APs |
| `reaver -i <iface> -b <bssid>` | WPS PIN brute force |

## airodump-ng CSV Fields

| Column | Description |
|--------|-------------|
| BSSID | Access point MAC address |
| Channel | Operating channel |
| Encryption | WPA2, WPA, WEP, OPN |
| ESSID | Network name |
| Power | Signal strength (dBm) |

## Encryption Risk Levels

| Encryption | Risk |
|-----------|------|
| Open (OPN) | Critical - No encryption |
| WEP | Critical - Easily crackable |
| WPA (TKIP) | High - Deprecated |
| WPA2 (CCMP) | Medium - Dictionary attacks |
| WPA3 (SAE) | Low - Current standard |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `subprocess` | stdlib | Execute aircrack-ng tools |
| `re` | stdlib | Parse tool output |
| `csv` | stdlib | Parse airodump CSV |

## References

- Aircrack-ng: https://www.aircrack-ng.org/doku.php
- Reaver: https://github.com/t6x/reaver-wps-fork-t6x
- WiFi Pineapple: https://www.hak5.org/products/wifi-pineapple
