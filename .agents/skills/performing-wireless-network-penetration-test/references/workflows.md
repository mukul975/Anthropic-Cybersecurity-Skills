# Workflows — Wireless Penetration Testing

## Attack Flow
```
Monitor Mode Activation
    │
    ├── Passive Reconnaissance
    │   ├── SSID/BSSID discovery
    │   ├── Client enumeration
    │   └── Channel mapping
    │
    ├── WPA2-PSK Attacks
    │   ├── Handshake capture (deauth + capture)
    │   ├── PMKID attack (clientless)
    │   └── Offline cracking (Hashcat/Aircrack)
    │
    ├── WPA2-Enterprise Attacks
    │   ├── Rogue AP (hostapd-mana)
    │   ├── EAP credential capture
    │   └── MSCHAP hash cracking
    │
    ├── Evil Twin / Captive Portal
    │   ├── Clone SSID
    │   ├── Deauth real AP
    │   └── Credential harvest
    │
    └── Segmentation Testing
        ├── Client isolation
        ├── VLAN traversal
        └── Corporate network reach
```
