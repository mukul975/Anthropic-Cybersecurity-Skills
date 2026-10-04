# API Reference: Rogue AP & Evil-Twin Detection

## 802.11 management-frame subtypes

Filter captures on these `wlan.fc.type_subtype` values (type 0 = management):

| Subtype | Hex | Frame | Relevance |
|---------|-----|-------|-----------|
| 8 | 0x08 | Beacon | Baseline BSSID/SSID/channel source |
| 5 | 0x05 | Probe Response | Karma/MANA APs answer every probe |
| 10 | 0x0a | Disassociation | Precedes evil-twin association |
| 12 | 0x0c | Deauthentication | Flood that drives clients off the real AP |

## airodump-ng CSV columns

`airodump-ng --output-format csv` writes two tables. The AP table (before the
`Station MAC` header) is 0-indexed as:

| Index | Field |
|-------|-------|
| 0 | BSSID |
| 3 | Channel |
| 5 | Encryption |
| 8 | Power (dBm) |
| 13 | ESSID |

## tshark deauth counter

```bash
tshark -i wlan0mon -y IEEE802_11_RADIO \
  -Y "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a" \
  -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype \
  | sort | uniq -c | sort -rn
```

A single `wlan.sa` emitting >100 deauth frames in under a minute is a flood
(ATT&CK T1498.001 Network Denial of Service).

## Classification thresholds

| Signal | Classification | Confidence |
|--------|---------------|-----------|
| Authorized SSID, unknown BSSID | Evil twin | High |
| Rogue BSSID also on wired VLAN (ARP/CAM match) | Rogue bridge | Critical |
| One BSSID advertising many SSIDs | Karma/MANA device | High |
| Rogue power ≥15 dBm hotter than nearest real AP for same SSID | Association-winning twin | High |
| Unrelated SSID from adjacent tenant | Neighbor/benign | Allowlist |

## nzyme detection alerts (reference)

nzyme raises these built-in alert types relevant here: `UnexpectedBSSID`,
`UnexpectedSSID`, `UnexpectedChannel`, `DeauthFlood`, `BeaconRate`. See the
nzyme documentation for sensor deployment and tap configuration.

## Standards & framework mappings

- **MITRE ATT&CK**: T1557 (Adversary-in-the-Middle), T1498.001 (Network DoS: Direct),
  T1200 (Hardware Additions — rogue bridge on the LAN).
- **NIST CSF 2.0**: DE.CM-01 (networks monitored), DE.CM-07 (unauthorized assets/
  devices monitored), DE.AE-02 (analysis of detected events).
- **NIST SP 800-153**: Guidelines for Securing Wireless LANs — rogue-AP monitoring.
- **PCI DSS v4.0 req. 11.2**: quarterly detection of unauthorized wireless access points.
