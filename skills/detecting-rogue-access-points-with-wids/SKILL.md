---
name: detecting-rogue-access-points-with-wids
description: >-
  Detects rogue access points and evil-twin Wi-Fi networks by correlating beacon
  frames against an authorized BSSID/SSID baseline, flagging signal-strength and
  channel anomalies, and spotting deauthentication floods from WIDS sensors and
  Kismet captures. Use when a SOC or wireless team must find unauthorized APs,
  karma/evil-twin impersonation, or management-frame attacks on a managed WLAN.
  Keywords: rogue AP, evil twin, WIDS, BSSID whitelist, beacon frame, deauth,
  802.11 management frame, Kismet, airodump-ng, nzyme. Do not use for actively
  attacking or auditing your own Wi-Fi - use performing-wireless-network-penetration-test;
  for a broad RF survey and passive device discovery use
  performing-wireless-security-assessment-with-kismet.
domain: cybersecurity
subdomain: wireless-security
tags:
- wireless
- rogue-ap
- evil-twin
- wids
- 802.11
- deauth
- kismet
- threat-detection
version: "1.0"
author: paultdriver-Drivoid
license: Apache-2.0
nist_csf:
- DE.CM-01
- DE.CM-07
- DE.AE-02
mitre_attack:
- T1557
- T1498.001
- T1200
---
# Detecting Rogue Access Points with a WIDS

## When to Use

Use this skill when:
- A wireless intrusion detection system (WIDS) or SOC must find access points broadcasting an authorized SSID from an **unauthorized BSSID** (evil twin).
- Users report intermittent disconnects consistent with a **deauthentication flood** preceding a credential-capture rogue AP.
- A physical-security or facilities team suspects an unsanctioned AP plugged into the corporate LAN (a rogue bridge).
- Periodic WLAN hygiene checks compare the live RF environment against the sanctioned AP inventory.

**Do not use** this skill to run the attack yourself or to audit your own WLAN's encryption — that is `performing-wireless-network-penetration-test`. For a general RF survey and passive client/AP discovery with no detection logic, use `performing-wireless-security-assessment-with-kismet`.

## Prerequisites

- One or more monitor-mode-capable 802.11 radios, or managed-AP WIDS sensors (e.g. Cisco CleanAir, Aruba RFProtect, Mist).
- An **authorized baseline**: a CSV of sanctioned `BSSID,SSID,channel,location` records exported from your controller or inventory.
- Capture tooling: `airodump-ng` (aircrack-ng suite), Kismet, or nzyme for continuous monitoring.
- Read access to the WLAN controller's rogue-AP classification table, if one exists, for cross-reference.
- Python 3.8+ for the correlation script below.

## Workflow

### Step 1: Capture the live RF environment

Put the radio in monitor mode and record beacons across all channels:

```bash
sudo airmon-ng start wlan0
sudo airodump-ng --band abg --write rfscan --output-format csv wlan0mon
```

Let it cycle channels for at least one full dwell (5–10 minutes). This writes `rfscan-01.csv` containing one row per observed BSSID with SSID, channel, and signal (`Power`).

### Step 2: Flag BSSIDs not in the authorized baseline

Any AP advertising a corporate SSID from an unlisted BSSID is a candidate evil twin:

```python
import csv

def load_baseline(path):
    with open(path, newline="") as fh:
        return {r["BSSID"].upper(): r for r in csv.DictReader(fh)}

def parse_airodump(path):
    rows, in_aps = [], False
    with open(path, newline="", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.startswith("BSSID"):
                in_aps = True
                continue
            if line.startswith("Station MAC"):
                break
            if in_aps and line.strip():
                f = [c.strip() for c in line.split(",")]
                if len(f) >= 14:
                    rows.append({"BSSID": f[0].upper(), "channel": f[3],
                                 "power": f[8], "SSID": f[13]})
    return rows

baseline = load_baseline("authorized_aps.csv")
authorized_ssids = {r["SSID"] for r in baseline.values()}

for ap in parse_airodump("rfscan-01.csv"):
    if ap["BSSID"] in baseline:
        continue
    if ap["SSID"] in authorized_ssids:
        print(f"[EVIL-TWIN] {ap['SSID']!r} from rogue BSSID {ap['BSSID']} "
              f"ch{ap['channel']} pwr{ap['power']}")
    else:
        print(f"[UNKNOWN-AP] {ap['BSSID']} {ap['SSID']!r} ch{ap['channel']}")
```

### Step 3: Confirm the impersonation signal

An evil twin usually sits on a **different channel** or at a **stronger signal** than the legitimate AP it mimics (to win client association). Compare the rogue's power/channel against the baseline entry for the same SSID — a rogue 15+ dBm hotter than any sanctioned AP for that SSID, or on an unexpected channel, raises confidence.

### Step 4: Detect the deauthentication flood

Evil-twin credential capture is typically preceded by deauth frames that knock clients off the real AP. Count 802.11 deauth/disassoc management frames:

```bash
sudo tshark -i wlan0mon -y IEEE802_11_RADIO \
  -Y "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a" \
  -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype \
  | sort | uniq -c | sort -rn | head
```

A single source address emitting hundreds of deauths in seconds is a flood (ATT&CK T1498.001). Correlate the source MAC with the rogue BSSID from Step 2.

### Step 5: Locate and classify

Use signal strength from multiple sensors (or a walk-around with one) to triangulate the rogue's physical position. Classify the finding:

- **Rogue on LAN** — rogue BSSID also appears bridged to a corporate subnet (confirm via wired ARP/switch MAC table). Highest severity.
- **Evil twin (RF only)** — impersonating SSID, not bridged. Credential-theft risk.
- **Neighbor/benign** — unrelated SSID from an adjacent tenant; add to an allowlist to suppress future noise.

### Step 6: Contain

Disable the switch port of a bridged rogue, issue a controller-based containment (deauth) against the rogue BSSID only where lawful and policy-permitted, and open an incident with the captures from Steps 1–4 attached.

## Key Concepts

| Term | Definition |
|------|-----------|
| **Rogue AP** | Any access point on or near the network that is not sanctioned by the WLAN owner. |
| **Evil twin** | A rogue AP cloning an authorized SSID to lure clients into associating with it. |
| **BSSID** | The MAC address of an AP's radio — the field a baseline whitelist pins against a known-good SSID. |
| **WIDS** | Wireless Intrusion Detection System — sensors (dedicated or AP-hosted) that watch 802.11 management frames for attacks. |
| **Deauthentication flood** | Spoofed 802.11 deauth/disassoc frames that forcibly disconnect clients, often to drive them onto an evil twin. |
| **Karma attack** | A rogue AP that answers every client probe request, impersonating whatever SSID a device searches for. |

## Tools & Systems

- **aircrack-ng (airodump-ng / airmon-ng)**: Monitor-mode capture and per-BSSID CSV output used for baseline comparison.
- **Kismet**: Continuous passive 802.11 monitor with an alerting engine for rogue and spoofed APs.
- **nzyme**: Open-source WiFi defense platform purpose-built for evil-twin and deauth detection across distributed sensors.
- **tshark / Wireshark**: Management-frame dissection and deauth counting.
- **WLAN controllers (Cisco, Aruba, Mist)**: Native rogue-AP classification and containment for managed deployments.

## Common Scenarios

- **Conference-room evil twin**: An attacker broadcasts the corporate guest SSID at high power to harvest portal credentials.
- **Rogue bridge**: An employee plugs a consumer AP into a wall jack for convenience, creating an unauthenticated bridge to the LAN.
- **Karma/MANA device**: A pentest or malicious device answers all probe requests; detected as one BSSID advertising many SSIDs.
- **Deauth-then-clone**: A burst of deauths against a legitimate AP immediately precedes a matching-SSID rogue appearing on another channel.

## Output Format

```
ROGUE AP DETECTION — HQ-FLOOR-3 WLAN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan window:   2026-10-04 14:02–14:12 UTC
Baseline:      142 authorized BSSIDs across 6 SSIDs

Findings:
  [CRITICAL] Evil twin of "CORP-WIFI"
    Rogue BSSID:   DE:AD:BE:EF:12:34  (not in baseline)
    Channel:       11 (sanctioned APs for this SSID: ch 1/6)
    Signal:        -41 dBm (18 dBm hotter than nearest real AP)
    Deauth flood:  612 frames from DE:AD:BE:EF:12:34 in 40 s
    Classification: Evil twin (RF only) — credential-theft risk

  [HIGH] Unauthorized bridge
    Rogue BSSID:   A0:11:22:33:44:55  SSID "linksys"
    Bridged:       Yes — MAC seen on VLAN 20 switch port Gi1/0/14

Containment:
  [DONE] Switch port Gi1/0/14 shut
  [DONE] Controller containment issued against DE:AD:BE:EF:12:34
  [DONE] Incident IR-2026-0912 opened with captures attached
```
