---
name: implementing-usb-device-control-policy
description: >
  Implements USB device control policies to restrict unauthorized removable media access on
  endpoints, preventing data exfiltration and malware introduction via USB devices. Use when
  deploying device control via Group Policy, Intune, or EDR platforms to enforce USB restrictions.
  Activates for requests involving USB control, removable media policy, device control, or
  data loss prevention via USB.
domain: cybersecurity
subdomain: endpoint-security
tags: [endpoint, USB-control, device-control, data-loss-prevention, removable-media]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Implementing USB Device Control Policy

## When to Use

Use this skill when:
- Restricting USB storage devices to prevent data exfiltration or malware introduction
- Implementing device control policies via GPO, Intune, or EDR device control modules
- Creating USB whitelists for authorized devices while blocking all others
- Meeting compliance requirements for removable media control (PCI DSS, HIPAA)

**Do not use** for network-based DLP or cloud storage restrictions.

## Prerequisites

- Active Directory GPO or Microsoft Intune for policy deployment
- Device Instance IDs of authorized USB devices
- EDR with device control module (CrowdStrike, Microsoft Defender for Endpoint)
- Understanding of USB device classes (mass storage, HID, printer, etc.)

## Workflow

### Step 1: Inventory Current USB Usage

```powershell
# Enumerate currently connected USB devices
Get-PnpDevice -Class USB | Select-Object InstanceId, FriendlyName, Status

# Query USB storage history from registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" |
  Select-Object FriendlyName, ContainerID, HardwareID

# Collect USB usage across fleet (via EDR or scripts)
# CrowdStrike: Investigate → USB Device Activity
# MDE: DeviceEvents | where ActionType == "UsbDriveMounted"
```

### Step 2: Configure GPO Device Control

```
Computer Configuration → Administrative Templates → System → Removable Storage Access

- All Removable Storage classes: Deny all access → Enabled
  (Block read AND write for all removable storage)

OR for granular control:
- CD and DVD: Deny read access → Enabled
- Removable Disks: Deny write access → Enabled (read-only USB)
- Tape Drives: Deny all access → Enabled
- WPD Devices: Deny all access → Enabled

To allow specific approved USB devices:
Computer Configuration → Administrative Templates → System → Device Installation
  → Device Installation Restrictions

- Prevent installation of devices not described by other policy settings → Enabled
- Allow installation of devices that match any of these device IDs → Enabled
  Add approved Device IDs: USB\VID_0781&PID_5583 (example: SanDisk Cruzer)
```

### Step 3: Deploy via Microsoft Defender for Endpoint

```xml
<!-- MDE Device Control policy (XML format) -->
<PolicyGroups>
  <Group Id="{d9a81dc0-1234-5678-9abc-def012345678}"
    Type="Device" Name="Approved USB Devices">
    <MatchClause>
      <MatchType>VID_PID</MatchType>
      <MatchData>0781_5583</MatchData> <!-- SanDisk -->
    </MatchClause>
  </Group>
</PolicyGroups>

<PolicyRules>
  <Rule Id="{rule-guid}" Name="Block unapproved USB storage">
    <IncludedIdList>
      <PrimaryId>RemovableMediaDevices</PrimaryId>
    </IncludedIdList>
    <ExcludedIdList>
      <GroupId>{d9a81dc0-1234-5678-9abc-def012345678}</GroupId>
    </ExcludedIdList>
    <Entry>
      <Type>Deny</Type>
      <AccessMask>63</AccessMask> <!-- All access -->
      <Options>4</Options> <!-- Show notification -->
    </Entry>
  </Rule>
</PolicyRules>
```

### Step 4: Audit and Monitor

```
# Monitor USB events in SIEM:
# Windows Event ID 6416 - New external device recognized
# Windows Event ID 4663 - File access on removable media
# MDE: DeviceEvents where ActionType contains "Usb"

# Generate USB activity reports monthly
# Track: blocked attempts, approved device usage, exception requests
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **VID/PID** | Vendor ID and Product ID that uniquely identify USB device models |
| **Device Instance ID** | Unique identifier for a specific physical USB device |
| **Device Control** | EDR/endpoint feature restricting device access based on type, vendor, or serial number |
| **USB Class** | USB device category (mass storage 08h, HID 03h, printer 07h) |

## Tools & Systems

- **Microsoft Defender Device Control**: MDE module for USB restriction policies
- **CrowdStrike Falcon Device Control**: EDR-based USB policy enforcement
- **Group Policy (Removable Storage Access)**: Built-in Windows USB restriction via GPO
- **Endpoint Protector**: Third-party device control and DLP solution

## Common Pitfalls

- **Blocking all USB without exception**: Keyboards and mice are USB HID devices. Block only mass storage class, not all USB.
- **Not communicating policy to users**: USB blocks without user notification generate helpdesk tickets. Display a notification explaining the policy.
- **Ignoring USB-C and Thunderbolt**: Modern devices use USB-C for docking, charging, and storage. Policies must distinguish between USB storage and USB peripherals.
- **No approved device process**: Users with legitimate USB needs (presentations, field data collection) require an exception process with approved, encrypted devices.
