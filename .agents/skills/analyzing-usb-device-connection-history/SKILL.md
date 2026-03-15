---
name: analyzing-usb-device-connection-history
description: Investigate USB device connection history from Windows registry, event logs, and setupapi logs to track removable media usage and potential data exfiltration.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, usb-forensics, removable-media, registry-analysis, data-exfiltration, device-history]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing USB Device Connection History

## When to Use
- When investigating potential data exfiltration via removable storage devices
- During insider threat investigations to track USB device usage
- For compliance audits verifying removable media policy enforcement
- When correlating USB connections with file access and copy events
- For establishing a timeline of device connections during an incident

## Prerequisites
- Forensic image or extracted registry hives and event logs
- Access to SYSTEM, SOFTWARE, and NTUSER.DAT registry hives
- SetupAPI logs (setupapi.dev.log)
- Windows Event Logs (System, Security, DriverFrameworks-UserMode)
- USBDeview, USB Forensic Tracker, or RegRipper
- Understanding of USB device identification (VID, PID, serial number)

## Workflow

### Step 1: Extract USB-Related Artifacts

```bash
# Mount forensic image and copy relevant artifacts
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

mkdir -p /cases/case-2024-001/usb/

# Registry hives
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/usb/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/usb/
cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/usb/

# SetupAPI logs (first connection timestamps)
cp /mnt/evidence/Windows/INF/setupapi.dev.log /cases/case-2024-001/usb/

# Event logs
cp /mnt/evidence/Windows/System32/winevt/Logs/System.evtx /cases/case-2024-001/usb/
cp "/mnt/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx" \
   /cases/case-2024-001/usb/ 2>/dev/null
cp "/mnt/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx" \
   /cases/case-2024-001/usb/ 2>/dev/null
```

### Step 2: Parse USBSTOR Registry Key

```bash
# Extract USBSTOR entries from SYSTEM hive
python3 << 'PYEOF'
from Registry import Registry
import json

reg = Registry.Registry("/cases/case-2024-001/usb/SYSTEM")

# Find current ControlSet
select = reg.open("Select")
current = select.value("Current").value()
controlset = f"ControlSet{current:03d}"

# Parse USBSTOR
usbstor_path = f"{controlset}\\Enum\\USBSTOR"
usbstor = reg.open(usbstor_path)

devices = []
print("=== USBSTOR DEVICES ===\n")

for device_class in usbstor.subkeys():
    # Format: Disk&Ven_VENDOR&Prod_PRODUCT&Rev_REVISION
    class_name = device_class.name()
    parts = class_name.split('&')
    vendor = parts[1].replace('Ven_', '') if len(parts) > 1 else 'Unknown'
    product = parts[2].replace('Prod_', '') if len(parts) > 2 else 'Unknown'
    revision = parts[3].replace('Rev_', '') if len(parts) > 3 else 'Unknown'

    for instance in device_class.subkeys():
        serial = instance.name()
        last_write = instance.timestamp()

        device_info = {
            'vendor': vendor,
            'product': product,
            'revision': revision,
            'serial': serial,
            'last_connected': str(last_write),
        }

        # Get friendly name if available
        try:
            friendly = instance.value("FriendlyName").value()
            device_info['friendly_name'] = friendly
        except:
            pass

        # Get device parameters
        try:
            params = instance.subkey("Device Parameters")
            try:
                device_info['class_guid'] = params.value("ClassGUID").value()
            except:
                pass
        except:
            pass

        devices.append(device_info)
        print(f"Device: {vendor} {product}")
        print(f"  Serial: {serial}")
        print(f"  Last Connected: {last_write}")
        print(f"  Friendly Name: {device_info.get('friendly_name', 'N/A')}")
        print()

# Save results
with open('/cases/case-2024-001/analysis/usb_devices.json', 'w') as f:
    json.dump(devices, f, indent=2)

print(f"\nTotal USB storage devices found: {len(devices)}")
PYEOF
```

### Step 3: Extract Drive Letter Assignments and User Associations

```bash
# Parse MountedDevices from SYSTEM hive
python3 << 'PYEOF'
from Registry import Registry
import struct

reg = Registry.Registry("/cases/case-2024-001/usb/SYSTEM")

mounted = reg.open("MountedDevices")

print("=== MOUNTED DEVICES (Drive Letter Assignments) ===\n")
for value in mounted.values():
    name = value.name()
    data = value.value()

    if name.startswith("\\DosDevices\\"):
        drive_letter = name.replace("\\DosDevices\\", "")
        if len(data) > 24:
            # USB device - contains device path string
            try:
                device_path = data.decode('utf-16-le').strip('\x00')
                if 'USBSTOR' in device_path or 'USB#' in device_path:
                    print(f"  {drive_letter} -> {device_path}")
            except:
                pass
        else:
            # Fixed disk - contains disk signature + offset
            disk_sig = struct.unpack('<I', data[0:4])[0]
            offset = struct.unpack('<Q', data[4:12])[0]
            print(f"  {drive_letter} -> Disk Signature: 0x{disk_sig:08X}, Offset: {offset}")
PYEOF

# Parse user MountPoints2 (which user accessed which devices)
python3 << 'PYEOF'
from Registry import Registry
import os, glob

print("\n=== USER MOUNT POINTS (MountPoints2) ===\n")

for ntuser in glob.glob("/cases/case-2024-001/usb/NTUSER*.DAT"):
    try:
        reg = Registry.Registry(ntuser)
        mp2 = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")

        print(f"User hive: {os.path.basename(ntuser)}")
        for key in mp2.subkeys():
            guid = key.name()
            last_write = key.timestamp()
            if '{' in guid:
                print(f"  Volume: {guid} | Last accessed: {last_write}")
        print()
    except Exception as e:
        print(f"  Error parsing {ntuser}: {e}")
PYEOF
```

### Step 4: Extract First Connection Timestamps from SetupAPI

```bash
# Parse setupapi.dev.log for USB device first-install timestamps
python3 << 'PYEOF'
import re

print("=== SETUPAPI USB DEVICE INSTALLATIONS ===\n")

with open('/cases/case-2024-001/usb/setupapi.dev.log', 'r', errors='ignore') as f:
    content = f.read()

# Find USB device installation sections
pattern = r'>>>\s+\[Device Install.*?\n.*?Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?\n(.*?)<<<'
matches = re.findall(pattern, content, re.DOTALL)

usb_installs = []
for timestamp, section in matches:
    if 'USBSTOR' in section or 'USB\\VID' in section:
        # Extract device ID
        dev_match = re.search(r'(USBSTOR\\[^\s]+|USB\\VID_\w+&PID_\w+[^\s]*)', section)
        if dev_match:
            device_id = dev_match.group(1)
            usb_installs.append({
                'first_install': timestamp,
                'device_id': device_id
            })
            print(f"  {timestamp} | {device_id}")

print(f"\nTotal USB installations found: {len(usb_installs)}")
PYEOF

# Parse Windows Event Logs for USB events
# Event IDs: 2003, 2010, 2100, 2102 (DriverFrameworks-UserMode)
# Event IDs: 6416 (Security - new external device recognized)
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

try:
    parser = PyEvtxParser("/cases/case-2024-001/usb/System.evtx")

    print("\n=== SYSTEM EVENT LOG USB EVENTS ===\n")
    for record in parser.records_json():
        data = json.loads(record['data'])
        event_id = str(data['Event']['System']['EventID'])

        # USB device connection events
        if event_id in ('20001', '20003', '10000', '10100'):
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            event_data = data['Event'].get('UserData', data['Event'].get('EventData', {}))
            print(f"  [{timestamp}] EventID {event_id}: {json.dumps(event_data, default=str)[:200]}")
except Exception as e:
    print(f"Error: {e}")
PYEOF
```

### Step 5: Build USB Activity Timeline and Report

```bash
# Compile all USB evidence into a unified timeline
python3 << 'PYEOF'
import json, csv

timeline = []

# Load USBSTOR data
with open('/cases/case-2024-001/analysis/usb_devices.json') as f:
    devices = json.load(f)

for device in devices:
    timeline.append({
        'timestamp': device['last_connected'],
        'source': 'USBSTOR Registry',
        'device': f"{device['vendor']} {device['product']}",
        'serial': device['serial'],
        'event': 'Last Connected',
        'detail': device.get('friendly_name', '')
    })

# Sort chronologically
timeline.sort(key=lambda x: x['timestamp'])

# Write timeline CSV
with open('/cases/case-2024-001/analysis/usb_timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'source', 'device', 'serial', 'event', 'detail'])
    writer.writeheader()
    writer.writerows(timeline)

print(f"USB Timeline: {len(timeline)} events written to usb_timeline.csv")

# Print summary
print("\n=== USB DEVICE SUMMARY ===")
for entry in timeline:
    print(f"  {entry['timestamp']} | {entry['device']} | {entry['serial'][:20]} | {entry['event']}")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| USBSTOR | Registry key storing USB mass storage device identification and connection data |
| VID/PID | Vendor ID and Product ID uniquely identifying USB device manufacturer and model |
| Device serial number | Unique identifier for individual USB devices (some devices share serials) |
| MountedDevices | Registry key mapping volume GUIDs and drive letters to physical devices |
| MountPoints2 | Per-user registry key showing which volumes a user accessed |
| SetupAPI log | Windows driver installation log recording first-time device connections |
| DeviceContainers | Registry key in SOFTWARE hive with device metadata and timestamps |
| EMDMgmt | Registry key tracking ReadyBoost-compatible devices with serial numbers and timestamps |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| USB Forensic Tracker | Specialized tool for USB device history extraction |
| USBDeview | NirSoft tool listing all USB devices connected to a system |
| RegRipper (usbstor plugin) | Automated USB artifact extraction from registry hives |
| Registry Explorer | Interactive registry analysis for USB-related keys |
| KAPE | Automated collection of USB-related artifacts |
| Plaso/log2timeline | Timeline creation including USB connection events |
| FTK Imager | Forensic imaging including removable media |
| Velociraptor | Endpoint agent with USB device history hunting artifacts |

## Common Scenarios

**Scenario 1: Data Exfiltration by Departing Employee**
Extract USBSTOR entries to identify all USB devices ever connected, correlate device serial numbers with MountPoints2 to confirm user access, cross-reference timestamps with file access logs and jump list recent files, check for large file copy patterns in USN journal.

**Scenario 2: Unauthorized Device on Secure System**
Audit all USBSTOR entries against approved device list, identify unauthorized devices by VID/PID not matching corporate-approved hardware, determine when the unauthorized device was first and last connected, check if any data was transferred.

**Scenario 3: Malware Delivery via USB**
Identify USB device connected just before malware execution (Prefetch timestamps), extract the device serial and vendor information, check if autorun was enabled for the device, look for executable launch from the removable drive letter in Prefetch and ShimCache.

**Scenario 4: Tracking a Specific USB Drive Across Multiple Systems**
Search for the same device serial number in USBSTOR across all forensic images, build a map of which systems the drive was connected to and when, identify the chronological path of the device through the organization, correlate with network share access logs.

## Output Format

```
USB Device History Analysis:
  System: DESKTOP-ABC123 (Windows 10 Pro)
  Total USB Storage Devices: 12
  Analysis Sources: USBSTOR, MountedDevices, MountPoints2, SetupAPI, Event Logs

  Device Inventory:
    1. Kingston DataTraveler 3.0 (Serial: 0019E06B4521A2B0)
       First Connected:  2024-01-10 09:15:32 (SetupAPI)
       Last Connected:   2024-01-18 14:30:00 (USBSTOR)
       Drive Letter:     E:
       User Access:      suspect_user (MountPoints2)

    2. WD My Passport (Serial: 575834314131363035)
       First Connected:  2024-01-15 20:00:00
       Last Connected:   2024-01-15 23:45:00
       Drive Letter:     F:
       User Access:      suspect_user

  Suspicious Findings:
    - Kingston drive connected 15 times during investigation period
    - WD Passport connected only once, late evening (unusual hours)
    - Unknown device (VID_1234&PID_5678) connected 2024-01-17, no matching approved device

  Timeline: /cases/case-2024-001/analysis/usb_timeline.csv
```
