---
name: analyzing-windows-lnk-files-for-artifacts
description: Parse Windows LNK shortcut files to extract target paths, timestamps, volume information, and machine identifiers for forensic timeline reconstruction.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, lnk-files, windows-artifacts, shortcut-analysis, timeline-reconstruction, evidence-collection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Windows LNK Files for Artifacts

## When to Use
- When reconstructing user file access history from Windows shortcut files
- For tracking accessed files, network shares, and removable media
- During investigations to prove a user opened specific documents
- When correlating file access with other timeline artifacts
- For identifying accessed paths on remote systems or USB devices

## Prerequisites
- Access to LNK files from forensic image (Recent, Desktop, Quick Launch)
- LECmd (Eric Zimmerman), python-lnk, or LnkParser for analysis
- Understanding of LNK file structure (Shell Link Binary format)
- Knowledge of LNK file locations on Windows systems
- Forensic workstation with analysis tools installed

## Workflow

### Step 1: Collect LNK Files from Forensic Image

```bash
# Mount forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

mkdir -p /cases/case-2024-001/lnk/{recent,desktop,startup,custom}

# Copy Recent items LNK files (primary source)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk \
   /cases/case-2024-001/lnk/recent/ 2>/dev/null

# Copy automatic destinations (Jump Lists)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms \
   /cases/case-2024-001/lnk/recent/ 2>/dev/null

# Copy custom destinations (pinned Jump List items)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms \
   /cases/case-2024-001/lnk/custom/ 2>/dev/null

# Copy Desktop shortcuts
cp /mnt/evidence/Users/*/Desktop/*.lnk /cases/case-2024-001/lnk/desktop/ 2>/dev/null

# Copy Startup folder shortcuts (persistence)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Start\ Menu/Programs/Startup/*.lnk \
   /cases/case-2024-001/lnk/startup/ 2>/dev/null
cp "/mnt/evidence/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"/*.lnk \
   /cases/case-2024-001/lnk/startup/ 2>/dev/null

# Find all LNK files on the system
find /mnt/evidence/ -name "*.lnk" -type f 2>/dev/null > /cases/case-2024-001/lnk/all_lnk_locations.txt

# Count and hash
ls /cases/case-2024-001/lnk/recent/ | wc -l
sha256sum /cases/case-2024-001/lnk/recent/*.lnk > /cases/case-2024-001/lnk/lnk_hashes.txt 2>/dev/null
```

### Step 2: Parse LNK Files with LECmd

```bash
# Using Eric Zimmerman's LECmd (Windows or via Mono)
# Process all LNK files in a directory
LECmd.exe -d "C:\cases\lnk\recent\" --csv "C:\cases\analysis\" --csvf lnk_analysis.csv

# Process a single LNK file with verbose output
LECmd.exe -f "C:\cases\lnk\recent\document.pdf.lnk"

# Process Jump List files
JLECmd.exe -d "C:\cases\lnk\recent\" --csv "C:\cases\analysis\" --csvf jumplist_analysis.csv

# Output includes:
# - Source file path
# - Target path (file that was accessed)
# - Target creation, modification, access timestamps
# - LNK creation and modification timestamps
# - Working directory
# - Command line arguments
# - Volume serial number and label
# - Drive type (Fixed, Removable, Network)
# - Machine ID (NetBIOS name)
# - MAC address (from tracker database)
# - File size of target
```

### Step 3: Parse LNK Files with Python

```bash
pip install LnkParse3

python3 << 'PYEOF'
import LnkParse3
import os, json, csv
from datetime import datetime

lnk_dir = '/cases/case-2024-001/lnk/recent/'
results = []

for filename in sorted(os.listdir(lnk_dir)):
    if not filename.lower().endswith('.lnk'):
        continue

    filepath = os.path.join(lnk_dir, filename)
    try:
        with open(filepath, 'rb') as f:
            lnk = LnkParse3.lnk_file(f)
            info = lnk.get_json()

            parsed = {
                'lnk_file': filename,
                'target_path': '',
                'working_dir': '',
                'arguments': '',
                'target_created': '',
                'target_modified': '',
                'target_accessed': '',
                'file_size': '',
                'drive_type': '',
                'volume_serial': '',
                'volume_label': '',
                'machine_id': '',
                'mac_address': '',
            }

            # Extract header timestamps
            header = info.get('header', {})
            parsed['target_created'] = str(header.get('creation_time', ''))
            parsed['target_modified'] = str(header.get('modified_time', ''))
            parsed['target_accessed'] = str(header.get('accessed_time', ''))
            parsed['file_size'] = str(header.get('file_size', ''))

            # Extract link info
            link_info = info.get('link_info', {})
            if link_info:
                local_path = link_info.get('local_base_path', '')
                network_path = link_info.get('common_network_relative_link', {}).get('net_name', '')
                parsed['target_path'] = local_path or network_path

                vol_info = link_info.get('volume_id', {})
                if vol_info:
                    parsed['drive_type'] = str(vol_info.get('drive_type', ''))
                    parsed['volume_serial'] = str(vol_info.get('drive_serial_number', ''))
                    parsed['volume_label'] = str(vol_info.get('volume_label', ''))

            # Extract string data
            string_data = info.get('string_data', {})
            parsed['working_dir'] = str(string_data.get('working_dir', ''))
            parsed['arguments'] = str(string_data.get('command_line_arguments', ''))

            # Extract tracker data (machine ID and MAC)
            extra = info.get('extra', {})
            tracker = extra.get('DISTRIBUTED_LINK_TRACKER_BLOCK', {})
            if tracker:
                parsed['machine_id'] = str(tracker.get('machine_id', ''))
                parsed['mac_address'] = str(tracker.get('mac_address', ''))

            results.append(parsed)

            # Print summary
            print(f"\n{filename}")
            print(f"  Target: {parsed['target_path']}")
            print(f"  Modified: {parsed['target_modified']}")
            print(f"  Drive: {parsed['drive_type']} (Serial: {parsed['volume_serial']})")
            if parsed['machine_id']:
                print(f"  Machine: {parsed['machine_id']}")

    except Exception as e:
        print(f"  Error parsing {filename}: {e}")

# Write results to CSV
with open('/cases/case-2024-001/analysis/lnk_analysis.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys() if results else [])
    writer.writeheader()
    writer.writerows(results)

print(f"\n\nTotal LNK files parsed: {len(results)}")
PYEOF
```

### Step 4: Analyze for Investigative Value

```bash
# Identify files accessed from removable media
python3 << 'PYEOF'
import csv

with open('/cases/case-2024-001/analysis/lnk_analysis.csv') as f:
    reader = csv.DictReader(f)

    print("=== FILES ACCESSED FROM REMOVABLE MEDIA ===\n")
    removable = []
    network = []

    for row in reader:
        if 'DRIVE_REMOVABLE' in row.get('drive_type', '').upper() or \
           'removable' in row.get('drive_type', '').lower():
            removable.append(row)
            print(f"  {row['target_modified']} | {row['target_path']} | Vol: {row['volume_serial']}")

        if 'network' in row.get('drive_type', '').lower() or \
           row.get('target_path', '').startswith('\\\\'):
            network.append(row)

    print(f"\n=== FILES ACCESSED FROM NETWORK SHARES ===\n")
    for row in network:
        print(f"  {row['target_modified']} | {row['target_path']}")

    print(f"\nRemovable media files: {len(removable)}")
    print(f"Network share files: {len(network)}")

    # Check for unique machines (tracker data)
    machines = set()
    for row in [*removable, *network]:
        if row.get('machine_id'):
            machines.add(row['machine_id'])
    if machines:
        print(f"\nMachine IDs found: {machines}")
PYEOF

# Check Startup folder LNK files for persistence
echo "=== STARTUP FOLDER SHORTCUTS (PERSISTENCE) ===" > /cases/case-2024-001/analysis/startup_persistence.txt
for lnk in /cases/case-2024-001/lnk/startup/*.lnk; do
    python3 -c "
import LnkParse3
with open('$lnk', 'rb') as f:
    lnk = LnkParse3.lnk_file(f)
    info = lnk.get_json()
    target = info.get('link_info', {}).get('local_base_path', 'Unknown')
    args = info.get('string_data', {}).get('command_line_arguments', '')
    print(f'  $(basename $lnk): {target} {args}')
" >> /cases/case-2024-001/analysis/startup_persistence.txt 2>/dev/null
done
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Shell Link (.lnk) | Windows shortcut file format containing target path, timestamps, and metadata |
| Target timestamps | Creation, modification, and access times of the file the shortcut points to |
| Volume serial number | Unique identifier of the drive volume where the target file resides |
| Machine ID | NetBIOS name embedded by the Distributed Link Tracking service |
| MAC address | Network adapter MAC from the machine that created the LNK file |
| Jump Lists | Recent and pinned file lists per application (contain embedded LNK data) |
| Automatic Destinations | System-managed Jump List entries for recently opened files |
| Custom Destinations | User-pinned Jump List items that persist until manually removed |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| LECmd | Eric Zimmerman command-line LNK file parser with CSV/JSON output |
| JLECmd | Eric Zimmerman Jump List parser |
| LnkParse3 | Python library for programmatic LNK file analysis |
| lnk_parser | Alternative Python LNK parsing tool |
| Autopsy | Forensic platform with LNK file analysis module |
| KAPE | Automated LNK and Jump List artifact collection |
| Plaso | Timeline tool with LNK file parser for super-timeline creation |
| LNK Explorer | GUI tool for interactive LNK file examination |

## Common Scenarios

**Scenario 1: Data Exfiltration via USB Drive**
Analyze Recent folder LNK files for targets on removable drives, correlate volume serial numbers with USBSTOR registry entries, build a list of files accessed from USB devices, establish which documents were opened from the removable drive, correlate with file copy timestamps.

**Scenario 2: Malware Persistence via Startup Shortcuts**
Examine Startup folder LNK files for malicious targets, check target path and arguments for encoded commands or suspicious executables, verify target file exists and examine it, correlate creation timestamp with initial compromise time.

**Scenario 3: Network Share Access Investigation**
Filter LNK files with network paths (UNC targets), identify which network shares were accessed and when, correlate machine IDs with known corporate systems, check if sensitive file servers were accessed outside of normal duties, build access timeline for compliance investigation.

**Scenario 4: Document Access Timeline for Legal Proceedings**
Extract all Recent folder LNK files, build chronological list of documents accessed by the user, identify specific files relevant to the case, present target timestamps showing when files were opened, correlate with email and communication timelines.

## Output Format

```
LNK File Analysis Summary:
  User Profile: suspect_user
  Total LNK Files: 234 (Recent: 198, Desktop: 23, Startup: 5, Other: 8)

  File Access Statistics:
    Local drive (C:):    156 files
    Removable media:     23 files (3 unique volume serials)
    Network shares:      15 files (\\server01, \\fileserver)
    Other drives:        4 files

  Machine IDs Found: DESKTOP-ABC123, LAPTOP-XYZ789
  MAC Addresses: AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66

  Removable Media Access:
    Volume Serial 1234-ABCD:
      2024-01-15 14:32 - E:\Confidential\financial_report.xlsx
      2024-01-15 14:45 - E:\Confidential\customer_database.csv
      2024-01-15 15:00 - E:\Projects\source_code.zip

  Startup Persistence:
    updater.lnk -> C:\ProgramData\svc\updater.exe (SUSPICIOUS)
    OneDrive.lnk -> C:\Users\...\OneDrive.exe (Legitimate)

  Timeline: /cases/case-2024-001/analysis/lnk_analysis.csv
```
