---
name: analyzing-windows-registry-for-artifacts
description: Extract and analyze Windows Registry hives to uncover user activity, installed software, autostart entries, and evidence of system compromise.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, windows-registry, artifact-analysis, regripper, registry-explorer, evidence-collection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Windows Registry for Artifacts

## When to Use
- When investigating user activity on a Windows system during an incident
- For identifying autorun/persistence mechanisms used by malware
- When tracing installed software, USB devices, and network connections
- During insider threat investigations to reconstruct user actions
- For correlating registry timestamps with other forensic artifacts

## Prerequisites
- Forensic image or extracted registry hive files
- RegRipper, Registry Explorer (Eric Zimmerman), or python-registry
- Access to registry hive locations (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat)
- Understanding of Windows Registry structure (hives, keys, values)
- SIFT Workstation or forensic analysis environment

## Workflow

### Step 1: Extract Registry Hives from the Forensic Image

```bash
# Mount the forensic image read-only
mkdir /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Copy system registry hives
cp /mnt/evidence/Windows/System32/config/SAM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SECURITY /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/DEFAULT /cases/case-2024-001/registry/

# Copy user-specific hives
cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/registry/
cp /mnt/evidence/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat /cases/case-2024-001/registry/

# Copy transaction logs (for dirty hive recovery)
cp /mnt/evidence/Windows/System32/config/*.LOG* /cases/case-2024-001/registry/logs/

# Hash all extracted hives
sha256sum /cases/case-2024-001/registry/* > /cases/case-2024-001/registry/hive_hashes.txt
```

### Step 2: Analyze with RegRipper for Automated Artifact Extraction

```bash
# Install RegRipper
git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper

# Run RegRipper against NTUSER.DAT (user profile)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -f ntuser > /cases/case-2024-001/analysis/ntuser_report.txt

# Run against SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -f system > /cases/case-2024-001/analysis/system_report.txt

# Run against SOFTWARE hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -f software > /cases/case-2024-001/analysis/software_report.txt

# Run against SAM hive (user accounts)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SAM \
   -f sam > /cases/case-2024-001/analysis/sam_report.txt

# Run specific plugins
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p userassist > /cases/case-2024-001/analysis/userassist.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p usbstor > /cases/case-2024-001/analysis/usbstor.txt
```

### Step 3: Extract Persistence and Autorun Entries

```bash
# Using python-registry for targeted extraction
pip install python-registry

python3 << 'PYEOF'
from Registry import Registry

# Open SOFTWARE hive
reg = Registry.Registry("/cases/case-2024-001/registry/SOFTWARE")

# Check Run keys (autostart)
autorun_paths = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for path in autorun_paths:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass

# Check installed services
key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Svchost")
print(f"\n=== Svchost Groups ===")
for value in key.values():
    print(f"  {value.name()}: {value.value()}")
PYEOF

# Check NTUSER.DAT for user-specific autorun
python3 << 'PYEOF'
from Registry import Registry

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

user_autorun = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
]

for path in user_autorun:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass
PYEOF
```

### Step 4: Analyze User Activity Artifacts

```bash
# Extract UserAssist data (program execution history with ROT13 encoding)
python3 << 'PYEOF'
from Registry import Registry
import codecs, struct, datetime

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
key = reg.open(ua_path)

for guid_key in key.subkeys():
    count_key = guid_key.subkey("Count")
    print(f"\n=== {guid_key.name()} ===")
    for value in count_key.values():
        decoded_name = codecs.decode(value.name(), 'rot_13')
        data = value.value()
        if len(data) >= 16:
            run_count = struct.unpack('<I', data[4:8])[0]
            focus_count = struct.unpack('<I', data[8:12])[0]
            timestamp = struct.unpack('<Q', data[60:68])[0] if len(data) >= 68 else 0
            if timestamp > 0:
                ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=timestamp//10)
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}, Last={ts}")
            else:
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}")
PYEOF

# Extract Recent Documents (MRU lists)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p recentdocs > /cases/case-2024-001/analysis/recentdocs.txt

# Extract typed URLs (browser)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedurls > /cases/case-2024-001/analysis/typedurls.txt

# Extract typed paths in Explorer
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedpaths > /cases/case-2024-001/analysis/typedpaths.txt
```

### Step 5: Extract System and Network Information

```bash
# Computer name and OS version from SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p compname > /cases/case-2024-001/analysis/system_info.txt

# Network interfaces and configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p nic2 >> /cases/case-2024-001/analysis/system_info.txt

# Wireless network history
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p networklist > /cases/case-2024-001/analysis/network_history.txt

# Timezone configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p timezone > /cases/case-2024-001/analysis/timezone.txt

# Shutdown time
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p shutdown > /cases/case-2024-001/analysis/shutdown.txt

# Installed software from Uninstall keys
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p uninstall > /cases/case-2024-001/analysis/installed_software.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Registry hive | Binary file storing a section of the registry (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) |
| MRU (Most Recently Used) | Lists tracking recently accessed files, commands, and search terms |
| UserAssist | ROT13-encoded registry entries tracking program execution with timestamps |
| ShimCache | Application compatibility cache recording executed programs |
| AmCache | Detailed execution history including SHA-1 hashes of executables |
| BAM/DAM | Background/Desktop Activity Moderator tracking program execution in Win10+ |
| Last Write Time | Timestamp on registry keys indicating when they were last modified |
| Transaction logs | Journal files allowing recovery of registry state after improper shutdown |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RegRipper | Automated registry artifact extraction with plugin architecture |
| Registry Explorer | Eric Zimmerman GUI tool for interactive registry analysis |
| python-registry | Python library for programmatic registry hive parsing |
| RECmd | Eric Zimmerman command-line registry analysis tool |
| yarp | Yet Another Registry Parser for Python-based analysis |
| AppCompatCacheParser | Dedicated ShimCache/AppCompatCache parser |
| AmcacheParser | Dedicated AmCache.hve analysis tool |
| ShellBags Explorer | Specialized tool for analyzing ShellBag artifacts |

## Common Scenarios

**Scenario 1: Malware Persistence Investigation**
Extract SOFTWARE and NTUSER.DAT hives, check all Run/RunOnce keys for unauthorized entries, examine services for suspicious additions, check scheduled tasks registry keys, correlate autorun timestamps with malware execution timeline.

**Scenario 2: User Activity Reconstruction**
Analyze UserAssist for program execution history, examine RecentDocs for accessed files, check TypedPaths for Explorer navigation, extract ShellBags for folder access patterns, build a timeline of user activity around the incident window.

**Scenario 3: Unauthorized Software Detection**
Parse Uninstall keys for all installed applications, compare against approved software baseline, check BAM/DAM for recently executed programs not in approved list, examine AppCompatCache for execution evidence even after uninstallation.

**Scenario 4: USB Data Exfiltration Investigation**
Extract USBSTOR entries from SYSTEM hive for connected devices, correlate device serial numbers with MountedDevices, check NTUSER.DAT MountPoints2 for user access to removable media, examine SetupAPI logs for first-connection timestamps.

## Output Format

```
Registry Analysis Summary:
  System: DESKTOP-ABC123 (Windows 10 Pro Build 19041)
  Timezone: Eastern Standard Time (UTC-5)
  Last Shutdown: 2024-01-18 23:45:12 UTC

  Autorun Entries:
    HKLM Run:     5 entries (1 suspicious: "updater.exe" -> C:\ProgramData\svc\updater.exe)
    HKCU Run:     3 entries (all legitimate)
    Services:     142 entries (2 unknown: "WinDefSvc", "SysMonAgent")

  User Activity (NTUSER.DAT):
    UserAssist Programs:  234 entries
    Recent Documents:     89 entries
    Typed URLs:           45 entries
    Typed Paths:          12 entries

  USB Devices Connected:
    - Kingston DataTraveler (Serial: 0019E06B4521) - First: 2024-01-10, Last: 2024-01-18
    - WD My Passport (Serial: 575834314131) - First: 2024-01-15, Last: 2024-01-15

  Installed Software:     127 applications
  Suspicious Findings:    3 items flagged for review
```
