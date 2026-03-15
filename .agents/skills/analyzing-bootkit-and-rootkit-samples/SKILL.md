---
name: analyzing-bootkit-and-rootkit-samples
description: >
  Analyzes bootkit and advanced rootkit malware that infects the Master Boot Record (MBR),
  Volume Boot Record (VBR), or UEFI firmware to gain persistence below the operating system.
  Covers boot sector analysis, UEFI module inspection, and anti-rootkit detection techniques.
  Activates for requests involving bootkit analysis, MBR malware investigation, UEFI
  persistence analysis, or pre-OS malware detection.
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, bootkit, rootkit, UEFI, MBR-analysis]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Analyzing Bootkit and Rootkit Samples

## When to Use

- A system shows signs of compromise that persist through OS reinstallation
- Antivirus and EDR are unable to detect malware despite clear evidence of compromise
- UEFI Secure Boot has been disabled or shows integrity violations
- Memory forensics reveals rootkit behavior (hidden processes, hooked system calls)
- Investigating nation-state level threats known to deploy bootkits (APT28, APT41, Equation Group)

**Do not use** for standard user-mode malware; bootkits and rootkits operate at a fundamentally different level requiring specialized analysis techniques.

## Prerequisites

- Disk imaging tools (dd, FTK Imager) for acquiring MBR/VBR sectors
- UEFITool for UEFI firmware volume analysis and module extraction
- chipsec for hardware-level firmware security assessment
- Ghidra with x86 real-mode and 16-bit support for MBR code analysis
- Volatility 3 for kernel-level rootkit artifact detection
- Bootable Linux live USB for offline system analysis

## Workflow

### Step 1: Acquire Boot Sectors and Firmware

Extract MBR, VBR, and UEFI firmware for offline analysis:

```bash
# Acquire MBR (first 512 bytes of disk)
dd if=/dev/sda of=mbr.bin bs=512 count=1

# Acquire first track (usually contains bootkit code beyond MBR)
dd if=/dev/sda of=first_track.bin bs=512 count=63

# Acquire VBR (Volume Boot Record - first sector of partition)
dd if=/dev/sda1 of=vbr.bin bs=512 count=1

# Acquire UEFI System Partition
mkdir /mnt/efi
mount /dev/sda1 /mnt/efi
cp -r /mnt/efi/EFI /analysis/efi_backup/

# Dump UEFI firmware (requires chipsec or flashrom)
# Using chipsec:
python chipsec_util.py spi dump firmware.rom

# Using flashrom:
flashrom -p internal -r firmware.rom

# Verify firmware dump integrity
sha256sum firmware.rom
```

### Step 2: Analyze MBR/VBR for Bootkit Code

Examine boot sector code for malicious modifications:

```bash
# Disassemble MBR code (16-bit real mode)
ndisasm -b16 mbr.bin > mbr_disasm.txt

# Compare MBR with known-good Windows MBR
# Standard Windows MBR begins with: EB 5A 90 (JMP 0x5C, NOP)
# Standard Windows 10 MBR: 33 C0 8E D0 BC 00 7C (XOR AX,AX; MOV SS,AX; MOV SP,7C00h)

python3 << 'PYEOF'
with open("mbr.bin", "rb") as f:
    mbr = f.read()

# Check MBR signature (bytes 510-511 should be 0x55AA)
if mbr[510:512] == b'\x55\xAA':
    print("[*] Valid MBR signature (0x55AA)")
else:
    print("[!] Invalid MBR signature")

# Check for known bootkit signatures
bootkit_sigs = {
    b'\xE8\x00\x00\x5E\x81\xEE': "TDL4/Alureon bootkit",
    b'\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B\xF4\x50\x07': "Standard Windows MBR (clean)",
    b'\xEB\x5A\x90\x4E\x54\x46\x53': "Standard NTFS VBR (clean)",
}

for sig, name in bootkit_sigs.items():
    if sig in mbr:
        print(f"[{'!' if 'clean' not in name else '*'}] Signature match: {name}")

# Check partition table entries
print("\nPartition Table:")
for i in range(4):
    offset = 446 + (i * 16)
    entry = mbr[offset:offset+16]
    if entry != b'\x00' * 16:
        boot_flag = "Active" if entry[0] == 0x80 else "Inactive"
        part_type = entry[4]
        start_lba = int.from_bytes(entry[8:12], 'little')
        size_lba = int.from_bytes(entry[12:16], 'little')
        print(f"  Partition {i+1}: Type=0x{part_type:02X} {boot_flag} Start=LBA {start_lba} Size={size_lba} sectors")
PYEOF
```

### Step 3: Analyze UEFI Firmware for Implants

Inspect UEFI firmware volumes for unauthorized modules:

```bash
# Extract UEFI firmware components with UEFITool
# GUI: Open firmware.rom -> Inspect firmware volumes
# CLI:
UEFIExtract firmware.rom all

# List all DXE drivers (most common target for UEFI implants)
find firmware.rom.dump -name "*.efi" -exec file {} \;

# Compare against known-good firmware module list
# Each UEFI module has a GUID - compare against vendor baseline

# Verify Secure Boot configuration
python chipsec_main.py -m common.secureboot.variables

# Check SPI flash write protection
python chipsec_main.py -m common.bios_wp

# Check for known UEFI malware patterns
yara -r uefi_malware.yar firmware.rom
```

```
Known UEFI Bootkit Detection Points:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LoJax (APT28):
  - Modified SPI flash
  - Added DXE driver that drops agent to Windows
  - Persists through OS reinstall and disk replacement

BlackLotus:
  - Exploits CVE-2022-21894 to bypass Secure Boot
  - Modifies EFI System Partition bootloader
  - Installs kernel driver during boot

CosmicStrand:
  - Modifies CORE_DXE firmware module
  - Hooks kernel initialization during boot
  - Drops shellcode into Windows kernel memory

MoonBounce:
  - SPI flash implant in CORE_DXE module
  - Modified GetVariable() function
  - Deploys user-mode implant through boot chain

ESPecter:
  - Modifies Windows Boot Manager on ESP
  - Patches winload.efi to disable DSE
  - Loads unsigned kernel driver
```

### Step 4: Detect Kernel-Level Rootkit Behavior

Analyze the running system for rootkit artifacts:

```bash
# Memory forensics for rootkit detection
# SSDT hook detection
vol3 -f memory.dmp windows.ssdt | grep -v "ntoskrnl\|win32k"

# Hidden processes (DKOM)
vol3 -f memory.dmp windows.psscan > psscan.txt
vol3 -f memory.dmp windows.pslist > pslist.txt
# Diff to find hidden processes

# Kernel callback registration (rootkits register callbacks for filtering)
vol3 -f memory.dmp windows.callbacks

# Driver analysis
vol3 -f memory.dmp windows.driverscan
vol3 -f memory.dmp windows.modules

# Check for unsigned drivers
vol3 -f memory.dmp windows.driverscan | while read line; do
    driver_path=$(echo "$line" | awk '{print $NF}')
    if [ -f "$driver_path" ]; then
        sigcheck -nobanner "$driver_path" 2>/dev/null | grep "Unsigned"
    fi
done

# IDT hook detection
vol3 -f memory.dmp windows.idt
```

### Step 5: Boot Process Integrity Verification

Verify the integrity of the entire boot chain:

```bash
# Verify Windows Boot Manager signature
sigcheck -a C:\Windows\Boot\EFI\bootmgfw.efi

# Verify winload.efi
sigcheck -a C:\Windows\System32\winload.efi

# Verify ntoskrnl.exe
sigcheck -a C:\Windows\System32\ntoskrnl.exe

# Check Measured Boot logs (if TPM is available)
# Windows: BCDEdit /enum firmware
bcdedit /enum firmware

# Verify Secure Boot state
Confirm-SecureBootUEFI  # PowerShell cmdlet

# Check boot configuration for tampering
bcdedit /v

# Look for boot configuration changes
# testsigning: should be No
# nointegritychecks: should be No
# debug: should be No
bcdedit | findstr /i "testsigning nointegritychecks debug"
```

### Step 6: Document Bootkit/Rootkit Analysis

Compile comprehensive analysis findings:

```
Analysis should document:
- Boot sector (MBR/VBR) integrity status with hex comparison
- UEFI firmware module inventory and integrity verification
- Secure Boot status and any bypass mechanisms detected
- Kernel-level hooks (SSDT, IDT, IRP, inline) identified
- Hidden processes, drivers, and files discovered
- Persistence mechanism (SPI flash, ESP, MBR, kernel driver)
- Boot chain integrity verification results
- Attribution to known bootkit families if possible
- Remediation steps (reflash firmware, rebuild MBR, replace hardware)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Bootkit** | Malware that infects the boot process (MBR, VBR, UEFI) to execute before the operating system loads, gaining persistent low-level control |
| **MBR (Master Boot Record)** | First 512 bytes of a disk containing bootstrap code and partition table; MBR bootkits replace this code with malicious loaders |
| **UEFI (Unified Extensible Firmware Interface)** | Modern firmware interface replacing BIOS; UEFI bootkits implant malicious modules in firmware volumes or modify the ESP |
| **Secure Boot** | UEFI security feature verifying digital signatures of boot components; bootkits like BlackLotus exploit vulnerabilities to bypass it |
| **SPI Flash** | Flash memory chip storing UEFI firmware; advanced bootkits like LoJax and MoonBounce modify SPI flash for firmware-level persistence |
| **DKOM (Direct Kernel Object Manipulation)** | Rootkit technique modifying kernel structures to hide processes, files, and network connections without hooking functions |
| **Driver Signature Enforcement (DSE)** | Windows security feature requiring kernel drivers to be digitally signed; bootkits disable DSE during boot to load unsigned rootkit drivers |

## Tools & Systems

- **UEFITool**: Open-source UEFI firmware image editor and parser for inspecting firmware volumes, drivers, and modules
- **chipsec**: Intel hardware security assessment framework for verifying SPI flash protection, Secure Boot, and UEFI configuration
- **Volatility**: Memory forensics framework with SSDT, IDT, callback, and driver analysis plugins for kernel rootkit detection
- **GMER**: Windows rootkit detection tool scanning for SSDT hooks, IDT hooks, hidden processes, and modified kernel modules
- **Bootkits Analyzer**: Specialized tool for analyzing MBR/VBR code including disassembly and comparison against known-good baselines

## Common Scenarios

### Scenario: Investigating Persistent Compromise Surviving OS Reinstallation

**Context**: An organization reimaged a compromised workstation, but the same C2 beaconing resumed within hours. Standard disk forensics finds no malware. UEFI bootkit is suspected.

**Approach**:
1. Boot from a Linux live USB to avoid executing any compromised OS components
2. Dump the SPI flash firmware using chipsec or flashrom for offline analysis
3. Dump the MBR and VBR sectors with dd for boot sector analysis
4. Copy the EFI System Partition for bootloader integrity verification
5. Open the SPI dump in UEFITool and compare module GUIDs against vendor-provided firmware
6. Look for additional or modified DXE drivers that should not be present
7. Analyze any suspicious modules with Ghidra (x86_64 UEFI module format)
8. Verify Secure Boot configuration and check for exploit-based bypasses

**Pitfalls**:
- Analyzing the system while the compromised OS is running (rootkit may hide from live analysis)
- Not checking SPI flash (only analyzing disk-based boot components misses firmware-level implants)
- Assuming Secure Boot prevents all bootkits (known bypasses exist, e.g., CVE-2022-21894)
- Not preserving the original firmware dump before reflashing (critical evidence for attribution)

## Output Format

```
BOOTKIT / ROOTKIT ANALYSIS REPORT
====================================
System:           Dell OptiPlex 7090 (UEFI, TPM 2.0)
Firmware Version: 1.15.0 (Dell)
Secure Boot:      ENABLED (but bypassed)
Capture Method:   Linux Live USB + chipsec SPI dump

MBR/VBR ANALYSIS
MBR Signature:    Valid (0x55AA)
MBR Code:         MATCHES standard Windows 10 MBR (clean)
VBR Code:         MATCHES standard NTFS VBR (clean)

UEFI FIRMWARE ANALYSIS
Total Modules:    287
Vendor Expected:  285
Extra Modules:    2 UNAUTHORIZED
  [!] DXE Driver GUID: {ABCD1234-...} "SmmAccessDxe_mod" (MODIFIED)
      Original Size: 12,288 bytes
      Current Size:  45,056 bytes (32KB ADDED)
      Entropy: 7.82 (HIGH - encrypted payload)

  [!] DXE Driver GUID: {EFGH5678-...} "UefiPayloadDxe" (NEW - not in vendor firmware)
      Size: 28,672 bytes
      Function: Drops persistence agent during boot

BOOT CHAIN INTEGRITY
bootmgfw.efi:     MODIFIED (hash mismatch, Secure Boot bypass via CVE-2022-21894)
winload.efi:      MODIFIED (DSE disabled at load time)
ntoskrnl.exe:     CLEAN (but unsigned driver loaded after boot)

KERNEL ROOTKIT COMPONENTS
Driver:           C:\Windows\System32\drivers\null_mod.sys (unsigned, hidden)
SSDT Hooks:       3 (NtQuerySystemInformation, NtQueryDirectoryFile, NtDeviceIoControlFile)
Hidden Processes: 2 (PID 6784: beacon.exe, PID 6812: keylog.exe)
Hidden Files:     C:\Windows\System32\drivers\null_mod.sys

ATTRIBUTION
Family:           BlackLotus variant
Confidence:       HIGH (CVE-2022-21894 exploit, ESP modification pattern matches)

REMEDIATION
1. Reflash SPI firmware with clean vendor image via hardware programmer
2. Rebuild EFI System Partition from clean Windows installation media
3. Reinstall OS from verified media
4. Enable all firmware write protections
5. Update firmware to latest version (patches CVE-2022-21894)
```
