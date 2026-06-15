---
name: analyzing-uefi-bootkit-persistence
description: 'Analyzes UEFI bootkit persistence mechanisms including firmware implants
  in SPI flash, EFI System Partition (ESP) modifications, Secure Boot bypass techniques,
  and UEFI variable manipulation. Covers detection of known bootkit families (BlackLotus,
  LoJax, MosaicRegressor, MoonBounce, CosmicStrand), ESP partition forensic inspection,
  chipsec-based firmware integrity verification, and Secure Boot configuration auditing.
  Activates for requests involving UEFI malware analysis, firmware persistence investigation,
  boot chain integrity verification, or Secure Boot bypass detection.

  '
domain: cybersecurity
subdomain: firmware-security
tags:
- UEFI
- bootkit
- firmware
- Secure-Boot
- chipsec
- ESP
- persistence
version: 1.0.0
author: mukul975
license: Apache-2.0
d3fend_techniques:
- Platform Hardening
- Restore Object
- Platform Monitoring
- Firmware Verification
- Firmware Embedded Monitoring Code
nist_csf:
- ID.RA-01
- PR.PS-01
- PR.PS-02
mitre_attack:
- T1542.001
- T1542.003
- T1553.006
- T1542
- T1014
---

# Analyzing UEFI Bootkit Persistence

## When to Use

- A compromised system re-establishes C2 communication after OS reinstallation or disk replacement
- Secure Boot has been tampered with, disabled, or shows unexpected Machine Owner Key (MOK) enrollment
- Firmware integrity verification fails against vendor-provided baselines
- Memory forensics reveals rootkit components loading during early boot phase
- Investigating advanced persistent threat (APT) campaigns known to deploy UEFI implants
- Auditing firmware security posture for enterprise endpoint hardening

**Do not use** for standard MBR-based bootkits on legacy BIOS systems without UEFI; use MBR/VBR bootkit analysis instead.

## Prerequisites

- chipsec framework for SPI flash dumping, UEFI variable inspection, and firmware security modules
- UEFITool / UEFIExtract for firmware volume parsing and DXE driver extraction
- Python 3.8+ with struct, hashlib, subprocess, and os modules
- Bootable Linux live USB for offline analysis (avoid running compromised OS)
- Volatility 3 for memory forensics of boot-phase artifacts
- YARA with UEFI malware rule sets for pattern-based detection
- Access to vendor firmware baselines for integrity comparison

## Workflow

### Step 1: Dump SPI Flash Firmware

Acquire the UEFI firmware from the SPI flash chip for offline analysis:

```bash
# Using chipsec to dump SPI flash contents
python chipsec_util.py spi dump firmware_dump.rom

# Using flashrom as an alternative
flashrom -p internal -r firmware_dump.rom

# Verify dump integrity
sha256sum firmware_dump.rom

# Read SPI flash descriptor information
python chipsec_util.py spi info

# Check SPI flash region access permissions
python chipsec_main.py -m common.spi_access

# Verify BIOS write protection is enabled
python chipsec_main.py -m common.bios_wp

# Check SPI flash controller lock
python chipsec_main.py -m common.spi_lock
```

### Step 2: Inspect UEFI Variables

Enumerate and analyze UEFI variables for unauthorized modifications:

```bash
# List all UEFI variables on a live system
python chipsec_util.py uefi var-list

# List UEFI variables from a SPI flash dump
python chipsec_util.py uefi var-list-spi firmware_dump.rom

# Read specific Secure Boot variables
python chipsec_util.py uefi var-read SecureBoot 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read SetupMode 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read PK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F

# Dump UEFI key databases for analysis
python chipsec_util.py uefi keys

# Check Secure Boot configuration module
python chipsec_main.py -m common.secureboot.variables
```

### Step 3: Analyze EFI System Partition (ESP)

Inspect the ESP for unauthorized or modified boot components:

```bash
# Mount ESP (typically the first FAT32 partition, ~100-500MB)
mkdir /mnt/esp
mount /dev/sda1 /mnt/esp

# List all files on ESP with timestamps
find /mnt/esp -type f -exec ls -la {} \;

# Check for BlackLotus indicators - custom directory under ESP:/system32/
ls -la /mnt/esp/system32/ 2>/dev/null

# Verify Windows Boot Manager signature
sigcheck -a /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi

# Hash all EFI binaries for comparison against known-good values
find /mnt/esp -name "*.efi" -exec sha256sum {} \;

# Check for unauthorized .efi files outside standard directories
find /mnt/esp -name "*.efi" | grep -v "Microsoft\|Boot\|ubuntu\|grub"

# Look for grubx64.efi planted by BlackLotus
find /mnt/esp -name "grubx64.efi" -exec sha256sum {} \;

# Examine MeasuredBoot logs for anomalies (Windows)
# Logs located at C:\Windows\Logs\MeasuredBoot\
```

### Step 4: Scan Firmware for Known Bootkit Signatures

Analyze the firmware dump for known UEFI malware patterns:

```bash
# Extract all firmware modules with UEFIExtract
UEFIExtract firmware_dump.rom all

# Generate firmware module whitelist from vendor baseline
python chipsec_main.py -m tools.uefi.whitelist -a generate,baseline.json,firmware_vendor.rom

# Compare current firmware against whitelist
python chipsec_main.py -m tools.uefi.whitelist -a check,baseline.json,firmware_dump.rom

# Scan firmware with UEFI-specific YARA rules
yara -r uefi_bootkits.yar firmware_dump.rom

# Scan extracted modules individually
find firmware_dump.rom.dump -name "*.efi" -exec yara -r uefi_bootkits.yar {} \;

# Check for modified CORE_DXE module (targeted by MoonBounce, CosmicStrand)
# Compare GUID and hash against vendor baseline
```

### Step 5: Detect Secure Boot Bypass Mechanisms

Check for known Secure Boot bypass techniques:

```bash
# Check if Secure Boot is enabled
python chipsec_main.py -m common.secureboot.variables

# Verify SMM (System Management Mode) protections
python chipsec_main.py -m common.smm

# Check SMM BIOS write protection
python chipsec_main.py -m common.bios_smi

# On Windows - check boot configuration for bypass indicators
bcdedit /enum firmware
bcdedit /v

# Check for testsigning/nointegritychecks/debug flags
bcdedit | findstr /i "testsigning nointegritychecks debug"

# Verify HVCI (Hypervisor-enforced Code Integrity) is not disabled
# BlackLotus sets HKLM:\...\DeviceGuard\...\HypervisorEnforcedCodeIntegrity Enabled=0
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled

# Check Secure Boot state via PowerShell
# Confirm-SecureBootUEFI returns True if properly enabled
```

### Step 6: Perform Boot Chain Integrity Verification

Verify every component in the boot chain from firmware through kernel:

```bash
# Verify firmware integrity against vendor hash
sha256sum firmware_dump.rom
# Compare with vendor-published hash

# Verify bootloader signatures
sigcheck -a C:\Windows\Boot\EFI\bootmgfw.efi
sigcheck -a C:\Windows\System32\winload.efi
sigcheck -a C:\Windows\System32\ntoskrnl.exe

# Check for unsigned or invalid boot drivers
sigcheck -u -e C:\Windows\System32\drivers\

# Analyze Measured Boot logs for unexpected EFI_Boot_Services_Application entries
# BlackLotus components appear as EV_EFI_Boot_Services_Application

# Memory forensics for boot-phase artifacts
vol3 -f memory.dmp windows.modules
vol3 -f memory.dmp windows.driverscan
```

### Step 7: Document UEFI Bootkit Analysis Findings

Compile a comprehensive analysis report:

```
Report should include:
- Firmware version, vendor, and platform identification
- SPI flash protection status (write protect, lock bits, access control)
- Secure Boot configuration and any bypass indicators detected
- UEFI variable anomalies (unauthorized keys, modified db/dbx, MOK enrollment)
- ESP contents inventory with hash verification against known-good baselines
- Firmware module comparison against vendor whitelist (added, modified, removed)
- Known bootkit family attribution with confidence level
- Boot chain integrity verification results for each component
- Remediation steps (reflash, key rotation, hardware replacement)
- MITRE ATT&CK mapping (T1542.001 - System Firmware, T1542.003 - Bootkit)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **UEFI Bootkit** | Malware that persists in UEFI firmware or the boot process, executing before the operating system loads and surviving OS reinstallation |
| **SPI Flash** | Serial Peripheral Interface flash memory chip on the motherboard storing UEFI firmware; firmware-level bootkits like LoJax and MoonBounce modify SPI flash contents |
| **EFI System Partition (ESP)** | FAT32 partition containing EFI bootloaders and drivers; bootkits like BlackLotus and ESPecter modify files on the ESP for persistence |
| **Secure Boot** | UEFI security feature that verifies digital signatures of boot components; can be bypassed via vulnerabilities (CVE-2022-21894) or MOK enrollment |
| **DXE Driver** | Driver Execution Environment driver loaded during UEFI boot; firmware implants inject malicious DXE drivers that execute before the OS |
| **Machine Owner Key (MOK)** | User-installable Secure Boot key; BlackLotus enrolls attacker-controlled MOKs to sign malicious bootloaders |
| **chipsec** | Intel platform security assessment framework for analyzing SPI flash, UEFI variables, Secure Boot, and hardware security configurations |
| **HVCI** | Hypervisor-enforced Code Integrity, a Windows security feature that bootkits disable to load unsigned kernel drivers |

## Tools & Systems

- **chipsec**: Intel framework for dumping SPI flash, reading UEFI variables, verifying firmware write protection, and Secure Boot configuration auditing
- **UEFITool**: Open-source UEFI firmware image parser for inspecting firmware volumes, extracting DXE drivers, and comparing module GUIDs
- **sigcheck**: Sysinternals utility for verifying digital signatures of EFI binaries and boot chain components
- **flashrom**: Open-source SPI flash programmer for reading and writing firmware chips on supported platforms
- **YARA**: Pattern matching engine used with UEFI-specific rule sets to detect known bootkit signatures in firmware dumps

## Common Scenarios

### Scenario: Investigating Persistent Compromise Surviving OS Reinstallation

**Context**: An enterprise endpoint was reimaged after a confirmed breach, but identical C2 beaconing resumed within hours. The endpoint has UEFI firmware with Secure Boot enabled, and a TPM 2.0 chip. The security team suspects a UEFI-level implant similar to BlackLotus or LoJax.

**Approach**:
1. Boot the system from a trusted Linux live USB to avoid executing any compromised OS components
2. Dump SPI flash firmware using `chipsec_util.py spi dump` for offline analysis
3. Mount the ESP and hash all `.efi` files for comparison against known-good values from identical hardware
4. Check for the `ESP:/system32/` directory (BlackLotus indicator) and unauthorized `grubx64.efi`
5. Extract firmware modules with UEFIExtract and compare GUID inventory against vendor baseline
6. Verify Secure Boot variables -- look for unauthorized MOK enrollment or modified db/dbx
7. Check SPI flash write protection and lock bits using chipsec modules
8. Scan firmware dump and extracted modules with UEFI-specific YARA rules
9. If BlackLotus is suspected, check registry for HVCI disabled and MeasuredBoot logs for anomalous entries

**Pitfalls**:
- Running analysis from the compromised OS (rootkit components hide from live analysis)
- Only checking the ESP without examining SPI flash firmware (misses firmware-level implants like LoJax, MoonBounce)
- Assuming Secure Boot prevents all bootkits (CVE-2022-21894 and other bypasses exist)
- Not preserving the original firmware dump before remediation (critical forensic evidence)
- Reflashing firmware without verifying the vendor image is authentic and unmodified

## Output Format

```
UEFI BOOTKIT PERSISTENCE ANALYSIS REPORT
============================================
System:           Lenovo ThinkPad X1 Carbon Gen 11
Firmware:         N3HET82W (1.54) - Lenovo UEFI BIOS
Platform:         Intel 13th Gen (Raptor Lake)
TPM:              2.0 (Infineon SLB 9672)
Secure Boot:      ENABLED (BYPASSED via CVE-2022-21894)
Analysis Method:  Linux live USB + chipsec + UEFITool

SPI FLASH PROTECTION STATUS
BIOS Write Protection:    DISABLED [!]
SPI Flash Lock (FLOCKDN): SET [OK]
SMM BIOS Write Protect:   DISABLED [!]
SPI Protected Ranges:     Region 0 only (descriptor)

UEFI VARIABLE ANALYSIS
SecureBoot:        Enabled (value=1)
SetupMode:         Disabled (value=0)
PK:                Lenovo Ltd. (legitimate)
KEK:               Microsoft + Lenovo (legitimate)
db:                MODIFIED - contains unauthorized entry [!]
  [!] Unknown certificate: CN=Secure Boot Signing, O=Unknown
  [!] Not present in vendor baseline db
MOK:               1 unauthorized key enrolled [!]
  [!] MOK enrolled: CN=shim, self-signed, not from distro vendor

ESP PARTITION ANALYSIS
Total EFI binaries:     12
Verified (signed):      9
Modified (hash mismatch): 2 [!]
Unauthorized:           1 [!]

  [!] EFI/Microsoft/Boot/bootmgfw.efi - MODIFIED
      Expected SHA-256: a3f2c8...
      Current SHA-256:  7b1e4d...
      Signature:        Valid (signed with unauthorized MOK)

  [!] EFI/Microsoft/Boot/grubx64.efi - UNAUTHORIZED
      SHA-256:  e9c1a7...
      Not present in vendor baseline
      Matches BlackLotus stage-2 loader signature

  [!] system32/ directory present on ESP (BlackLotus artifact)
      Directory empty (files deleted post-installation)

FIRMWARE MODULE ANALYSIS
Total firmware modules:   312
Vendor baseline modules:  312
Added modules:            0
Modified modules:         0
SPI flash integrity:      CLEAN (no firmware-level implant detected)

BOOTKIT ATTRIBUTION
Family:           BlackLotus
Confidence:       HIGH
Persistence:      ESP-based (not SPI flash)
Bypass Method:    CVE-2022-21894 (baton drop)
MITRE ATT&CK:    T1542.003 (Bootkit), T1553.006 (Code Signing Policy Modification)

INDICATORS OF COMPROMISE
- ESP:/system32/ directory (empty, post-cleanup artifact)
- ESP:/EFI/Microsoft/Boot/grubx64.efi (unauthorized, BlackLotus loader)
- Modified bootmgfw.efi (re-signed with attacker MOK)
- HVCI disabled via registry: DeviceGuard\...\Enabled = 0
- Unauthorized MOK enrollment in UEFI variable store
- MeasuredBoot log shows EV_EFI_Boot_Services_Application for grubx64.efi

REMEDIATION
1. Replace bootmgfw.efi with authentic copy from Windows installation media
2. Delete unauthorized grubx64.efi and system32/ directory from ESP
3. Reset Secure Boot keys to factory defaults (clear MOK, restore PK/KEK/db)
4. Enable BIOS write protection and verify SPI flash lock bits
5. Apply firmware update to latest version (patches CVE-2022-21894)
6. Enable HVCI and verify via Group Policy
7. Reimport only trusted certificates into Secure Boot db
8. Monitor MeasuredBoot logs for anomalous boot component loading
```
