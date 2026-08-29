---
name: auditing-uefi-firmware-with-chipsec
description: Use Intel CHIPSEC to assess platform firmware configuration, verifying SPI flash write protection, BIOS lock, SMM/SMRR, and Secure Boot variable state, running the automated test suite, dumping SPI flash, and triaging UEFI variables for firmware-level threats. Use when baselining or hardening a platform's firmware defenses and confirming that write-protection and flash locks are correctly engaged. Do not use for investigating or attributing an active UEFI bootkit infection like BlackLotus or LoJax - use analyzing-uefi-bootkit-persistence.
domain: cybersecurity
subdomain: hardware-firmware-security
tags:
- hardware-firmware-security
- uefi
- chipsec
- spi-flash
- bios-write-protection
- secure-boot
- firmware-assessment
- platform-security
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.AM-02
mitre_attack:
- T1542.001
---
# Auditing UEFI Firmware with CHIPSEC

> **Authorized Use Only:** CHIPSEC loads a kernel driver and reads/writes low-level hardware registers, SPI flash, and SMM. Run it only on systems you own or are explicitly authorized to assess, ideally on dedicated test hardware. Misuse (especially write/modify modules) can brick a machine. Never run write-capable modules on production systems.

## Overview

CHIPSEC is the open-source **Platform Security Assessment Framework** created by Intel's Advanced Threat Research team. It inspects the low-level security configuration of x86 platform firmware and hardware — the layer below the operating system where bootkits and firmware implants live. CHIPSEC loads a signed kernel driver (Linux, Windows, or it can run from the UEFI shell) to read and write hardware registers, Model-Specific Registers (MSRs), PCI config space, SPI flash, and UEFI variables, then runs an automated test suite that checks whether the platform's defensive locks are actually engaged.

The threat CHIPSEC addresses is MITRE ATT&CK **T1542.001 — Pre-OS Boot: System Firmware**: adversaries who modify system firmware (the BIOS/UEFI image on SPI flash) to gain stealthy, persistent, OS-survivable control. Firmware implants persist across OS reinstall and disk replacement and are invisible to most EDR. CHIPSEC's value is verifying the *prerequisites* that prevent such implants: that the SPI flash BIOS region is write-protected (BIOS_CNTL `BLE`/`SMM_BWP`, SPI Protected Ranges), that the flash descriptor locks region access, that SMRAM/SMRR are configured, and that Secure Boot variables are protected. It also dumps the SPI flash for offline forensic comparison.

Sources: Intel/CHIPSEC project (https://github.com/chipsec/chipsec), CHIPSEC documentation (https://chipsec.github.io/).

## When to Use

- Baseline firmware-security assessment of a new laptop/server platform or fleet image
- Verifying that BIOS write protection and SPI flash locks are correctly enabled by the OEM
- Firmware forensics: dumping SPI flash to compare against a known-good image
- Validating Secure Boot variable protection and S3 boot-script protection
- Hunting for evidence of a firmware implant or misconfiguration enabling one

## Prerequisites

- Physical or admin/root access to the target x86 platform (Intel or AMD)
- Linux (root) or Windows (Administrator), or a UEFI shell environment
- Ability to load a kernel driver (Secure Boot may need to allow the CHIPSEC driver, or use `--no_driver` for limited checks)
- Python 3.8+ and a C compiler/build tools for the kernel module on Linux
- Dedicated test hardware strongly recommended

Install CHIPSEC:

```bash
# From PyPI
pip install chipsec

# Or from source (builds the kernel helper/driver)
git clone https://github.com/chipsec/chipsec
cd chipsec
python setup.py install        # builds and installs, including the Linux driver

# Verify
sudo chipsec_main --help
sudo chipsec_util --help
```

## Objectives

- Run the full automated platform-security test suite and interpret PASS/FAIL/WARNING
- Verify BIOS write protection (BIOS_CNTL) and SPI Protected Ranges
- Verify the SPI flash descriptor locks region read/write access
- Verify SMRAM/SMRR and SMI handler protections
- Verify Secure Boot variable protection and S3 boot-script protection
- Dump SPI flash and decode it for offline analysis
- Enumerate UEFI variables and detect anomalous/unexpected entries

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1542.001 | Pre-OS Boot: System Firmware | Persistence / Defense Evasion |

CHIPSEC defends against T1542.001 by verifying that the controls preventing unauthorized firmware modification are enabled. A FAIL on `common.bios_wp` (BIOS not write-protected) or `chipsec.modules.common.spi_lock` (flash descriptor unlocked) means an attacker with OS privileges could rewrite the SPI flash and implant persistent firmware — exactly the precondition for this technique.

## Workflow

### Step 1: Run the full automated test suite
`chipsec_main` with no module argument runs every applicable security check for the detected platform and prints a summary of PASS/FAIL/WARNING/INFORMATION results.

```bash
sudo chipsec_main

# Save machine-readable output for reporting / diffing
sudo chipsec_main -j results.json -x results.xml -l chipsec.log
```

### Step 2: Run the core firmware-protection modules individually
The `common` module group contains the OEM-independent security checks. Run the group or specific modules:

```bash
# Run the whole common group
sudo chipsec_main -m common

# BIOS write protection: checks BIOS_CNTL BLE/SMM_BWP and SPI protected ranges
sudo chipsec_main -m common.bios_wp

# SPI flash descriptor lock (FLOCKDN) — are flash region accesses locked?
sudo chipsec_main -m common.spi_lock

# SMRR programming — protects SMRAM from cache-based attacks
sudo chipsec_main -m common.smrr

# SMM BIOS write protection
sudo chipsec_main -m common.smm

# S3 resume boot-script protection (against bootscript table attacks)
sudo chipsec_main -m common.uefi.s3bootscript
```

### Step 3: Verify Secure Boot variable protection
```bash
# Checks that Secure Boot UEFI variables are properly protected
sudo chipsec_main -m common.secureboot.variables

# To actively test write protection of the variables (test hardware ONLY):
sudo chipsec_main -m common.secureboot.variables -a modify
```

### Step 4: Inspect SPI flash region access permissions
```bash
# Report SPI flash regions, descriptor, and access permissions
sudo chipsec_util spi info

# Check the SPI access-control module
sudo chipsec_main -m common.spi_access
```

### Step 5: Dump SPI flash for offline forensics
Dumping the flash lets you decode the firmware volumes and compare against a known-good OEM image.

```bash
# Dump the entire SPI flash to a file
sudo chipsec_util spi dump rom.bin

# Decode the dumped image: extracts firmware volumes, files, NVRAM variables, etc.
sudo chipsec_util decode rom.bin
```

### Step 6: Enumerate and triage UEFI variables
```bash
# List all UEFI variables from the runtime interface
sudo chipsec_util uefi var-list

# List variables directly from the SPI image (offline)
sudo chipsec_util uefi var-find PK
sudo chipsec_util uefi var-read db <GUID> db.bin

# Decode the UEFI firmware structure
sudo chipsec_util uefi decode rom.bin
```

### Step 7: Limited assessment without a kernel driver
Where loading the driver is impossible (locked-down Secure Boot), some checks still run read-only.

```bash
sudo chipsec_main -n            # --no_driver: skip checks that need the driver
sudo chipsec_main -p <PLATFORM> # force platform code if auto-detect fails
```

### Step 8: Triage results and report
- **FAIL** on `bios_wp` / `spi_lock` → firmware is rewritable from the OS: high risk for T1542.001.
- **FAIL** on `secureboot.variables` → Secure Boot policy can be tampered.
- Compare the `spi dump` against the OEM's known-good image (hash firmware volumes) to detect unauthorized modification.
- Record platform, BIOS version, and every FAIL/WARNING with the relevant register values for the report.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| chipsec_main | Automated platform-security test suite | https://github.com/chipsec/chipsec |
| chipsec_util | Manual hardware/firmware access (spi, uefi, decode) | https://chipsec.github.io/ |
| UEFITool | GUI/CLI parsing of dumped UEFI images | https://github.com/LongSoft/UEFITool |
| Binarly fwhunt | Firmware vulnerability/implant hunting rules | https://github.com/binarly-io/fwhunt-scan |
| NSA UEFI Secure Boot guidance | Hardening reference | https://media.defense.gov/ |

## Core Module Reference

| Module | Checks |
|--------|--------|
| common.bios_wp | BIOS_CNTL BLE / SMM_BWP and SPI Protected Ranges |
| common.spi_lock | SPI flash descriptor FLOCKDN |
| common.spi_access | SPI flash region read/write permissions |
| common.smrr | System Management Range Registers programming |
| common.smm | SMM BIOS write protection |
| common.secureboot.variables | Secure Boot variable protection |
| common.uefi.s3bootscript | S3 resume boot-script protection |

## Validation Criteria

- [ ] CHIPSEC installed and driver loads (or `-n` documented if not)
- [ ] Full `chipsec_main` suite executed with JSON/XML/log output saved
- [ ] `common.bios_wp` result interpreted (write protection state)
- [ ] `common.spi_lock` / `spi_access` result interpreted (descriptor lock)
- [ ] SMRR/SMM module results recorded
- [ ] Secure Boot variable protection checked
- [ ] SPI flash dumped and decoded for offline analysis
- [ ] UEFI variables enumerated and triaged
- [ ] All FAIL/WARNING findings documented with platform/BIOS version
- [ ] Write/modify modules NOT run on production hardware
