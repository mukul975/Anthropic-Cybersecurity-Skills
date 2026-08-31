---
name: hunting-bootkits-in-efi-system-partition
description: Baseline the EFI System Partition and hunt malicious EFI binaries such as ESPecter, BlackLotus, Bootkitty, and Glupteba by mounting the ESP, hashing and verifying boot loaders, scanning with YARA, and flagging anomalous non-EFI files or out-of-band bootloader changes. Use when running proactive threat hunts for firmware/bootkit persistence (MITRE ATT&CK T1542.003) or investigating suspected UEFI-level compromise that survives OS reinstall. Do not use for verifying Secure Boot state and dbx revocation currency - use detecting-secure-boot-bypass.
domain: cybersecurity
subdomain: hardware-firmware-security
tags:
- bootkit
- uefi
- efi-system-partition
- secure-boot
- firmware-forensics
- threat-hunting
- yara
- measured-boot
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1542.003
---
# Hunting Bootkits in the EFI System Partition

## Overview

The EFI System Partition (ESP) is a small FAT32-formatted partition that the platform firmware reads at power-on to locate and execute the operating system's boot loader. Because it executes *before* the operating system, kernel, and any EDR agent, the ESP is one of the most coveted persistence locations for advanced adversaries. UEFI bootkits that live on the ESP survive OS reinstallation, disk reformatting of the OS partition, and most endpoint defenses.

This skill follows the detection research published by **Eclypsium** ("Enhanced Threat Detection: Bootloaders, Bootkits, and Secure Boot", and the *Bootkitty* and *Glupteba* analyses) and aligns with the ESP-hunting methodology Rapid7 documented for Velociraptor (`Windows.Forensics.UEFI`, `Windows.Detection.Yara.UEFI`). The threat context is concrete and current:

- **ESPecter** (ESET, 2021) — a UEFI bootkit that persists on the ESP as a patched Windows Boot Manager (`bootmgfw.efi`) plus malicious kernel-mode drivers. It marked the move of UEFI threats *from SPI flash to the ESP*, where they are far easier to deploy.
- **BlackLotus** (2023) — the first in-the-wild UEFI bootkit able to bypass Secure Boot on fully patched Windows 11 by exploiting CVE-2022-21894 ("baton drop") and staging a vulnerable signed `bootmgfw.efi` on the ESP.
- **Bootkitty** (2024) — the first UEFI bootkit targeting Linux, dropped onto the ESP.
- **Glupteba** — commodity malware whose UEFI variant replaces software on the EFI partition.

The core detection insight from Eclypsium and Rapid7 is that the bootloader normally changes **only** during a vendor or OS update; an out-of-band change to ESP binaries, an unsigned or untrusted-signed boot loader, or any file in the ESP root that is *not* under the `EFI/` directory is a high-fidelity indicator of compromise. This skill builds that baseline and hunts deviations from it.

## When to Use

- During proactive threat hunts for firmware/bootkit persistence (MITRE ATT&CK T1542.003 — Pre-OS Boot: Bootkit)
- After an incident where an adversary achieved SYSTEM/root and may have established below-OS persistence
- When validating Secure Boot posture across a fleet and confirming boot-chain integrity
- As a periodic integrity check, comparing the current ESP contents against a trusted golden baseline
- When triaging hosts that show measured-boot (TPM PCR) mismatches

## Prerequisites

- Administrative/root access to the target host (mounting and reading the ESP requires elevation)
- Linux analysis tooling — install on Debian/Ubuntu:
  ```bash
  sudo apt-get update
  sudo apt-get install -y sbsigntool pesign efitools efibootmgr binwalk yara
  pip install pefile
  ```
- `UEFITool` for inspecting firmware/binaries (download from https://github.com/LongSoft/UEFITool/releases)
- A trusted **golden baseline** of EFI binary hashes for the OS/vendor versions in scope (build it once on a known-clean, freshly imaged host)
- For Windows targets: WinPE or a forensic boot environment, or Velociraptor with the `Windows.Forensics.UEFI` artifact

## Objectives

- Mount and enumerate the ESP read-only without altering evidence
- Inventory every EFI binary and compute cryptographic hashes
- Verify Secure Boot signatures on each boot loader against trusted keys
- Compare contents against a golden baseline to surface out-of-band changes
- YARA-scan ESP binaries for known bootkit signatures
- Flag anomalies: files outside `EFI/`, unsigned loaders, modified `bootmgfw.efi`/`grubx64.efi`, and tampered boot entries
- Confirm measured-boot (TPM PCR 0/2/4) integrity where TPM is present

## MITRE ATT&CK Mapping

| ID | Name | Relevance |
|----|------|-----------|
| T1542.003 | Pre-OS Boot: Bootkit | Adversaries place malicious boot loaders on the ESP to execute before the OS and EDR, achieving stealthy, resilient persistence. This skill hunts exactly that artifact. |

## Workflow

### Step 1: Identify and mount the ESP read-only
The ESP is a FAT32 partition, usually flagged `EF00` (GPT) or `esp,boot`. Locate it and mount read-only to preserve evidence.
```bash
# Identify the ESP (type code EF00 / "EFI System")
sudo lsblk -o NAME,FSTYPE,PARTTYPENAME,MOUNTPOINT
sudo fdisk -l | grep -i "EFI System"

# Mount the ESP read-only (replace /dev/sda1 with the identified partition)
sudo mkdir -p /mnt/esp
sudo mount -o ro,umask=077 /dev/sda1 /mnt/esp

# Confirm the canonical layout: EFI/ should be the only top-level dir
ls -la /mnt/esp
```

### Step 2: Detect anomalous top-level entries (high-fidelity hunt)
Per Rapid7/Velociraptor guidance, the ESP root should contain **only** the `EFI/` directory (and possibly a vendor `System Volume Information`). Anything else is suspicious.
```bash
# Any path in the ESP root NOT under EFI/ is a red flag
find /mnt/esp -maxdepth 1 -mindepth 1 ! -name 'EFI' ! -iname 'System Volume Information'

# Hunt for boot binaries dropped outside expected vendor folders
find /mnt/esp -type f \( -iname '*.efi' -o -iname '*.sys' -o -iname '*.dll' \) -printf '%p\t%s bytes\t%TY-%Tm-%Td\n'
```

### Step 3: Inventory and hash every EFI binary
Compute SHA-256 of all boot binaries for baseline comparison and threat-intel lookup.
```bash
# Recursively hash all EFI/PE binaries on the ESP
find /mnt/esp -type f \( -iname '*.efi' -o -iname '*.sys' \) -print0 \
  | xargs -0 sha256sum | tee /tmp/esp_hashes.txt

# Quick triage on the primary loaders
sha256sum /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi 2>/dev/null
sha256sum /mnt/esp/EFI/Boot/bootx64.efi 2>/dev/null
sha256sum /mnt/esp/EFI/*/grubx64.efi /mnt/esp/EFI/*/shimx64.efi 2>/dev/null
```
Submit unknown hashes to VirusTotal / the LOLDrivers and Binarly catalogs to identify known-vulnerable or malicious loaders (e.g., the BlackLotus-abused `bootmgfw.efi` builds).

### Step 4: Verify Secure Boot signatures on each loader
A legitimate loader is signed by Microsoft UEFI CA (Windows/shim) or the distro vendor. Use `sbverify` to list/verify signatures and `pesign` for the certificate chain.
```bash
# List embedded signatures on a loader
sbverify --list /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi

# Verify against the platform's db certificate (export it first)
sudo efi-readvar -v db -o /tmp/db.esl   # dump Secure Boot db
sbverify --cert /path/to/MicrosoftUEFICA.pem /mnt/esp/EFI/Boot/bootx64.efi

# Inspect the PE certificate chain
pesign -S -i /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi
```
An **unsigned** loader, a loader signed by an unexpected/self-signed certificate, or a known-vulnerable signed binary staged by an attacker (BlackLotus technique) is a confirmed finding.

### Step 5: Compare against the golden baseline
Diff the live ESP hash inventory against a trusted baseline captured from a clean image of the same OS/vendor build.
```bash
# Sort both inventories on the hash column and diff
awk '{print $1}' /tmp/esp_hashes.txt | sort > /tmp/live.sha256
sort baseline_esp_hashes.sha256 > /tmp/base.sha256

# Hashes present live but absent from the baseline = unexpected/new binaries
comm -23 /tmp/live.sha256 /tmp/base.sha256
```
Because the bootloader changes only during legitimate updates, any new hash that does not correspond to a known patch is an actionable lead.

### Step 6: YARA-scan ESP binaries for bootkit signatures
Run YARA rules for known bootkits (ESPecter, BlackLotus, Bootkitty, CosmicStrand) across the ESP — the same approach as Velociraptor's `Windows.Detection.Yara.UEFI`.
```bash
# Scan all ESP files recursively with a bootkit ruleset
yara -r -w bootkit_rules.yar /mnt/esp/

# Example: scan only the binaries collected in Step 3
yara -r bootkit_rules.yar /mnt/esp/EFI/
```
Source rules from the YARA-Rules project, Eclypsium/Binarly publications, and ESET's bootkit reports.

### Step 7: Inspect and validate UEFI boot entries
ESPecter-class bootkits manipulate the boot order/entries. Enumerate NVRAM boot variables and confirm each points to an expected, signed loader.
```bash
# List boot entries and the current order (Bootkitty/ESPecter tamper here)
sudo efibootmgr -v

# Confirm Secure Boot is enabled and look for revoked hashes in dbx
mokutil --sb-state
sudo efi-readvar -v dbx -o /tmp/dbx.esl
```
A boot entry referencing a file outside `\EFI\` or a loader whose hash appears in `dbx` (revoked) but is still present indicates tampering.

### Step 8: Validate measured boot against TPM PCRs (where available)
Measured boot records the boot-chain components into TPM PCRs (notably PCR 0, 2, 4). A bootkit that alters loaders changes these measurements.
```bash
# Read PCRs that cover firmware and the boot loader
sudo tpm2_pcrread sha256:0,2,4,7

# Parse the TCG event log to see what was measured into each PCR
sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements
```
Compare measured values against the host's known-good attestation baseline; an unexplained PCR 4 change correlates with a modified boot loader.

### Step 9: Document findings and preserve evidence
```bash
# Make a forensic image of the ESP for offline analysis before remediation
sudo dd if=/dev/sda1 of=/evidence/esp_$(hostname)_$(date +%F).img bs=4M conv=noerror,sync
sha256sum /evidence/esp_*.img > /evidence/esp_image.sha256
sudo umount /mnt/esp
```
Record every anomalous binary (path, hash, signature status, baseline diff result, YARA match) in the case file before any cleanup.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| sbsigntool (`sbverify`) | List/verify Secure Boot signatures on EFI binaries | https://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git |
| pesign | Inspect PE/COFF signatures and certificate chains | https://github.com/rhboot/pesign |
| efitools (`efi-readvar`) | Dump Secure Boot variables (db/dbx/KEK/PK) | https://git.kernel.org/pub/scm/linux/kernel/git/jejb/efitools.git |
| efibootmgr / mokutil | Enumerate boot entries and Secure Boot state | https://github.com/rhboot/efibootmgr |
| UEFITool | Parse and inspect UEFI binaries/firmware | https://github.com/LongSoft/UEFITool |
| YARA | Signature-scan ESP binaries for bootkits | https://github.com/VirusTotal/yara |
| tpm2-tools | Read PCRs and TCG event log for measured boot | https://github.com/tpm2-software/tpm2-tools |
| Velociraptor `Windows.Forensics.UEFI` | Scale ESP hunting across a fleet | https://docs.velociraptor.app/ |
| Eclypsium bootkit research | Threat context and detection methodology | https://eclypsium.com/blog/threat-detection-bootloaders-bootkits-secureboot/ |
| Rapid7 UEFI hunting blog | ESP hunting with Velociraptor artifacts | https://www.rapid7.com/blog/post/2024/02/29/how-to-hunt-for-uefi-malware-using-velociraptor/ |

## Known Bootkit Indicators

| Bootkit | ESP Artifact / Behavior | Reference |
|---------|-------------------------|-----------|
| ESPecter | Patched `bootmgfw.efi` + kernel drivers on ESP | ESET WeLiveSecurity 2021 |
| BlackLotus | Vulnerable signed `bootmgfw.efi` staged to bypass Secure Boot (CVE-2022-21894) | ESET 2023 |
| Bootkitty | Malicious EFI loader on ESP targeting Linux | ESET / Eclypsium 2024 |
| Glupteba (UEFI) | Replaces software on the EFI partition | Eclypsium |
| CosmicStrand | UEFI firmware implant hooking the boot chain | Eclypsium / Kaspersky |

## Validation Criteria

- [ ] ESP located and mounted read-only without modifying evidence
- [ ] Top-level ESP contents enumerated; any non-`EFI/` entries flagged
- [ ] All EFI binaries inventoried with SHA-256 hashes
- [ ] Secure Boot signatures verified on every boot loader
- [ ] Live inventory diffed against a trusted golden baseline
- [ ] YARA bootkit ruleset run across the ESP with no unexplained matches
- [ ] Boot entries (`efibootmgr`) validated; no references outside `\EFI\`
- [ ] Secure Boot confirmed enabled; no present binary matches a `dbx`-revoked hash
- [ ] TPM PCR 0/2/4 measurements compared to baseline (where TPM present)
- [ ] Forensic ESP image preserved and all findings documented
