#!/usr/bin/env python3
"""UEFI bootkit persistence analysis agent for detecting firmware implants,
ESP modifications, Secure Boot bypasses, and UEFI variable manipulation."""

import argparse
import struct
import hashlib
import os
import sys
import subprocess
import re
import math
from collections import Counter
from pathlib import Path

DISCLAIMER = """
==========================================================================
  AUTHORIZED USE ONLY -- This tool is intended for authorized firmware
  security assessments, incident response, and defensive security research.
  Analyzing UEFI firmware and boot components requires appropriate system
  access and authorization. Unauthorized firmware modification or Secure
  Boot key manipulation may render systems unbootable or violate policy.
==========================================================================
"""


# ---------------------------------------------------------------------------
# Known Bootkit Signatures and IOCs
# ---------------------------------------------------------------------------

KNOWN_BOOTKITS = {
    "BlackLotus": {
        "description": "First in-the-wild UEFI bootkit bypassing Secure Boot on fully patched Windows 11",
        "cve": "CVE-2022-21894",
        "persistence": "ESP-based (modifies bootmgfw.efi, enrolls attacker MOK)",
        "esp_indicators": ["system32/", "grubx64.efi"],
        "registry_indicators": {
            r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity": {
                "Enabled": 0
            }
        },
        "mitre": "T1542.003",
    },
    "LoJax": {
        "description": "First SPI flash firmware implant found in the wild (APT28/Fancy Bear)",
        "cve": None,
        "persistence": "SPI flash (injects DXE driver into firmware volume)",
        "firmware_indicators": ["rpcnetp.exe", "autoche.exe"],
        "dxe_modifications": True,
        "mitre": "T1542.001",
    },
    "MoonBounce": {
        "description": "SPI flash implant modifying CORE_DXE module to hook GetVariable()",
        "cve": None,
        "persistence": "SPI flash (modifies CORE_DXE firmware module)",
        "firmware_indicators": ["CORE_DXE modification", "GetVariable hook"],
        "dxe_modifications": True,
        "mitre": "T1542.001",
    },
    "CosmicStrand": {
        "description": "Firmware rootkit modifying CORE_DXE to hook kernel initialization",
        "cve": None,
        "persistence": "SPI flash (patches CORE_DXE)",
        "firmware_indicators": ["CORE_DXE modification", "kernel callback shellcode"],
        "dxe_modifications": True,
        "mitre": "T1542.001",
    },
    "ESPecter": {
        "description": "ESP-based bootkit that patches winload.efi to disable DSE",
        "cve": None,
        "persistence": "ESP-based (modifies Windows Boot Manager)",
        "esp_indicators": ["modified winload.efi", "unsigned kernel driver"],
        "mitre": "T1542.003",
    },
    "MosaicRegressor": {
        "description": "Multi-component UEFI implant using NTFS file drops via READY_TO_BOOT callbacks",
        "cve": None,
        "persistence": "SPI flash (READY_TO_BOOT callback for NTFS drops)",
        "firmware_indicators": ["fTA variable", "READY_TO_BOOT callback"],
        "dxe_modifications": True,
        "mitre": "T1542.001",
    },
    "Bootkitty": {
        "description": "First UEFI bootkit targeting Linux systems",
        "cve": None,
        "persistence": "ESP-based (modifies GRUB bootloader)",
        "esp_indicators": ["modified grubx64.efi"],
        "mitre": "T1542.003",
    },
}

# UEFI Secure Boot variable GUIDs
SECUREBOOT_GUID = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
IMAGE_SECURITY_GUID = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F"

# Standard UEFI firmware volume GUIDs
KNOWN_FV_GUIDS = {
    "8C8CE578-8A3D-4F1C-9935-896185C32DD3": "Firmware File System (FFS) v2",
    "5473C07A-3DCB-4DCA-BD6F-1E9689E7349A": "Firmware File System (FFS) v3",
    "04ADEEAD-61FF-4D31-B6BA-64F8BF901F5A": "Apple ROM section",
    "16B45DA2-7D70-4AEA-A58D-760E9ECB841D": "DXE Core volume",
}


# ---------------------------------------------------------------------------
# ESP Partition Analysis
# ---------------------------------------------------------------------------

def scan_esp_partition(esp_mount_path):
    """Scan a mounted EFI System Partition for bootkit indicators."""
    findings = []
    if not os.path.isdir(esp_mount_path):
        return [{"severity": "ERROR", "message": f"ESP path not found: {esp_mount_path}"}]

    # Check for BlackLotus system32 directory
    system32_path = os.path.join(esp_mount_path, "system32")
    if os.path.exists(system32_path):
        findings.append({
            "severity": "CRITICAL",
            "indicator": "BlackLotus",
            "message": f"BlackLotus artifact: system32/ directory found on ESP at {system32_path}",
            "path": system32_path,
        })

    # Enumerate all EFI binaries
    efi_files = []
    for root, dirs, files in os.walk(esp_mount_path):
        for fname in files:
            if fname.lower().endswith(".efi"):
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, esp_mount_path)
                file_hash = hash_file(full_path)
                file_size = os.path.getsize(full_path)
                efi_files.append({
                    "path": rel_path,
                    "full_path": full_path,
                    "sha256": file_hash,
                    "size": file_size,
                })

    # Check for unauthorized grubx64.efi (BlackLotus indicator)
    for ef in efi_files:
        if "grubx64.efi" in ef["path"].lower():
            # grubx64.efi on a Windows-only system is suspicious
            findings.append({
                "severity": "HIGH",
                "indicator": "BlackLotus/Bootkitty",
                "message": f"Suspicious grubx64.efi found: {ef['path']} ({ef['size']} bytes)",
                "sha256": ef["sha256"],
            })

    # Check for files outside standard EFI directories
    standard_dirs = {"efi", "boot", "microsoft", "ubuntu", "debian", "fedora", "grub"}
    for ef in efi_files:
        parts = Path(ef["path"]).parts
        top_dirs = {p.lower() for p in parts[:-1]}
        if not top_dirs.intersection(standard_dirs):
            findings.append({
                "severity": "MEDIUM",
                "indicator": "Unknown",
                "message": f"EFI binary in non-standard location: {ef['path']}",
                "sha256": ef["sha256"],
            })

    return findings, efi_files


def hash_file(file_path):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------------------------------------------------------------------------
# Firmware Analysis
# ---------------------------------------------------------------------------

EFI_FV_HEADER_MAGIC = b"_FVH"
PE_MAGIC = b"MZ"


def scan_firmware_dump(firmware_path):
    """Scan a raw firmware dump for EFI firmware volumes and PE/COFF executables."""
    if not os.path.isfile(firmware_path):
        return {"error": f"Firmware file not found: {firmware_path}"}

    file_size = os.path.getsize(firmware_path)
    with open(firmware_path, "rb") as f:
        data = f.read()

    firmware_hash = hashlib.sha256(data).hexdigest()
    results = {
        "file": os.path.basename(firmware_path),
        "size": file_size,
        "sha256": firmware_hash,
        "firmware_volumes": [],
        "pe_executables": [],
        "suspicious_strings": [],
    }

    # Find firmware volume headers (_FVH signature at offset 0x28 in FV header)
    offset = 0
    while offset < len(data) - 0x40:
        idx = data.find(EFI_FV_HEADER_MAGIC, offset)
        if idx == -1:
            break
        # FV header signature is at offset 0x28 from the start of the volume
        fv_start = idx - 0x28
        if fv_start >= 0:
            # Parse FV header length (8 bytes at offset 0x20)
            fv_length = struct.unpack_from("<Q", data, fv_start + 0x20)[0]
            # Extract GUID (16 bytes at offset 0x10)
            guid_bytes = data[fv_start + 0x10:fv_start + 0x20]
            guid_str = format_guid(guid_bytes)
            results["firmware_volumes"].append({
                "offset": f"0x{fv_start:08X}",
                "length": fv_length,
                "guid": guid_str,
                "description": KNOWN_FV_GUIDS.get(guid_str, "Unknown firmware volume"),
            })
        offset = idx + 4

    # Find PE/COFF executables (EFI binaries)
    offset = 0
    while offset < len(data) - 64:
        idx = data.find(PE_MAGIC, offset)
        if idx == -1:
            break
        # Verify PE header: check for "PE\0\0" at e_lfanew offset
        if idx + 0x3C < len(data):
            pe_offset = struct.unpack_from("<I", data, idx + 0x3C)[0]
            if idx + pe_offset + 4 < len(data):
                pe_sig = data[idx + pe_offset:idx + pe_offset + 4]
                if pe_sig == b"PE\x00\x00":
                    results["pe_executables"].append({
                        "offset": f"0x{idx:08X}",
                        "pe_header_offset": f"0x{idx + pe_offset:08X}",
                    })
        offset = idx + 2

    # Scan for suspicious strings in firmware
    suspicious_patterns = [
        (rb"rpcnetp", "LoJax dropper component"),
        (rb"autoche", "LoJax persistence component"),
        (rb"SmmAccessDxe", "Potential DXE driver modification target"),
        (rb"CORE_DXE", "Core DXE module (MoonBounce/CosmicStrand target)"),
        (rb"GetVariable", "UEFI runtime service (hooking target)"),
        (rb"SetVariable", "UEFI runtime service (variable manipulation)"),
        (rb"READY_TO_BOOT", "Boot event callback (MosaicRegressor indicator)"),
        (rb"\\EFI\\Microsoft\\Boot", "Windows boot path reference"),
        (rb"cmd\.exe", "Command shell reference in firmware (suspicious)"),
        (rb"powershell", "PowerShell reference in firmware (suspicious)"),
    ]
    for pattern, description in suspicious_patterns:
        matches = [m.start() for m in re.finditer(pattern, data, re.IGNORECASE)]
        if matches:
            results["suspicious_strings"].append({
                "pattern": pattern.decode("ascii", errors="replace"),
                "description": description,
                "occurrences": len(matches),
                "offsets": [f"0x{o:08X}" for o in matches[:5]],
            })

    return results


def format_guid(guid_bytes):
    """Format 16 raw GUID bytes into standard XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX form."""
    if len(guid_bytes) != 16:
        return guid_bytes.hex().upper()
    part1 = struct.unpack_from("<IHH", guid_bytes, 0)
    part2 = guid_bytes[8:16]
    return (f"{part1[0]:08X}-{part1[1]:04X}-{part1[2]:04X}-"
            f"{part2[0]:02X}{part2[1]:02X}-"
            f"{part2[2]:02X}{part2[3]:02X}{part2[4]:02X}"
            f"{part2[5]:02X}{part2[6]:02X}{part2[7]:02X}")


# ---------------------------------------------------------------------------
# Secure Boot Verification
# ---------------------------------------------------------------------------

def check_secure_boot_status():
    """Check Secure Boot status on the local system (Linux)."""
    results = {}
    # Try reading from efivarfs (Linux)
    efivar_path = "/sys/firmware/efi/efivars"
    if os.path.isdir(efivar_path):
        results["efi_available"] = True
        secureboot_var = os.path.join(
            efivar_path,
            f"SecureBoot-{SECUREBOOT_GUID.lower()}"
        )
        if os.path.exists(secureboot_var):
            with open(secureboot_var, "rb") as f:
                raw = f.read()
            # First 4 bytes are attributes, 5th byte is the value
            if len(raw) >= 5:
                value = raw[4]
                results["secure_boot_enabled"] = value == 1
                results["secure_boot_value"] = value
        setupmode_var = os.path.join(
            efivar_path,
            f"SetupMode-{SECUREBOOT_GUID.lower()}"
        )
        if os.path.exists(setupmode_var):
            with open(setupmode_var, "rb") as f:
                raw = f.read()
            if len(raw) >= 5:
                results["setup_mode"] = raw[4] == 1
    else:
        results["efi_available"] = False
        results["note"] = "Not a UEFI system or efivarfs not mounted"
    return results


# ---------------------------------------------------------------------------
# Chipsec Subprocess Interface
# ---------------------------------------------------------------------------

def run_chipsec_module(module_name, args=None):
    """Run a chipsec module via subprocess and return output."""
    cmd = ["python", "chipsec_main.py", "-m", module_name]
    if args:
        cmd.extend(["-a", args])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "module": module_name,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "rc": result.returncode,
            "passed": "PASSED" in result.stdout,
            "failed": "FAILED" in result.stdout or "WARNING" in result.stdout,
        }
    except FileNotFoundError:
        return {"module": module_name, "error": "chipsec not found in PATH", "rc": -1}
    except subprocess.TimeoutExpired:
        return {"module": module_name, "error": "chipsec module timed out", "rc": -2}


def run_chipsec_spi_dump(output_path):
    """Dump SPI flash contents via chipsec."""
    cmd = ["python", "chipsec_util.py", "spi", "dump", output_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode}
    except FileNotFoundError:
        return {"error": "chipsec not found in PATH", "rc": -1}
    except subprocess.TimeoutExpired:
        return {"error": "SPI dump timed out", "rc": -2}


def run_firmware_security_audit():
    """Run a comprehensive set of chipsec security modules."""
    modules = [
        ("common.bios_wp", "BIOS region write protection"),
        ("common.spi_lock", "SPI flash controller lock"),
        ("common.spi_access", "SPI flash region access permissions"),
        ("common.spi_desc", "SPI flash descriptor security"),
        ("common.secureboot.variables", "Secure Boot variable configuration"),
        ("common.smm", "SMM protection (SMRAM range)"),
        ("common.bios_smi", "SMI suppression / BIOS write via SMI"),
    ]
    results = {}
    for module, description in modules:
        print(f"  Running: {module} ({description})...")
        result = run_chipsec_module(module)
        result["description"] = description
        results[module] = result
    return results


# ---------------------------------------------------------------------------
# Entropy Analysis for Firmware Regions
# ---------------------------------------------------------------------------

def firmware_entropy_map(firmware_path, block_size=4096):
    """Generate block-level entropy map to detect encrypted/compressed firmware regions."""
    results = []
    with open(firmware_path, "rb") as f:
        offset = 0
        while True:
            block = f.read(block_size)
            if not block:
                break
            counter = Counter(block)
            length = len(block)
            if length == 0:
                entropy = 0.0
            else:
                entropy = -sum(
                    (c / length) * math.log2(c / length)
                    for c in counter.values()
                )
            classification = "empty" if entropy < 1.0 else \
                            "code/data" if entropy < 5.0 else \
                            "compressed" if entropy < 7.5 else "encrypted/random"
            results.append({
                "offset": f"0x{offset:08X}",
                "entropy": round(entropy, 4),
                "classification": classification,
            })
            offset += len(block)
    return results


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyze_uefi_bootkit(target_path, target_type="firmware"):
    """Perform UEFI bootkit persistence analysis on a firmware dump or ESP mount point."""
    print("=" * 65)
    print("  UEFI Bootkit Persistence Analysis Agent")
    print("=" * 65)

    if target_type == "firmware" and os.path.isfile(target_path):
        print(f"\n[*] Analyzing firmware dump: {target_path}")
        print(f"[*] File size: {os.path.getsize(target_path)} bytes")
        print(f"[*] SHA-256: {hash_file(target_path)}")

        # Firmware volume and PE scan
        print("\n--- Firmware Structure Analysis ---")
        fw_results = scan_firmware_dump(target_path)
        print(f"  Firmware volumes found: {len(fw_results['firmware_volumes'])}")
        for fv in fw_results["firmware_volumes"]:
            print(f"    {fv['offset']}  GUID={fv['guid']}  Size={fv['length']}  [{fv['description']}]")
        print(f"  PE/COFF executables found: {len(fw_results['pe_executables'])}")
        for pe in fw_results["pe_executables"][:10]:
            print(f"    {pe['offset']}  (PE header at {pe['pe_header_offset']})")

        # Suspicious strings
        if fw_results["suspicious_strings"]:
            print("\n--- Suspicious Strings in Firmware ---")
            for ss in fw_results["suspicious_strings"]:
                print(f"  [!] {ss['description']}: \"{ss['pattern']}\" "
                      f"({ss['occurrences']} occurrences)")
                for off in ss["offsets"]:
                    print(f"      at {off}")

        # Entropy analysis
        print("\n--- Firmware Entropy Analysis ---")
        emap = firmware_entropy_map(target_path, block_size=16384)
        region_counts = Counter(e["classification"] for e in emap)
        for classification, count in region_counts.most_common():
            print(f"  {classification}: {count} blocks")

    elif target_type == "esp" and os.path.isdir(target_path):
        print(f"\n[*] Analyzing ESP mount point: {target_path}")

        # ESP analysis
        print("\n--- ESP Partition Analysis ---")
        findings, efi_files = scan_esp_partition(target_path)
        print(f"  Total EFI binaries: {len(efi_files)}")
        for ef in efi_files:
            print(f"    {ef['path']}  ({ef['size']} bytes)  SHA-256={ef['sha256'][:16]}...")

        if findings:
            print("\n--- Bootkit Indicators ---")
            for f in findings:
                print(f"  [{f['severity']}] {f['message']}")
        else:
            print("\n  No bootkit indicators found on ESP.")

    else:
        print(f"\n[ERROR] Invalid target: {target_path} (type={target_type})")
        return

    # Known bootkit reference
    print("\n--- Known UEFI Bootkit Families ---")
    for name, info in KNOWN_BOOTKITS.items():
        print(f"  {name}: {info['description']}")
        print(f"    Persistence: {info['persistence']}")
        print(f"    MITRE: {info['mitre']}")

    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="UEFI bootkit persistence analysis agent for detecting firmware "
                    "implants, ESP modifications, Secure Boot bypasses, and UEFI "
                    "variable manipulation.",
        epilog="Authorized use only. Requires appropriate system access for firmware analysis.",
    )
    parser.add_argument(
        "target",
        help="Path to a firmware dump (.rom, .bin) or a mounted ESP directory",
    )
    parser.add_argument(
        "--type", "-t",
        choices=["firmware", "esp", "auto"],
        default="auto",
        help="Target type: 'firmware' for SPI flash dumps, 'esp' for mounted ESP "
             "partition, 'auto' to detect (default: auto)",
    )
    parser.add_argument(
        "--check-secureboot", "-s",
        action="store_true",
        help="Check Secure Boot status on the local system (Linux efivarfs)",
    )
    parser.add_argument(
        "--run-chipsec-audit", "-c",
        action="store_true",
        help="Run comprehensive chipsec firmware security audit modules",
    )
    parser.add_argument(
        "--baseline", "-b",
        type=str, default=None,
        help="Path to known-good firmware baseline for comparison",
    )
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results in JSON format instead of text",
    )
    parser.add_argument(
        "--list-bootkits",
        action="store_true",
        help="List all known UEFI bootkit families in the database and exit",
    )

    args = parser.parse_args()
    print(DISCLAIMER)

    if args.list_bootkits:
        print("Known UEFI Bootkit Families:")
        print("-" * 50)
        for name, info in KNOWN_BOOTKITS.items():
            print(f"\n  {name}")
            print(f"    {info['description']}")
            print(f"    Persistence: {info['persistence']}")
            print(f"    MITRE ATT&CK: {info['mitre']}")
            if info.get("cve"):
                print(f"    CVE: {info['cve']}")
        sys.exit(0)

    target_type = args.type
    if target_type == "auto":
        target_type = "esp" if os.path.isdir(args.target) else "firmware"

    analyze_uefi_bootkit(args.target, target_type)

    if args.check_secureboot:
        print("\n--- Local Secure Boot Status ---")
        sb_status = check_secure_boot_status()
        for k, v in sb_status.items():
            print(f"  {k}: {v}")

    if args.run_chipsec_audit:
        print("\n--- Chipsec Firmware Security Audit ---")
        audit_results = run_firmware_security_audit()
        for module, result in audit_results.items():
            status = "PASSED" if result.get("passed") else "FAILED" if result.get("failed") else "UNKNOWN"
            print(f"  [{status}] {module}: {result.get('description', '')}")
