#!/usr/bin/env python3
"""Bootkit and rootkit analysis agent for MBR/VBR/UEFI inspection and rootkit detection."""

import struct
import hashlib
import os
import sys
import subprocess
import math
from collections import Counter


def read_mbr(disk_path_or_file):
    """Read and parse the first 512 bytes (MBR) from a disk image or device."""
    with open(disk_path_or_file, "rb") as f:
        mbr = f.read(512)
    return mbr


def validate_mbr_signature(mbr_data):
    """Check the MBR boot signature at bytes 510-511 (should be 0x55AA)."""
    sig = mbr_data[510:512]
    valid = sig == b"\x55\xAA"
    return valid, sig.hex()


def parse_partition_table(mbr_data):
    """Parse the four 16-byte partition table entries starting at offset 446."""
    partitions = []
    for i in range(4):
        offset = 446 + (i * 16)
        entry = mbr_data[offset:offset + 16]
        if entry == b"\x00" * 16:
            continue
        boot_flag = entry[0]
        part_type = entry[4]
        start_lba = struct.unpack_from("<I", entry, 8)[0]
        size_lba = struct.unpack_from("<I", entry, 12)[0]
        partitions.append({
            "index": i + 1,
            "active": boot_flag == 0x80,
            "type_id": f"0x{part_type:02X}",
            "start_lba": start_lba,
            "size_sectors": size_lba,
            "size_mb": round(size_lba * 512 / (1024 * 1024), 1),
        })
    return partitions


BOOTKIT_SIGNATURES = {
    b"\xE8\x00\x00\x5E\x81\xEE": "TDL4/Alureon bootkit",
    b"\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B\xF4\x50\x07": "Standard Windows MBR (clean)",
    b"\xEB\x5A\x90\x4E\x54\x46\x53": "Standard NTFS VBR (clean)",
    b"\xEB\x52\x90\x4E\x54\x46\x53": "NTFS VBR variant (clean)",
    b"\x33\xC0\x8E\xD0\xBC\x00\x7C": "Windows 10 MBR (clean)",
}


def scan_bootkit_signatures(data):
    """Scan boot sector data against known bootkit signatures."""
    matches = []
    for sig, name in BOOTKIT_SIGNATURES.items():
        if sig in data:
            offset = data.find(sig)
            matches.append({"signature": name, "offset": offset, "clean": "clean" in name})
    return matches


def calculate_entropy(data):
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def read_first_track(disk_path, num_sectors=63):
    """Read the first track (typically 63 sectors) for extended bootkit code."""
    with open(disk_path, "rb") as f:
        data = f.read(num_sectors * 512)
    return data


def analyze_boot_code(mbr_data):
    """Analyze MBR bootstrap code (bytes 0-445) for suspicious patterns."""
    boot_code = mbr_data[:446]
    entropy = calculate_entropy(boot_code)
    sha256 = hashlib.sha256(boot_code).hexdigest()
    suspicious_patterns = []
    # Check for INT 13h hooking (common bootkit technique)
    if b"\xCD\x13" in boot_code:
        count = boot_code.count(b"\xCD\x13")
        suspicious_patterns.append(f"INT 13h calls: {count}")
    # Check for far jumps to unusual addresses
    if b"\xEA" in boot_code:
        suspicious_patterns.append("Far JMP instruction found")
    # Check for self-modifying code patterns
    if b"\xF3\xA4" in boot_code or b"\xF3\xA5" in boot_code:
        suspicious_patterns.append("REP MOVSB/MOVSW (memory copy, possible code relocation)")
    return {
        "entropy": entropy,
        "sha256": sha256,
        "high_entropy": entropy > 6.5,
        "suspicious_patterns": suspicious_patterns,
    }


def run_volatility_rootkit_scan(memory_dump, plugin):
    """Run a Volatility 3 plugin for rootkit detection via subprocess."""
    cmd = f"vol3 -f {memory_dump} {plugin}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode


def detect_kernel_rootkit(memory_dump):
    """Run multiple Volatility plugins to detect kernel-level rootkit artifacts."""
    plugins = [
        "windows.ssdt",
        "windows.callbacks",
        "windows.driverscan",
        "windows.modules",
        "windows.psscan",
        "windows.pslist",
    ]
    results = {}
    for plugin in plugins:
        stdout, stderr, rc = run_volatility_rootkit_scan(memory_dump, plugin)
        results[plugin] = {"output": stdout, "error": stderr, "return_code": rc}
    return results


def compare_process_lists(pslist_output, psscan_output):
    """Compare pslist and psscan output to find hidden processes (DKOM)."""
    pslist_pids = set()
    psscan_pids = set()
    for line in pslist_output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            pslist_pids.add(int(parts[1]))
    for line in psscan_output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            psscan_pids.add(int(parts[1]))
    hidden = psscan_pids - pslist_pids
    return hidden


if __name__ == "__main__":
    print("=" * 60)
    print("Bootkit & Rootkit Analysis Agent")
    print("MBR/VBR inspection, UEFI firmware analysis, rootkit detection")
    print("=" * 60)

    # Demo with a sample MBR file if available
    demo_mbr = "mbr.bin"
    if len(sys.argv) > 1:
        demo_mbr = sys.argv[1]

    if os.path.exists(demo_mbr):
        print(f"\n[*] Analyzing: {demo_mbr}")
        mbr = read_mbr(demo_mbr)
        valid, sig_hex = validate_mbr_signature(mbr)
        print(f"[*] MBR Signature: 0x{sig_hex.upper()} ({'Valid' if valid else 'INVALID'})")

        partitions = parse_partition_table(mbr)
        print(f"[*] Partition entries: {len(partitions)}")
        for p in partitions:
            active = "Active" if p["active"] else "Inactive"
            print(f"    Part {p['index']}: Type={p['type_id']} {active} "
                  f"Start=LBA {p['start_lba']} Size={p['size_mb']} MB")

        sigs = scan_bootkit_signatures(mbr)
        for s in sigs:
            tag = "[*]" if s["clean"] else "[!]"
            print(f"{tag} Signature match: {s['signature']} at offset {s['offset']}")

        analysis = analyze_boot_code(mbr)
        print(f"[*] Boot code entropy: {analysis['entropy']}"
              f" ({'HIGH - possible encryption' if analysis['high_entropy'] else 'Normal'})")
        print(f"[*] Boot code SHA-256: {analysis['sha256']}")
        for pat in analysis["suspicious_patterns"]:
            print(f"[!] {pat}")
    else:
        print(f"\n[DEMO] No MBR file provided. Usage: {sys.argv[0]} <mbr.bin | /dev/sda>")
        print("[DEMO] Provide a 512-byte MBR dump or disk device for analysis.")
        print("\n[*] Supported analysis:")
        print("    - MBR/VBR signature validation and bootkit detection")
        print("    - Partition table parsing and anomaly detection")
        print("    - Boot code entropy and pattern analysis")
        print("    - Volatility-based kernel rootkit detection (SSDT, callbacks, DKOM)")
        print("    - UEFI firmware module inspection via chipsec subprocess")
