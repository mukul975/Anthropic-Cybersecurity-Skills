#!/usr/bin/env python3
"""Firmware extraction and analysis agent using binwalk for signature scanning,
entropy analysis, filesystem extraction, and string-based credential discovery."""

import argparse
import struct
import hashlib
import math
import os
import subprocess
import re
from collections import Counter
from pathlib import Path

DISCLAIMER = """
==========================================================================
  AUTHORIZED USE ONLY -- This tool is intended for authorized security
  testing, firmware research, and educational purposes. Ensure you have
  explicit written permission before analyzing any firmware image you do
  not own. Unauthorized access to or reverse engineering of proprietary
  firmware may violate applicable laws and vendor agreements.
==========================================================================
"""


# ---------------------------------------------------------------------------
# Entropy Analysis
# ---------------------------------------------------------------------------

def calculate_entropy(data):
    """Calculate Shannon entropy of a byte sequence (0.0 = uniform, 8.0 = max random)."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def entropy_map(file_path, block_size=4096):
    """Generate a block-by-block entropy map of a firmware image."""
    results = []
    with open(file_path, "rb") as f:
        offset = 0
        while True:
            block = f.read(block_size)
            if not block:
                break
            ent = calculate_entropy(block)
            results.append({
                "offset": offset,
                "offset_hex": f"0x{offset:08X}",
                "entropy": ent,
                "classification": classify_entropy(ent),
            })
            offset += len(block)
    return results


def classify_entropy(value):
    """Classify an entropy value into a human-readable category."""
    if value < 1.0:
        return "empty/padding"
    elif value < 5.0:
        return "plaintext/code"
    elif value < 7.0:
        return "compressed"
    elif value < 7.9:
        return "highly-compressed"
    else:
        return "encrypted/random"


def detect_entropy_regions(entropy_data, threshold_high=7.0, threshold_low=1.0):
    """Identify contiguous regions of high or low entropy in a firmware image."""
    regions = []
    current_region = None
    for entry in entropy_data:
        classification = entry["classification"]
        if current_region and current_region["classification"] == classification:
            current_region["end_offset"] = entry["offset"]
            current_region["block_count"] += 1
        else:
            if current_region:
                regions.append(current_region)
            current_region = {
                "start_offset": entry["offset"],
                "start_hex": entry["offset_hex"],
                "end_offset": entry["offset"],
                "classification": classification,
                "block_count": 1,
            }
    if current_region:
        regions.append(current_region)
    return regions


# ---------------------------------------------------------------------------
# Firmware Header Parsing
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = {
    b"\x27\x05\x19\x56": "U-Boot image header (uImage)",
    b"\x68\x73\x71\x73": "SquashFS filesystem (little-endian)",
    b"\x73\x71\x73\x68": "SquashFS filesystem (big-endian)",
    b"\x45\x3D\xCD\x28": "CramFS filesystem",
    b"\x85\x19\x01\x20": "JFFS2 filesystem (little-endian)",
    b"\x19\x85\x20\x01": "JFFS2 filesystem (big-endian)",
    b"\x1F\x8B\x08": "gzip compressed data",
    b"\x5D\x00\x00": "LZMA compressed data",
    b"\xFD\x37\x7A\x58\x5A\x00": "XZ compressed data",
    b"\x30\x37\x30\x37\x30\x31": "CPIO archive",
    b"\x55\xAA": "x86 boot sector",
    b"\xD0\x0D\xFE\xED": "Device Tree Blob (DTB)",
    b"\x4D\x5A": "PE/COFF executable (EFI binary)",
    b"\x7F\x45\x4C\x46": "ELF executable",
    b"\x89\x50\x4E\x47": "PNG image",
    b"\xFF\xD8\xFF": "JPEG image",
}


def scan_signatures(file_path, chunk_size=65536):
    """Scan a firmware image for known magic byte signatures."""
    matches = []
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        offset = 0
        while offset < file_size:
            f.seek(offset)
            data = f.read(chunk_size)
            if not data:
                break
            for magic, description in MAGIC_SIGNATURES.items():
                pos = 0
                while True:
                    idx = data.find(magic, pos)
                    if idx == -1:
                        break
                    absolute_offset = offset + idx
                    matches.append({
                        "offset": absolute_offset,
                        "offset_hex": f"0x{absolute_offset:08X}",
                        "magic_hex": magic.hex().upper(),
                        "description": description,
                    })
                    pos = idx + 1
            offset += chunk_size - max(len(m) for m in MAGIC_SIGNATURES) + 1
    matches.sort(key=lambda x: x["offset"])
    return matches


def parse_uboot_header(file_path, offset=0):
    """Parse a U-Boot image header at the given offset."""
    with open(file_path, "rb") as f:
        f.seek(offset)
        header = f.read(64)
    if len(header) < 64:
        return None
    magic = struct.unpack(">I", header[0:4])[0]
    if magic != 0x27051956:
        return None
    header_crc = struct.unpack(">I", header[4:8])[0]
    timestamp = struct.unpack(">I", header[8:12])[0]
    data_size = struct.unpack(">I", header[12:16])[0]
    load_addr = struct.unpack(">I", header[16:20])[0]
    entry_point = struct.unpack(">I", header[20:24])[0]
    data_crc = struct.unpack(">I", header[24:28])[0]
    os_type = header[28]
    arch = header[29]
    image_type = header[30]
    comp_type = header[31]
    name = header[32:64].split(b"\x00")[0].decode("ascii", errors="replace")

    OS_TYPES = {0: "Invalid", 1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD",
                4: "4_4BSD", 5: "Linux", 6: "SVR4", 7: "Esix", 8: "Solaris",
                9: "Irix", 10: "SCO", 11: "Dell", 12: "NCR", 14: "QNX",
                15: "U-Boot", 16: "RTEMS"}
    ARCH_TYPES = {0: "Invalid", 1: "Alpha", 2: "ARM", 3: "x86", 4: "IA64",
                  5: "MIPS", 6: "MIPS64", 7: "PowerPC", 8: "S390",
                  9: "SuperH", 10: "SPARC", 11: "SPARC64", 12: "M68K",
                  15: "AArch64", 22: "RISC-V"}
    COMP_TYPES = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo",
                  5: "lz4", 6: "zstd"}

    return {
        "magic": f"0x{magic:08X}",
        "header_crc": f"0x{header_crc:08X}",
        "data_size": data_size,
        "load_address": f"0x{load_addr:08X}",
        "entry_point": f"0x{entry_point:08X}",
        "data_crc": f"0x{data_crc:08X}",
        "os": OS_TYPES.get(os_type, f"Unknown({os_type})"),
        "architecture": ARCH_TYPES.get(arch, f"Unknown({arch})"),
        "compression": COMP_TYPES.get(comp_type, f"Unknown({comp_type})"),
        "name": name,
    }


# ---------------------------------------------------------------------------
# String Analysis
# ---------------------------------------------------------------------------

SENSITIVE_PATTERNS = [
    (re.compile(rb"password\s*[:=]\s*\S+", re.IGNORECASE), "Hardcoded password"),
    (re.compile(rb"passwd\s*[:=]\s*\S+", re.IGNORECASE), "Hardcoded password"),
    (re.compile(rb"api[_-]?key\s*[:=]\s*\S+", re.IGNORECASE), "API key"),
    (re.compile(rb"secret\s*[:=]\s*\S+", re.IGNORECASE), "Secret value"),
    (re.compile(rb"token\s*[:=]\s*\S+", re.IGNORECASE), "Authentication token"),
    (re.compile(rb"-----BEGIN\s+(RSA |DSA |EC )?PRIVATE KEY-----"), "Private key"),
    (re.compile(rb"-----BEGIN CERTIFICATE-----"), "X.509 certificate"),
    (re.compile(rb"https?://\S+"), "URL/endpoint"),
    (re.compile(rb"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "IP address"),
    (re.compile(rb"root:\$[156]\$"), "Root password hash"),
    (re.compile(rb"telnetd|dropbear|sshd|httpd|uHTTPd"), "Network service"),
]


def scan_strings(file_path, min_length=8):
    """Extract printable ASCII strings and scan for sensitive patterns."""
    findings = []
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        data = f.read()
    # Extract ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
    strings_found = ascii_pattern.findall(data)
    # Scan each string against sensitive patterns
    for s in strings_found:
        for pattern, description in SENSITIVE_PATTERNS:
            if pattern.search(s):
                offset = data.find(s)
                findings.append({
                    "offset": f"0x{offset:08X}",
                    "type": description,
                    "value": s[:120].decode("ascii", errors="replace"),
                })
                break
    return findings


# ---------------------------------------------------------------------------
# Binwalk Subprocess Interface
# ---------------------------------------------------------------------------

def run_binwalk_scan(firmware_path):
    """Run binwalk signature scan via subprocess and return parsed output."""
    try:
        result = subprocess.run(
            ["binwalk", firmware_path],
            capture_output=True, text=True, timeout=120,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "binwalk not found in PATH", "rc": -1}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "binwalk scan timed out", "rc": -2}


def run_binwalk_extract(firmware_path, output_dir=None, recursive=False):
    """Run binwalk extraction via subprocess."""
    cmd = ["binwalk", "-e"]
    if recursive:
        cmd.append("-M")
    if output_dir:
        cmd.extend(["-C", output_dir])
    cmd.append(firmware_path)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return {"stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "binwalk not found in PATH", "rc": -1}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "binwalk extraction timed out", "rc": -2}


def run_binwalk_entropy(firmware_path):
    """Run binwalk entropy analysis via subprocess."""
    try:
        result = subprocess.run(
            ["binwalk", "-E", firmware_path],
            capture_output=True, text=True, timeout=120,
        )
        return {"stdout": result.stdout, "stderr": result.stderr, "rc": result.returncode}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "binwalk not found in PATH", "rc": -1}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "binwalk entropy analysis timed out", "rc": -2}


# ---------------------------------------------------------------------------
# Firmware Metadata
# ---------------------------------------------------------------------------

def get_firmware_metadata(file_path):
    """Compute basic metadata for a firmware image file."""
    file_size = os.path.getsize(file_path)
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "file": os.path.basename(file_path),
        "path": str(Path(file_path).resolve()),
        "size_bytes": file_size,
        "size_human": f"{file_size / (1024*1024):.2f} MB" if file_size > 1048576
                      else f"{file_size / 1024:.2f} KB",
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def analyze_firmware(firmware_path):
    """Perform a complete firmware analysis pipeline."""
    print("=" * 65)
    print("  Firmware Extraction & Analysis Agent (binwalk)")
    print("=" * 65)

    if not os.path.isfile(firmware_path):
        print(f"[ERROR] File not found: {firmware_path}")
        return

    # Metadata
    meta = get_firmware_metadata(firmware_path)
    print(f"\n[*] File:    {meta['file']}")
    print(f"[*] Size:    {meta['size_human']} ({meta['size_bytes']} bytes)")
    print(f"[*] SHA-256: {meta['sha256']}")
    print(f"[*] MD5:     {meta['md5']}")

    # Signature scan
    print("\n--- Signature Scan ---")
    sigs = scan_signatures(firmware_path)
    if sigs:
        for s in sigs:
            print(f"  {s['offset_hex']}  {s['description']}  (magic: {s['magic_hex']})")
    else:
        print("  No known signatures detected.")

    # U-Boot header
    for s in sigs:
        if "U-Boot" in s["description"]:
            print(f"\n--- U-Boot Header at {s['offset_hex']} ---")
            hdr = parse_uboot_header(firmware_path, s["offset"])
            if hdr:
                for k, v in hdr.items():
                    print(f"  {k}: {v}")

    # Entropy analysis
    print("\n--- Entropy Analysis ---")
    emap = entropy_map(firmware_path, block_size=8192)
    regions = detect_entropy_regions(emap)
    for r in regions:
        size_bytes = (r["block_count"]) * 8192
        print(f"  {r['start_hex']} - 0x{r['end_offset']:08X}  "
              f"({size_bytes:>8} bytes)  [{r['classification']}]")

    # String analysis for sensitive data
    print("\n--- Sensitive String Analysis ---")
    findings = scan_strings(firmware_path, min_length=8)
    if findings:
        seen = set()
        for f in findings[:30]:
            key = (f["type"], f["value"][:60])
            if key not in seen:
                seen.add(key)
                print(f"  [{f['type']}] @ {f['offset']}: {f['value'][:80]}")
    else:
        print("  No sensitive strings detected.")

    # Binwalk subprocess scan
    print("\n--- Binwalk Scan Output ---")
    bw = run_binwalk_scan(firmware_path)
    if bw["rc"] == 0:
        print(bw["stdout"][:2000])
    elif bw["rc"] == -1:
        print("  [WARN] binwalk binary not found; install with: pip install binwalk3")
    else:
        print(f"  [ERROR] binwalk returned code {bw['rc']}: {bw['stderr'][:200]}")

    print("\n[*] Analysis complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Firmware extraction and analysis agent using binwalk for "
                    "signature scanning, entropy analysis, filesystem extraction, "
                    "and string-based credential discovery.",
        epilog="Authorized use only. Ensure you have permission to analyze the target firmware.",
    )
    parser.add_argument(
        "firmware",
        help="Path to a firmware image file (.bin, .img, .rom)",
    )
    parser.add_argument(
        "--block-size", "-b",
        type=int, default=8192,
        help="Block size in bytes for entropy analysis (default: 8192)",
    )
    parser.add_argument(
        "--min-string-length", "-s",
        type=int, default=8,
        help="Minimum string length for sensitive string scanning (default: 8)",
    )
    parser.add_argument(
        "--extract", "-e",
        action="store_true",
        help="Run binwalk extraction after analysis",
    )
    parser.add_argument(
        "--recursive", "-M",
        action="store_true",
        help="Enable recursive (matryoshka) extraction",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str, default=None,
        help="Output directory for extraction results",
    )
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results in JSON format instead of text",
    )

    args = parser.parse_args()
    print(DISCLAIMER)
    analyze_firmware(args.firmware)

    if args.extract:
        print("\n--- Running Binwalk Extraction ---")
        result = run_binwalk_extract(args.firmware, args.output_dir, args.recursive)
        if result["rc"] == 0:
            print(result["stdout"][:2000])
        else:
            print(f"  [ERROR] Extraction failed: {result.get('stderr', '')[:200]}")
