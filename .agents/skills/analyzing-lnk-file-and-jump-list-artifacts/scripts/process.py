#!/usr/bin/env python3
"""
LNK File and Jump List Forensic Analyzer

Parses LNK file headers and extracts forensic metadata including
target paths, timestamps, volume information, and machine identifiers.
"""

import struct
import os
import sys
import json
import csv
from datetime import datetime, timedelta
from pathlib import Path


FILETIME_EPOCH = datetime(1601, 1, 1)


def filetime_to_datetime(ft_bytes: bytes):
    """Convert Windows FILETIME to datetime."""
    ft = struct.unpack("<Q", ft_bytes)[0]
    if ft == 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def parse_lnk_file(filepath: str) -> dict:
    """Parse a Windows LNK file and extract forensic metadata."""
    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 76:
        return {"error": "File too small for LNK header"}

    header_size = struct.unpack("<I", data[0:4])[0]
    if header_size != 0x4C:
        return {"error": "Invalid LNK header signature"}

    link_flags = struct.unpack("<I", data[0x14:0x18])[0]
    file_attrs = struct.unpack("<I", data[0x18:0x1C])[0]

    result = {
        "file": filepath,
        "file_size_lnk": len(data),
        "creation_time": str(filetime_to_datetime(data[0x1C:0x24])),
        "access_time": str(filetime_to_datetime(data[0x24:0x2C])),
        "write_time": str(filetime_to_datetime(data[0x2C:0x34])),
        "target_file_size": struct.unpack("<I", data[0x34:0x38])[0],
        "flags": {
            "has_target_id_list": bool(link_flags & 0x01),
            "has_link_info": bool(link_flags & 0x02),
            "has_name": bool(link_flags & 0x04),
            "has_relative_path": bool(link_flags & 0x08),
            "has_working_dir": bool(link_flags & 0x10),
            "has_arguments": bool(link_flags & 0x20),
            "has_icon_location": bool(link_flags & 0x40),
        },
        "attributes": {
            "readonly": bool(file_attrs & 0x01),
            "hidden": bool(file_attrs & 0x02),
            "system": bool(file_attrs & 0x04),
            "directory": bool(file_attrs & 0x10),
            "archive": bool(file_attrs & 0x20),
        }
    }
    return result


def scan_directory(lnk_dir: str, output_dir: str) -> str:
    """Scan a directory for LNK files and generate analysis report."""
    os.makedirs(output_dir, exist_ok=True)
    results = []

    for root, dirs, files in os.walk(lnk_dir):
        for fname in files:
            if fname.lower().endswith(".lnk"):
                filepath = os.path.join(root, fname)
                parsed = parse_lnk_file(filepath)
                results.append(parsed)

    report_path = os.path.join(output_dir, "lnk_analysis_report.json")
    with open(report_path, "w") as f:
        json.dump({
            "analysis_timestamp": datetime.now().isoformat(),
            "source_directory": lnk_dir,
            "total_lnk_files": len(results),
            "files": results
        }, f, indent=2, default=str)

    print(f"[*] Analyzed {len(results)} LNK files")
    print(f"[*] Report: {report_path}")
    return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <lnk_directory> <output_dir>")
        sys.exit(1)
    scan_directory(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
