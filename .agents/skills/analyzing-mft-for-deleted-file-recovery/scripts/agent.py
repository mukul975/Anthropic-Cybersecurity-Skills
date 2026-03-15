#!/usr/bin/env python3
"""MFT Deleted File Recovery Agent - Parses NTFS Master File Table for deleted file artifacts."""

import json
import struct
import os
import logging
import argparse
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MFT_ENTRY_SIZE = 1024
FILETIME_EPOCH = datetime(1601, 1, 1)


def filetime_to_dt(ft):
    """Convert FILETIME to datetime."""
    if ft == 0:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def parse_mft_entry(data, offset=0):
    """Parse a single MFT entry."""
    if len(data) < offset + 48:
        return None
    signature = data[offset:offset + 4]
    if signature != b"FILE":
        return None

    flags = struct.unpack_from("<H", data, offset + 22)[0]
    seq_number = struct.unpack_from("<H", data, offset + 18)[0]
    first_attr_offset = struct.unpack_from("<H", data, offset + 20)[0]

    entry = {
        "flags": flags,
        "in_use": bool(flags & 0x01),
        "is_directory": bool(flags & 0x02),
        "sequence_number": seq_number,
        "attributes": [],
    }

    attr_offset = offset + first_attr_offset
    while attr_offset + 4 <= len(data):
        attr_type = struct.unpack_from("<I", data, attr_offset)[0]
        if attr_type == 0xFFFFFFFF:
            break
        attr_length = struct.unpack_from("<I", data, attr_offset + 4)[0]
        if attr_length == 0 or attr_offset + attr_length > len(data):
            break

        if attr_type == 0x10:  # $STANDARD_INFORMATION
            if attr_offset + 24 + 32 <= len(data):
                si_offset = attr_offset + struct.unpack_from("<H", data, attr_offset + 20)[0]
                if si_offset + 32 <= len(data):
                    entry["created"] = str(filetime_to_dt(struct.unpack_from("<Q", data, si_offset)[0]))
                    entry["modified"] = str(filetime_to_dt(struct.unpack_from("<Q", data, si_offset + 8)[0]))
                    entry["mft_modified"] = str(filetime_to_dt(struct.unpack_from("<Q", data, si_offset + 16)[0]))
                    entry["accessed"] = str(filetime_to_dt(struct.unpack_from("<Q", data, si_offset + 24)[0]))

        elif attr_type == 0x30:  # $FILE_NAME
            non_res = struct.unpack_from("<B", data, attr_offset + 8)[0]
            if non_res == 0:
                fn_offset = attr_offset + struct.unpack_from("<H", data, attr_offset + 20)[0]
                if fn_offset + 66 <= len(data):
                    parent_ref = struct.unpack_from("<Q", data, fn_offset)[0] & 0xFFFFFFFFFFFF
                    name_len = data[fn_offset + 64] if fn_offset + 64 < len(data) else 0
                    name_ns = data[fn_offset + 65] if fn_offset + 65 < len(data) else 0
                    if fn_offset + 66 + name_len * 2 <= len(data):
                        filename = data[fn_offset + 66:fn_offset + 66 + name_len * 2].decode("utf-16-le", errors="ignore")
                        entry["filename"] = filename
                        entry["parent_ref"] = parent_ref
                        entry["name_type"] = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}.get(name_ns, "Unknown")

        attr_offset += attr_length

    return entry


def parse_mft_file(mft_path):
    """Parse an extracted MFT file."""
    entries = []
    with open(mft_path, "rb") as f:
        data = f.read()

    total_entries = len(data) // MFT_ENTRY_SIZE
    for i in range(total_entries):
        offset = i * MFT_ENTRY_SIZE
        entry = parse_mft_entry(data, offset)
        if entry:
            entry["record_number"] = i
            entries.append(entry)

    logger.info("Parsed %d MFT entries (%d total records)", len(entries), total_entries)
    return entries


def find_deleted_files(entries):
    """Find deleted file entries in MFT."""
    deleted = [e for e in entries if not e["in_use"] and e.get("filename")]
    logger.info("Found %d deleted file entries", len(deleted))
    return deleted


def analyze_deleted_files(deleted):
    """Analyze deleted files for forensic significance."""
    findings = []
    suspicious_extensions = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr"}
    for entry in deleted:
        fname = entry.get("filename", "").lower()
        ext = os.path.splitext(fname)[1]
        if ext in suspicious_extensions:
            findings.append({
                "record": entry["record_number"],
                "filename": entry.get("filename"),
                "type": "Deleted executable/script",
                "severity": "high",
                "modified": entry.get("modified"),
            })
    return findings


def generate_report(entries, deleted, findings):
    """Generate MFT analysis report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_entries": len(entries),
        "active_entries": len([e for e in entries if e["in_use"]]),
        "deleted_entries": len(deleted),
        "suspicious_deleted": len(findings),
        "findings": findings[:100],
        "deleted_files": [{"record": d["record_number"], "filename": d.get("filename"), "modified": d.get("modified")} for d in deleted[:200]],
    }
    print(f"MFT REPORT: {len(entries)} entries, {len(deleted)} deleted, {len(findings)} suspicious")
    return report


def main():
    parser = argparse.ArgumentParser(description="MFT Deleted File Recovery Agent")
    parser.add_argument("--mft-file", required=True, help="Path to extracted $MFT file")
    parser.add_argument("--output", default="mft_report.json")
    args = parser.parse_args()

    entries = parse_mft_file(args.mft_file)
    deleted = find_deleted_files(entries)
    findings = analyze_deleted_files(deleted)
    report = generate_report(entries, deleted, findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
