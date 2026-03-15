#!/usr/bin/env python3
"""
Forensic Evidence Processor

Parses and correlates forensic artifacts from KAPE/EZ tool output
to generate consolidated timeline and IOC reports.
"""

import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict


def parse_prefetch_csv(csv_path: str) -> list:
    """Parse PECmd output for program execution history."""
    entries = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append({
                "artifact": "prefetch",
                "timestamp": row.get("LastRun", ""),
                "executable": row.get("ExecutableName", ""),
                "run_count": row.get("RunCount", ""),
                "path": row.get("SourceFilename", ""),
                "hash": row.get("Hash", ""),
                "volume": row.get("Volume0Name", ""),
            })
    return entries


def parse_shimcache_csv(csv_path: str) -> list:
    """Parse AppCompatCacheParser output."""
    entries = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append({
                "artifact": "shimcache",
                "timestamp": row.get("LastModifiedTimeUTC", ""),
                "path": row.get("Path", ""),
                "executed": row.get("Executed", ""),
            })
    return entries


def parse_amcache_csv(csv_path: str) -> list:
    """Parse AmcacheParser output for installed programs."""
    entries = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append({
                "artifact": "amcache",
                "timestamp": row.get("FileKeyLastWriteTimestamp", ""),
                "path": row.get("FullPath", row.get("Name", "")),
                "sha1": row.get("SHA1", ""),
                "publisher": row.get("Publisher", ""),
                "product": row.get("ProductName", ""),
            })
    return entries


def parse_mft_csv(csv_path: str) -> list:
    """Parse MFTECmd output for file system timeline."""
    entries = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append({
                "artifact": "mft",
                "timestamp_created": row.get("Created0x10", ""),
                "timestamp_modified": row.get("LastModified0x10", ""),
                "path": row.get("ParentPath", "") + "\\" + row.get("FileName", ""),
                "size": row.get("FileSize", ""),
                "in_use": row.get("InUse", ""),
                "is_directory": row.get("IsDirectory", ""),
            })
    return entries


def build_timeline(all_entries: list) -> list:
    """Build consolidated timeline from all artifact sources."""
    timeline = []

    for entry in all_entries:
        ts = ""
        for key in ["timestamp", "timestamp_created", "timestamp_modified"]:
            if entry.get(key):
                ts = entry[key]
                break

        if ts:
            timeline.append({
                "timestamp": ts,
                "artifact": entry.get("artifact", "unknown"),
                "description": entry.get("path", entry.get("executable", "")),
                "details": {k: v for k, v in entry.items()
                            if k not in ("timestamp", "artifact")},
            })

    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def extract_iocs(all_entries: list) -> dict:
    """Extract potential IOCs from forensic artifacts."""
    iocs = {
        "file_hashes": set(),
        "suspicious_paths": [],
        "executables": set(),
    }

    suspicious_dirs = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\users\\public\\", "\\programdata\\",
        "\\recycle", "\\windows\\debug\\",
    ]

    for entry in all_entries:
        for hash_key in ["hash", "sha1", "md5"]:
            h = entry.get(hash_key, "")
            if h and len(h) >= 32:
                iocs["file_hashes"].add(h)

        path = entry.get("path", "").lower()
        if any(d in path for d in suspicious_dirs):
            if path.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".js")):
                iocs["suspicious_paths"].append({
                    "path": entry.get("path", ""),
                    "artifact": entry.get("artifact", ""),
                    "timestamp": entry.get("timestamp", ""),
                })

        exe = entry.get("executable", "")
        if exe:
            iocs["executables"].add(exe)

    iocs["file_hashes"] = sorted(iocs["file_hashes"])
    iocs["executables"] = sorted(iocs["executables"])
    return iocs


def generate_report(timeline: list, iocs: dict, output_path: str) -> None:
    """Generate forensic analysis report."""
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "timeline_entries": len(timeline),
        "iocs": {
            "file_hashes": iocs["file_hashes"][:100],
            "suspicious_files": iocs["suspicious_paths"][:50],
            "unique_executables": len(iocs["executables"]),
        },
        "timeline_sample": timeline[:100],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process.py <kape_output_directory>")
        print()
        print("Parses KAPE/EZ tool CSV output and generates timeline + IOC report.")
        sys.exit(1)

    kape_dir = sys.argv[1]
    if not os.path.isdir(kape_dir):
        print(f"Error: Directory not found: {kape_dir}")
        sys.exit(1)

    all_entries = []

    for root, dirs, files in os.walk(kape_dir):
        for f in files:
            if not f.endswith(".csv"):
                continue
            path = os.path.join(root, f)
            fl = f.lower()
            try:
                if "prefetch" in fl or "pecmd" in fl:
                    all_entries.extend(parse_prefetch_csv(path))
                elif "shimcache" in fl or "appcompat" in fl:
                    all_entries.extend(parse_shimcache_csv(path))
                elif "amcache" in fl:
                    all_entries.extend(parse_amcache_csv(path))
                elif "mft" in fl:
                    all_entries.extend(parse_mft_csv(path))
            except Exception as e:
                print(f"Warning: Could not parse {path}: {e}")

    print(f"Parsed {len(all_entries)} artifact entries")

    timeline = build_timeline(all_entries)
    iocs = extract_iocs(all_entries)

    report_path = os.path.join(kape_dir, "forensic_analysis.json")
    generate_report(timeline, iocs, report_path)
    print(f"Forensic report: {report_path}")

    print(f"\n--- Forensic Summary ---")
    print(f"Timeline entries: {len(timeline)}")
    print(f"Unique file hashes: {len(iocs['file_hashes'])}")
    print(f"Suspicious file paths: {len(iocs['suspicious_paths'])}")
    print(f"Unique executables: {len(iocs['executables'])}")
