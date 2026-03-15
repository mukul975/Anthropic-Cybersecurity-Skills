#!/usr/bin/env python3
"""Shellbag Forensic Analyzer - Parses SBECmd CSV output for investigation."""
import csv, json, os, sys
from datetime import datetime
from collections import defaultdict

def analyze_shellbags(csv_path: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    entries = []
    usb_access = []
    network_access = []
    with open(csv_path, "r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            entries.append(row)
            path = row.get("AbsolutePath", "")
            if any(d in path for d in ["E:\\", "F:\\", "G:\\", "H:\\"]):
                usb_access.append(row)
            if path.startswith("\\\\"):
                network_access.append(row)
    report = {
        "analysis_timestamp": datetime.now().isoformat(),
        "total_entries": len(entries),
        "usb_access_entries": len(usb_access),
        "network_access_entries": len(network_access),
        "usb_paths": [r.get("AbsolutePath", "") for r in usb_access],
        "network_paths": [r.get("AbsolutePath", "") for r in network_access],
    }
    report_path = os.path.join(output_dir, "shellbag_analysis.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Total entries: {len(entries)}, USB: {len(usb_access)}, Network: {len(network_access)}")
    return report_path

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python process.py <shellbag_csv> <output_dir>")
        sys.exit(1)
    analyze_shellbags(sys.argv[1], sys.argv[2])
