#!/usr/bin/env python3
"""Agent for analyzing NTFS slack space and file system artifacts."""

import os
import sys
import json
import struct
import argparse
import subprocess
from datetime import datetime, timedelta
from pathlib import Path


def parse_mft_with_analyzeMFT(mft_path, output_csv):
    """Parse MFT using analyzeMFT and return deleted/timestomped files."""
    cmd = ["analyzeMFT.py", "-f", mft_path, "-o", output_csv, "-c"]
    subprocess.run(cmd, check=True)
    return output_csv


def extract_slack_space(image_path, offset, output_path):
    """Extract slack space from a disk image using blkls from The Sleuth Kit."""
    cmd = ["blkls", "-s", "-o", str(offset), image_path]
    with open(output_path, "wb") as out:
        subprocess.run(cmd, stdout=out, check=True)
    return output_path


def search_slack_keywords(slack_path, keywords=None):
    """Search extracted slack space for forensic keywords."""
    if keywords is None:
        keywords = ["password", "secret", "confidential", "credit card", "ssn"]
    hits = []
    with open(slack_path, "rb") as f:
        data = f.read()
    for kw in keywords:
        kw_bytes = kw.encode("utf-8")
        start = 0
        while True:
            idx = data.find(kw_bytes, start)
            if idx == -1:
                break
            context = data[max(0, idx - 20):idx + len(kw_bytes) + 20]
            hits.append({
                "keyword": kw,
                "offset": idx,
                "context": context.decode("utf-8", errors="replace"),
            })
            start = idx + 1
    return hits


def parse_usn_journal(usn_path):
    """Parse NTFS USN Change Journal ($UsnJrnl:$J) records."""
    REASON_FLAGS = {
        0x01: "DATA_OVERWRITE", 0x02: "DATA_EXTEND", 0x04: "DATA_TRUNCATION",
        0x100: "FILE_CREATE", 0x200: "FILE_DELETE", 0x400: "EA_CHANGE",
        0x800: "SECURITY_CHANGE", 0x1000: "RENAME_OLD_NAME",
        0x2000: "RENAME_NEW_NAME", 0x80000000: "CLOSE",
    }
    records = []
    with open(usn_path, "rb") as f:
        data = f.read()
    offset = 0
    while offset < len(data) - 8:
        rec_len = struct.unpack_from("<I", data, offset)[0]
        if rec_len < 56 or rec_len > 65536 or offset + rec_len > len(data):
            offset += 8
            continue
        major = struct.unpack_from("<H", data, offset + 4)[0]
        if major != 2:
            offset += max(rec_len, 8)
            continue
        mft_ref = struct.unpack_from("<Q", data, offset + 8)[0] & 0xFFFFFFFFFFFF
        timestamp = struct.unpack_from("<Q", data, offset + 32)[0]
        reason = struct.unpack_from("<I", data, offset + 40)[0]
        fn_len = struct.unpack_from("<H", data, offset + 56)[0]
        fn_off = struct.unpack_from("<H", data, offset + 58)[0]
        name = data[offset + fn_off:offset + fn_off + fn_len].decode("utf-16-le", errors="ignore")
        ts = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)
        reasons = [desc for flag, desc in REASON_FLAGS.items() if reason & flag]
        records.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "filename": name,
            "mft_entry": mft_ref,
            "reasons": "|".join(reasons),
        })
        offset += rec_len
    return records


def find_ads_in_image(image_path, offset):
    """List Alternate Data Streams using fls from The Sleuth Kit."""
    cmd = ["fls", "-r", "-o", str(offset), image_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    ads_entries = [line for line in result.stdout.splitlines() if ":" in line]
    return ads_entries


def detect_timestomping(mft_csv_path):
    """Detect timestomping by comparing $SI and $FN timestamps in MFT CSV output."""
    import csv
    suspicious = []
    with open(mft_csv_path, "r", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            si_mod = row.get("SI_Modified", "")
            fn_mod = row.get("FN_Modified", "")
            if si_mod and fn_mod and si_mod != fn_mod:
                suspicious.append({
                    "filename": row.get("Filename", ""),
                    "si_modified": si_mod,
                    "fn_modified": fn_mod,
                })
    return suspicious


def generate_report(results_data, case_id):
    """Generate a structured forensic report."""
    report = {
        "report_type": "File System Artifact Analysis",
        "case_id": case_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": results_data,
    }
    return json.dumps(report, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="NTFS File System Artifact Analysis Agent")
    parser.add_argument("--image", required=True, help="Path to forensic disk image")
    parser.add_argument("--offset", type=int, default=2048, help="Partition offset in sectors")
    parser.add_argument("--case-id", default="CASE-001", help="Case identifier")
    parser.add_argument("--output-dir", default="./analysis", help="Output directory")
    parser.add_argument("--action", choices=[
        "extract_slack", "parse_usn", "find_ads", "search_slack",
        "parse_mft", "detect_timestomping", "full_analysis"
    ], default="full_analysis")
    parser.add_argument("--mft-path", help="Path to extracted $MFT file")
    parser.add_argument("--usn-path", help="Path to extracted $UsnJrnl:$J file")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    findings = {}

    if args.action in ("extract_slack", "full_analysis"):
        slack_path = os.path.join(args.output_dir, "slack_space.raw")
        extract_slack_space(args.image, args.offset, slack_path)
        hits = search_slack_keywords(slack_path)
        findings["slack_keywords"] = hits
        print(f"[+] Slack space: {len(hits)} keyword hits found")

    if args.action in ("parse_usn", "full_analysis") and args.usn_path:
        records = parse_usn_journal(args.usn_path)
        deletions = [r for r in records if "FILE_DELETE" in r["reasons"]]
        findings["usn_journal"] = {
            "total_records": len(records),
            "deletions": len(deletions),
            "recent_deletions": deletions[-20:],
        }
        print(f"[+] USN Journal: {len(records)} records, {len(deletions)} deletions")

    if args.action in ("find_ads", "full_analysis"):
        ads = find_ads_in_image(args.image, args.offset)
        findings["alternate_data_streams"] = ads
        print(f"[+] Alternate Data Streams: {len(ads)} found")

    print(generate_report(findings, args.case_id))


if __name__ == "__main__":
    main()
