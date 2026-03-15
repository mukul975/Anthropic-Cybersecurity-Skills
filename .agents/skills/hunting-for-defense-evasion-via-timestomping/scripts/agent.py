#!/usr/bin/env python3
"""Timestomping detection agent for NTFS MFT analysis.

Detects MITRE T1070.006 (Timestomping) by comparing $STANDARD_INFORMATION
and $FILE_NAME timestamps in NTFS Master File Table entries. Identifies
anomalous nanosecond patterns and temporal inconsistencies.
"""

import argparse
import csv
import json
import os
import re
import sys
import datetime


TIMESTOMP_INDICATORS = {
    "zero_nanoseconds": "Nanosecond field is exactly 0000000 (common in timestomping tools)",
    "si_before_fn": "$STANDARD_INFORMATION created before $FILE_NAME created",
    "future_timestamp": "Timestamp is in the future",
    "pre_os_timestamp": "Timestamp predates the operating system install",
    "round_seconds": "Timestamp has perfectly round seconds (no fractional component)",
}


def parse_mft_csv(csv_path):
    """Parse analyzeMFT CSV output for timestamp analysis."""
    entries = []
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = {
                    "record_number": row.get("Record Number", ""),
                    "filename": row.get("Filename", row.get("Good", "")),
                    "si_created": row.get("SI Created", row.get("STD_INFO Creation date", "")),
                    "si_modified": row.get("SI Modified", row.get("STD_INFO Modification date", "")),
                    "si_accessed": row.get("SI Accessed", row.get("STD_INFO Access date", "")),
                    "si_entry_modified": row.get("SI Entry Modified", row.get("STD_INFO Entry date", "")),
                    "fn_created": row.get("FN Created", row.get("FN Creation date", "")),
                    "fn_modified": row.get("FN Modified", row.get("FN Modification date", "")),
                    "fn_accessed": row.get("FN Accessed", row.get("FN Access date", "")),
                    "fn_entry_modified": row.get("FN Entry Modified", row.get("FN Entry date", "")),
                    "in_use": row.get("Active", row.get("In Use", "")).lower() in ("true", "1", "yes"),
                }
                if entry["filename"]:
                    entries.append(entry)
    except FileNotFoundError:
        return {"error": f"File not found: {csv_path}"}
    return entries


def parse_timestamp(ts_str):
    """Parse various timestamp formats to datetime."""
    if not ts_str or ts_str in ("", "NoFNDate", "N/A"):
        return None
    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def detect_timestomping(entries, os_install_date=None):
    """Analyze MFT entries for timestomping indicators."""
    if os_install_date is None:
        os_install_date = datetime.datetime(2020, 1, 1)
    now = datetime.datetime.now()
    findings = []

    for entry in entries:
        if isinstance(entry, dict) and "error" in entry:
            continue
        reasons = []
        si_created = parse_timestamp(entry.get("si_created", ""))
        fn_created = parse_timestamp(entry.get("fn_created", ""))

        # Check zero nanoseconds
        si_str = entry.get("si_created", "")
        if ".0000000" in si_str or (si_str and re.search(r"\.\d{6}0$", si_str)):
            reasons.append("zero_nanoseconds")

        # Check SI before FN (most reliable indicator)
        if si_created and fn_created:
            if si_created < fn_created - datetime.timedelta(seconds=2):
                reasons.append("si_before_fn")

        # Check future timestamps
        if si_created and si_created > now + datetime.timedelta(days=1):
            reasons.append("future_timestamp")

        # Check pre-OS timestamps
        if si_created and si_created < os_install_date:
            if fn_created and fn_created >= os_install_date:
                reasons.append("pre_os_timestamp")

        # Check perfectly round timestamps
        if si_created and si_created.microsecond == 0:
            si_mod = parse_timestamp(entry.get("si_modified", ""))
            if si_mod and si_mod.microsecond == 0:
                reasons.append("round_seconds")

        if reasons:
            findings.append({
                "filename": entry.get("filename", ""),
                "record_number": entry.get("record_number", ""),
                "si_created": entry.get("si_created", ""),
                "fn_created": entry.get("fn_created", ""),
                "indicators": reasons,
                "descriptions": [TIMESTOMP_INDICATORS.get(r, r) for r in reasons],
                "confidence": "HIGH" if "si_before_fn" in reasons else "MEDIUM",
                "mitre": "T1070.006",
            })

    return findings


def generate_report(entries, findings):
    """Generate timestomping analysis report."""
    return {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "total_mft_entries": len(entries) if isinstance(entries, list) else 0,
        "total_findings": len(findings),
        "high_confidence": sum(1 for f in findings if f.get("confidence") == "HIGH"),
        "medium_confidence": sum(1 for f in findings if f.get("confidence") == "MEDIUM"),
        "indicator_counts": dict(collections.Counter(
            ind for f in findings for ind in f.get("indicators", [])
        )) if findings else {},
        "mitre_technique": "T1070.006 - Indicator Removal: Timestomp",
    }


# Need collections for generate_report
import collections


def main():
    parser = argparse.ArgumentParser(
        description="NTFS timestomping detection via MFT analysis (MITRE T1070.006)"
    )
    parser.add_argument("mft_csv", nargs="?", help="Path to analyzeMFT CSV output")
    parser.add_argument("--os-install", help="OS install date (YYYY-MM-DD) for baseline")
    parser.add_argument("--high-only", action="store_true", help="Show only HIGH confidence findings")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    print("[*] Timestomping Detection Agent (MITRE T1070.006)")
    print("[*] Compares $STANDARD_INFORMATION vs $FILE_NAME timestamps")

    if not args.mft_csv:
        print("\n[DEMO] Usage:")
        print("  1. Extract MFT: ftkimager /path/to/image mft_output")
        print("  2. Parse MFT: analyzeMFT.py -f $MFT -o mft.csv")
        print("  3. Detect: python agent.py mft.csv [--os-install 2022-01-15]")
        print("\n  Indicators detected:")
        for name, desc in TIMESTOMP_INDICATORS.items():
            print(f"    - {name}: {desc}")
        print(json.dumps({"demo": True, "indicators": len(TIMESTOMP_INDICATORS)}, indent=2))
        sys.exit(0)

    os_date = None
    if args.os_install:
        try:
            os_date = datetime.datetime.strptime(args.os_install, "%Y-%m-%d")
        except ValueError:
            print(f"[!] Invalid date format: {args.os_install}")

    entries = parse_mft_csv(args.mft_csv)
    if isinstance(entries, dict) and "error" in entries:
        print(f"[!] {entries['error']}")
        sys.exit(1)

    findings = detect_timestomping(entries, os_date)
    if args.high_only:
        findings = [f for f in findings if f.get("confidence") == "HIGH"]

    report = generate_report(entries, findings)
    print(f"[*] MFT entries analyzed: {report['total_mft_entries']}")
    print(f"[*] Timestomping findings: {report['total_findings']}")
    print(f"    HIGH confidence: {report['high_confidence']}")
    print(f"    MEDIUM confidence: {report['medium_confidence']}")

    for f in findings[:20]:
        print(f"  [{f['confidence']}] {f['filename']}")
        for desc in f["descriptions"]:
            print(f"    - {desc}")

    if args.output:
        full_report = {"summary": report, "findings": findings}
        with open(args.output, "w") as f:
            json.dump(full_report, f, indent=2)

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
