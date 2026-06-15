---
name: hunting-for-defense-evasion-via-timestomping
description: 'Detect NTFS timestamp manipulation (MITRE T1070.006) by comparing $STANDARD_INFORMATION
  vs $FILE_NAME timestamps in the MFT. Uses analyzeMFT and Python to identify files
  with anomalous temporal patterns indicating anti-forensic timestomping activity.

  '
domain: cybersecurity
subdomain: threat-hunting
tags:
- timestomping
- ntfs-forensics
- mft-analysis
- defense-evasion
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
- Platform Hardening
- File Format Verification
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1027
---

# Hunting for Defense Evasion via Timestomping

Detect timestamp manipulation by analyzing NTFS MFT entries for
discrepancies between $STANDARD_INFORMATION and $FILE_NAME attributes.

## When to Use

- Investigating suspected anti-forensic activity where an adversary may have altered file timestamps to blend malware into legitimate directories
- Threat hunting for defense evasion (MITRE ATT&CK T1070.006) across compromised Windows systems
- Validating timeline integrity during forensic examinations of disk images or live acquisitions
- Triaging suspicious files that appear to have creation dates older than the OS installation or inconsistent with known deployment timelines
- Detecting tools like Timestomp (Metasploit), NTimeStomp, SetMACE, or PowerShell Set-ItemProperty used to alter timestamps
- Building automated detection pipelines that flag temporal anomalies in MFT data for SOC analysts

**Do not use** as the sole detection method; advanced adversaries can manipulate both $STANDARD_INFORMATION and $FILE_NAME timestamps (though the latter requires raw disk access and is much harder). Combine with USN Journal, $LogFile, and ShimCache/Amcache analysis for corroboration.

## Prerequisites

- Raw $MFT file extracted from a Windows system (via FTK Imager, KAPE, or live extraction)
- `MFTECmd` (Eric Zimmerman tool) or `analyzeMFT` for MFT parsing
- Python 3.8+ with `pandas` for analysis
- Optional: `mft` Python library (`pip install mft`) for programmatic MFT parsing
- Optional: KAPE (Kroll Artifact Parser and Extractor) for automated artifact collection
- Timeline Explorer or Excel for visual analysis of parsed MFT output

## Workflow

### Step 1: Extract the $MFT from a Live System or Disk Image

```powershell
# Method 1: Using KAPE to collect MFT and related artifacts
.\kape.exe --tsource C: --tdest D:\Evidence\MFT_Collection --target !SANS_Triage

# Method 2: Using FTK Imager CLI to extract $MFT
ftkimager.exe \\.\C: D:\Evidence\mft_raw.bin --e01 --include $MFT

# Method 3: Raw copy using RawCopy (handles locked NTFS system files)
RawCopy.exe /FileNamePath:C:0 /OutputPath:D:\Evidence\ /OutputName:$MFT
```

```bash
# Method 4: On a mounted forensic image in Linux
sudo mount -o ro,norecovery /dev/sdb1 /mnt/evidence
sudo icat -o 2048 /dev/sdb 0 > /mnt/output/$MFT

# Method 5: Using sleuthkit to extract MFT from disk image
icat -o 2048 evidence.E01 0 > extracted_MFT
```

### Step 2: Parse the MFT with MFTECmd

Use Eric Zimmerman's MFTECmd to produce a CSV with both $STANDARD_INFORMATION and $FILE_NAME timestamps:

```powershell
# Parse MFT to CSV with all timestamp columns
MFTECmd.exe -f "D:\Evidence\$MFT" --csv D:\Evidence\Parsed\ --csvf mft_parsed.csv

# The output CSV contains these critical columns:
# Created0x10         - $STANDARD_INFORMATION Created timestamp
# LastModified0x10    - $STANDARD_INFORMATION Modified timestamp
# LastAccess0x10      - $STANDARD_INFORMATION Accessed timestamp
# LastRecordChange0x10 - $STANDARD_INFORMATION Entry Modified timestamp
# Created0x30         - $FILE_NAME Created timestamp
# LastModified0x30    - $FILE_NAME Modified timestamp
# LastAccess0x30      - $FILE_NAME Accessed timestamp
# LastRecordChange0x30 - $FILE_NAME Entry Modified timestamp
```

### Step 3: Detect Timestomping via SI vs FN Comparison

The core detection: $STANDARD_INFORMATION timestamps are easily modified by user-mode tools, but $FILE_NAME timestamps are updated only by the NTFS driver (kernel-mode). When SI timestamps are OLDER than FN timestamps, timestomping is likely:

```python
import pandas as pd
from datetime import datetime, timedelta

def load_mft_data(csv_path):
    """Load MFTECmd parsed CSV output."""
    df = pd.read_csv(csv_path, low_memory=False)

    # Parse timestamp columns
    timestamp_cols = [
        "Created0x10", "LastModified0x10", "LastAccess0x10", "LastRecordChange0x10",
        "Created0x30", "LastModified0x30", "LastAccess0x30", "LastRecordChange0x30"
    ]

    for col in timestamp_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    return df

def detect_timestomping(df):
    """Detect timestamp manipulation by comparing SI and FN attributes.

    Key indicators:
    1. SI Created < FN Created (SI timestamp pushed back in time)
    2. SI timestamps have nanoseconds = 0000000 (tool artifact)
    3. SI Created < FN Entry Modified (impossible under normal NTFS behavior)
    4. Large gap between SI and FN timestamps
    """
    results = []

    for idx, row in df.iterrows():
        si_created = row.get("Created0x10")
        fn_created = row.get("Created0x30")
        si_modified = row.get("LastModified0x10")
        fn_modified = row.get("LastModified0x30")
        si_entry = row.get("LastRecordChange0x10")
        fn_entry = row.get("LastRecordChange0x30")

        if pd.isna(si_created) or pd.isna(fn_created):
            continue

        filepath = row.get("FileName", "unknown")
        parent_path = row.get("ParentPath", "")
        full_path = f"{parent_path}\\{filepath}" if parent_path else filepath
        indicators = []

        # Detection 1: SI Created is BEFORE FN Created
        # Under normal NTFS operations, SI Created >= FN Created
        if si_created < fn_created:
            delta = fn_created - si_created
            indicators.append({
                "check": "SI_Created < FN_Created",
                "si_value": str(si_created),
                "fn_value": str(fn_created),
                "delta": str(delta),
                "confidence": "high"
            })

        # Detection 2: SI Modified is BEFORE FN Created
        # A file cannot be modified before it was created
        if pd.notna(si_modified) and si_modified < fn_created:
            indicators.append({
                "check": "SI_Modified < FN_Created",
                "si_value": str(si_modified),
                "fn_value": str(fn_created),
                "confidence": "high"
            })

        # Detection 3: Nanosecond precision check
        # Many timestomping tools set timestamps with zero nanoseconds
        if pd.notna(si_created):
            si_created_str = str(si_created)
            if ".000000" in si_created_str or si_created_str.endswith("00:00:00"):
                # Check if FN has normal nanosecond precision
                fn_str = str(fn_created)
                if ".000000" not in fn_str:
                    indicators.append({
                        "check": "SI_nanoseconds_zeroed",
                        "si_value": si_created_str,
                        "fn_value": fn_str,
                        "confidence": "medium"
                    })

        # Detection 4: Large time gap between SI and FN
        # Normal gap is seconds to minutes, not years
        if abs((si_created - fn_created).days) > 365:
            indicators.append({
                "check": "SI_FN_gap_exceeds_1_year",
                "si_value": str(si_created),
                "fn_value": str(fn_created),
                "delta_days": abs((si_created - fn_created).days),
                "confidence": "high"
            })

        # Detection 5: SI Entry Modified much later than SI Created
        # Indicates the SI attribute was rewritten
        if pd.notna(si_entry) and pd.notna(si_created):
            entry_delta = si_entry - si_created
            if entry_delta.days > 365 * 5:  # Entry modified years after creation
                indicators.append({
                    "check": "SI_entry_modified_years_after_creation",
                    "si_created": str(si_created),
                    "si_entry_modified": str(si_entry),
                    "confidence": "medium"
                })

        if indicators:
            results.append({
                "file_path": full_path,
                "entry_number": row.get("EntryNumber", ""),
                "in_use": row.get("InUse", True),
                "si_created": str(si_created),
                "fn_created": str(fn_created),
                "indicators": indicators,
                "highest_confidence": max(i["confidence"] for i in indicators),
            })

    return results

# Run detection
df = load_mft_data("D:\\Evidence\\Parsed\\mft_parsed.csv")
stomped_files = detect_timestomping(df)

print(f"\nTimestomping Detection Results")
print(f"{'='*60}")
print(f"Total MFT entries analyzed: {len(df)}")
print(f"Suspicious entries found: {len(stomped_files)}")
print()

for entry in sorted(stomped_files, key=lambda x: x["highest_confidence"], reverse=True):
    print(f"[{entry['highest_confidence'].upper()}] {entry['file_path']}")
    print(f"  SI Created: {entry['si_created']}")
    print(f"  FN Created: {entry['fn_created']}")
    for ind in entry["indicators"]:
        print(f"  Check: {ind['check']} (confidence: {ind['confidence']})")
    print()
```

### Step 4: Corroborate with USN Journal Analysis

The USN Journal records metadata change events that persist even after timestomping:

```python
def correlate_with_usn_journal(stomped_files, usn_csv_path):
    """Cross-reference timestomped files with USN Journal entries.

    The USN Journal records a BASIC_INFO_CHANGE reason when timestamps
    are modified, providing corroborating evidence of timestomping.
    """
    usn_df = pd.read_csv(usn_csv_path, low_memory=False)
    usn_df["UpdateTimestamp"] = pd.to_datetime(usn_df["UpdateTimestamp"], errors="coerce")

    corroborated = []
    for entry in stomped_files:
        filename = entry["file_path"].split("\\")[-1]

        # Find USN entries for this file with BASIC_INFO_CHANGE
        usn_matches = usn_df[
            (usn_df["Name"] == filename) &
            (usn_df["UpdateReasons"].str.contains("BASIC_INFO_CHANGE", na=False))
        ]

        if not usn_matches.empty:
            entry["usn_corroboration"] = True
            entry["usn_change_times"] = usn_matches["UpdateTimestamp"].tolist()
            entry["highest_confidence"] = "critical"
            corroborated.append(entry)
            print(f"[CORROBORATED] {filename} - USN Journal confirms "
                  f"BASIC_INFO_CHANGE at {usn_matches['UpdateTimestamp'].iloc[0]}")

    return corroborated

# Parse USN Journal (use MFTECmd or ANJP)
# MFTECmd.exe -f "$J" --csv D:\Evidence\Parsed\ --csvf usn_parsed.csv
```

### Step 5: Check ShimCache and Amcache for Timeline Validation

```python
def check_shimcache_timeline(stomped_files, shimcache_csv):
    """Validate timestamps against ShimCache (AppCompatCache) entries.

    ShimCache records the last modification time of executables
    independently of NTFS timestamps, providing another corroboration point.
    """
    shim_df = pd.read_csv(shimcache_csv, low_memory=False)
    shim_df["LastModifiedTimeUTC"] = pd.to_datetime(
        shim_df["LastModifiedTimeUTC"], errors="coerce"
    )

    for entry in stomped_files:
        filepath = entry["file_path"]
        shim_match = shim_df[
            shim_df["Path"].str.lower() == filepath.lower()
        ]

        if not shim_match.empty:
            shim_time = shim_match["LastModifiedTimeUTC"].iloc[0]
            si_modified = pd.to_datetime(entry.get("si_created"))

            if pd.notna(shim_time) and pd.notna(si_modified):
                delta = abs((shim_time - si_modified).days)
                if delta > 30:
                    entry["shimcache_mismatch"] = True
                    entry["shimcache_time"] = str(shim_time)
                    print(f"[SHIMCACHE MISMATCH] {filepath}")
                    print(f"  SI timestamp: {si_modified}")
                    print(f"  ShimCache timestamp: {shim_time}")
                    print(f"  Delta: {delta} days")

    return stomped_files
```

### Step 6: Generate a Timestomping Detection Report

```python
import json

def generate_report(stomped_files, output_path):
    """Generate a structured JSON report of all timestomping detections."""
    report = {
        "report_title": "Timestomping Detection Analysis",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "mitre_technique": "T1070.006 - Indicator Removal: Timestomp",
        "total_suspicious_files": len(stomped_files),
        "critical_findings": len([f for f in stomped_files if f["highest_confidence"] == "critical"]),
        "high_findings": len([f for f in stomped_files if f["highest_confidence"] == "high"]),
        "medium_findings": len([f for f in stomped_files if f["highest_confidence"] == "medium"]),
        "findings": stomped_files,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Report written to {output_path}")
    print(f"  Critical: {report['critical_findings']}")
    print(f"  High: {report['high_findings']}")
    print(f"  Medium: {report['medium_findings']}")

generate_report(stomped_files, "D:\\Evidence\\timestomping_report.json")
```

## Verification

- Confirm MFTECmd parses the $MFT without errors and produces both 0x10 (SI) and 0x30 (FN) timestamp columns
- Create a test file and use a timestomping tool (e.g., NTimeStomp) in a lab to verify the detection logic catches the manipulation
- Validate that the nanosecond-zeroed check does not produce excessive false positives on files created by installers that legitimately set timestamps
- Cross-reference flagged files with the USN Journal to confirm BASIC_INFO_CHANGE events exist at the expected times
- Verify ShimCache and Amcache timestamps provide independent corroboration of timeline inconsistencies
- Test against known-clean system images to establish a false-positive baseline (some backup/imaging software legitimately resets timestamps)
- Confirm the detection pipeline correctly handles deleted MFT entries (InUse=false) which may contain evidence of timestomped files that were later removed
