#!/usr/bin/env python3
"""Ransomware encryption behavior detection agent.

Detects ransomware activity using entropy analysis, file system I/O monitoring,
and behavioral heuristics. Monitors file modifications for entropy spikes and
mass rename patterns characteristic of ransomware encryption.
"""

import hashlib
import json
import logging
import math
import os
import sys
import time
from collections import Counter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ransomware_detector")

RANSOMWARE_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".locky", ".cerber", ".wncry",
    ".dharma", ".basta", ".blackcat", ".hive", ".royal", ".akira",
    ".lockbit", ".conti", ".ryuk", ".maze", ".revil", ".phobos",
}

RANSOM_NOTE_NAMES = {
    "readme.txt", "readme.html", "decrypt.txt", "decrypt.html",
    "how_to_decrypt.txt", "restore_files.txt", "how_to_recover.txt",
}

HIGH_VALUE_EXTENSIONS = {
    ".docx", ".xlsx", ".pptx", ".pdf", ".doc", ".xls", ".ppt",
    ".csv", ".sql", ".mdb", ".accdb", ".bak", ".zip", ".7z",
    ".pst", ".ost", ".eml", ".jpg", ".png", ".dwg", ".vmdk",
}


def shannon_entropy(data):
    """Calculate Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def analyze_file_entropy(filepath):
    """Analyze entropy of a file and its segments."""
    with open(filepath, "rb") as f:
        data = f.read()

    if not data:
        return {"overall": 0.0, "is_encrypted": False}

    overall = shannon_entropy(data)
    file_size = len(data)

    chunk_size = min(4096, file_size // 4) if file_size > 16 else file_size
    first_entropy = shannon_entropy(data[:chunk_size])
    mid_entropy = shannon_entropy(data[file_size // 2: file_size // 2 + chunk_size])
    last_entropy = shannon_entropy(data[-chunk_size:])

    return {
        "overall": round(overall, 4),
        "first_chunk": round(first_entropy, 4),
        "mid_chunk": round(mid_entropy, 4),
        "last_chunk": round(last_entropy, 4),
        "file_size": file_size,
        "is_encrypted": overall > 7.5,
        "is_partial_encryption": abs(first_entropy - mid_entropy) > 2.0,
    }


def scan_directory_entropy(directory, extensions=None):
    """Scan directory for files with high entropy indicating encryption."""
    results = {"total_files": 0, "encrypted_files": 0, "files": []}

    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = os.path.splitext(filename)[1].lower()

            if extensions and ext not in extensions:
                continue

            try:
                analysis = analyze_file_entropy(filepath)
                results["total_files"] += 1

                if analysis["is_encrypted"]:
                    results["encrypted_files"] += 1
                    analysis["path"] = filepath
                    analysis["filename"] = filename
                    results["files"].append(analysis)
            except (OSError, PermissionError):
                continue

    results["encryption_ratio"] = (
        round(results["encrypted_files"] / results["total_files"], 4)
        if results["total_files"] > 0 else 0
    )
    return results


def detect_ransomware_indicators(directory):
    """Detect multiple ransomware indicators in a directory tree."""
    indicators = {
        "ransomware_extensions": [],
        "ransom_notes": [],
        "high_entropy_files": [],
        "renamed_files": [],
        "score": 0,
    }

    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            lower_name = filename.lower()

            # Check for ransomware file extensions
            ext = os.path.splitext(filename)[1].lower()
            if ext in RANSOMWARE_EXTENSIONS:
                indicators["ransomware_extensions"].append(filepath)

            # Check for double extensions (report.docx.locked)
            parts = filename.rsplit(".", 2)
            if len(parts) >= 3:
                original_ext = "." + parts[-2].lower()
                appended_ext = "." + parts[-1].lower()
                if original_ext in HIGH_VALUE_EXTENSIONS and appended_ext in RANSOMWARE_EXTENSIONS:
                    indicators["renamed_files"].append({
                        "path": filepath,
                        "original_ext": original_ext,
                        "ransomware_ext": appended_ext,
                    })

            # Check for ransom notes
            if lower_name in RANSOM_NOTE_NAMES:
                indicators["ransom_notes"].append(filepath)

            # Check entropy of high-value file types
            if ext in HIGH_VALUE_EXTENSIONS:
                try:
                    analysis = analyze_file_entropy(filepath)
                    if analysis["is_encrypted"]:
                        indicators["high_entropy_files"].append({
                            "path": filepath,
                            "entropy": analysis["overall"],
                        })
                except (OSError, PermissionError):
                    continue

    # Calculate ransomware score
    score = 0
    score += min(len(indicators["ransomware_extensions"]) * 5, 30)
    score += min(len(indicators["ransom_notes"]) * 15, 30)
    score += min(len(indicators["high_entropy_files"]) * 3, 20)
    score += min(len(indicators["renamed_files"]) * 5, 20)
    indicators["score"] = min(score, 100)

    if indicators["score"] >= 75:
        indicators["verdict"] = "CRITICAL - Active ransomware encryption detected"
    elif indicators["score"] >= 50:
        indicators["verdict"] = "HIGH - Strong ransomware indicators present"
    elif indicators["score"] >= 25:
        indicators["verdict"] = "MEDIUM - Suspicious activity, investigate further"
    else:
        indicators["verdict"] = "LOW - No significant ransomware indicators"

    return indicators


def snapshot_directory_state(directory):
    """Take a baseline snapshot of directory for differential analysis."""
    snapshot = {}
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                stat = os.stat(filepath)
                sha256 = hashlib.sha256()
                with open(filepath, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        sha256.update(chunk)
                snapshot[filepath] = {
                    "hash": sha256.hexdigest(),
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                }
            except (OSError, PermissionError):
                continue
    return snapshot


def compare_snapshots(before, after):
    """Compare two directory snapshots to detect bulk encryption."""
    changes = {"modified": [], "deleted": [], "created": [], "total_changes": 0}

    for path, info in before.items():
        if path not in after:
            changes["deleted"].append(path)
        elif after[path]["hash"] != info["hash"]:
            changes["modified"].append({
                "path": path,
                "size_before": info["size"],
                "size_after": after[path]["size"],
            })

    for path in after:
        if path not in before:
            changes["created"].append(path)

    changes["total_changes"] = (
        len(changes["modified"]) + len(changes["deleted"]) + len(changes["created"])
    )

    if changes["total_changes"] > 0:
        mod_ratio = len(changes["modified"]) / max(len(before), 1)
        changes["bulk_modification_ratio"] = round(mod_ratio, 4)
        changes["ransomware_likely"] = mod_ratio > 0.3 and len(changes["modified"]) > 10
    else:
        changes["bulk_modification_ratio"] = 0
        changes["ransomware_likely"] = False

    return changes


if __name__ == "__main__":
    print("=" * 60)
    print("Ransomware Encryption Behavior Detection Agent")
    print("Entropy analysis, I/O monitoring, behavioral heuristics")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python agent.py scan <directory>          Scan for ransomware indicators")
        print("  python agent.py entropy <directory>       Entropy scan of files")
        print("  python agent.py entropy-file <file>       Analyze single file entropy")
        print("  python agent.py snapshot <directory>      Take baseline snapshot")
        print("  python agent.py compare <snap1> <snap2>   Compare two snapshots")
        sys.exit(0)

    command = sys.argv[1]

    if command == "scan":
        target = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
        print(f"\n[*] Scanning {target} for ransomware indicators...")
        results = detect_ransomware_indicators(target)
        print("\n--- Ransomware Detection Results ---")
        print(f"  Score: {results['score']}/100")
        print(f"  Verdict: {results['verdict']}")
        print(f"  Ransomware extensions found: {len(results['ransomware_extensions'])}")
        print(f"  Ransom notes found: {len(results['ransom_notes'])}")
        print(f"  High-entropy files: {len(results['high_entropy_files'])}")
        print(f"  Renamed files: {len(results['renamed_files'])}")
        print(f"\n{json.dumps(results, indent=2, default=str)}")

    elif command == "entropy":
        target = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
        print(f"\n[*] Entropy scanning {target}...")
        results = scan_directory_entropy(target, HIGH_VALUE_EXTENSIONS)
        print("\n--- Entropy Scan Results ---")
        print(f"  Total files scanned: {results['total_files']}")
        print(f"  Files with encrypted entropy: {results['encrypted_files']}")
        print(f"  Encryption ratio: {results['encryption_ratio']}")
        for f in results["files"][:10]:
            print(f"  [!] {f['filename']}: entropy={f['overall']}")

    elif command == "entropy-file":
        if len(sys.argv) < 3:
            print("[!] Provide a file path")
            sys.exit(1)
        filepath = sys.argv[2]
        analysis = analyze_file_entropy(filepath)
        print("\n--- File Entropy Analysis ---")
        print(f"  File: {filepath}")
        print(f"  Overall entropy: {analysis['overall']}")
        print(f"  First chunk: {analysis['first_chunk']}")
        print(f"  Mid chunk: {analysis['mid_chunk']}")
        print(f"  Last chunk: {analysis['last_chunk']}")
        print(f"  Encrypted: {analysis['is_encrypted']}")
        print(f"  Partial encryption: {analysis['is_partial_encryption']}")

    elif command == "snapshot":
        target = sys.argv[2] if len(sys.argv) > 2 else os.getcwd()
        print(f"\n[*] Taking snapshot of {target}...")
        snap = snapshot_directory_state(target)
        output = f"snapshot_{int(time.time())}.json"
        with open(output, "w") as f:
            json.dump(snap, f, indent=2)
        print(f"[+] Snapshot saved: {output} ({len(snap)} files)")

    elif command == "compare":
        if len(sys.argv) < 4:
            print("[!] Provide two snapshot JSON files")
            sys.exit(1)
        with open(sys.argv[2]) as f:
            snap1 = json.load(f)
        with open(sys.argv[3]) as f:
            snap2 = json.load(f)
        changes = compare_snapshots(snap1, snap2)
        print("\n--- Snapshot Comparison ---")
        print(f"  Modified: {len(changes['modified'])}")
        print(f"  Deleted: {len(changes['deleted'])}")
        print(f"  Created: {len(changes['created'])}")
        print(f"  Ransomware likely: {changes['ransomware_likely']}")
        print(f"\n{json.dumps(changes, indent=2, default=str)}")

    else:
        print(f"[!] Unknown command: {command}")
