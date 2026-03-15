#!/usr/bin/env python3
"""Ransomware Incident Response agent — automates initial triage, IOC
collection, and containment actions during a ransomware event."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".crypt", ".cry", ".crypto", ".enc",
    ".locky", ".cerber", ".zepto", ".wncry", ".wnry", ".wcry",
    ".onion", ".aaa", ".abc", ".xyz", ".zzz", ".micro", ".r5a",
}

RANSOM_NOTE_PATTERNS = [
    "readme.txt", "how_to_decrypt.txt", "decrypt_instructions.html",
    "restore_files.txt", "help_decrypt.html", "recovery.txt",
    "_readme.txt", "how_to_recover.txt",
]


def scan_encrypted_files(target_dir: str, max_files: int = 5000) -> list[dict]:
    """Scan directory for files with ransomware-associated extensions."""
    findings = []
    count = 0
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if count >= max_files:
                return findings
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            if ext in RANSOMWARE_EXTENSIONS:
                try:
                    stat = os.stat(fpath)
                    findings.append({
                        "path": fpath,
                        "extension": ext,
                        "size_bytes": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })
                except OSError:
                    pass
                count += 1
    return findings


def find_ransom_notes(target_dir: str) -> list[dict]:
    """Search for known ransom note filenames."""
    notes = []
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if fname.lower() in RANSOM_NOTE_PATTERNS:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(2048)
                    notes.append({"path": fpath, "preview": content[:500]})
                except OSError:
                    notes.append({"path": fpath, "preview": "[unreadable]"})
    return notes


def collect_file_hashes(file_paths: list[str], max_hash: int = 100) -> list[dict]:
    """Compute SHA-256 hashes for IOC submission."""
    hashes = []
    for fpath in file_paths[:max_hash]:
        try:
            sha = hashlib.sha256()
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha.update(chunk)
            hashes.append({"path": fpath, "sha256": sha.hexdigest()})
        except OSError:
            pass
    return hashes


def check_shadow_copies(platform: str = sys.platform) -> dict:
    """Check if Volume Shadow Copies are intact (Windows) or snapshots exist."""
    if platform == "win32":
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True, text=True, timeout=30
            )
            shadow_count = result.stdout.count("Shadow Copy ID")
            return {"platform": "windows", "shadow_copies": shadow_count,
                    "intact": shadow_count > 0, "raw": result.stdout[:1000]}
        except (subprocess.SubprocessError, FileNotFoundError):
            return {"platform": "windows", "shadow_copies": 0, "intact": False, "error": "vssadmin unavailable"}
    return {"platform": platform, "shadow_copies": -1, "intact": False, "note": "Manual check required"}


def generate_containment_actions(encrypted_count: int, notes_found: int) -> list[dict]:
    """Produce recommended containment actions based on findings."""
    actions = [
        {"priority": 1, "action": "Isolate affected hosts from network immediately",
         "detail": "Disable network adapters or move to quarantine VLAN"},
        {"priority": 2, "action": "Preserve forensic evidence before remediation",
         "detail": "Create disk images of affected systems"},
        {"priority": 3, "action": "Reset credentials for all privileged accounts",
         "detail": "Include krbtgt, service accounts, and domain admins"},
    ]
    if encrypted_count > 100:
        actions.append({"priority": 4, "action": "Activate business continuity plan",
                        "detail": f"{encrypted_count} encrypted files detected — significant data impact"})
    if notes_found > 0:
        actions.append({"priority": 5, "action": "Collect and analyze ransom notes for variant identification",
                        "detail": "Submit to ID Ransomware (id-ransomware.malwarehunterteam.com)"})
    return actions


def generate_report(target_dir: str, max_files: int) -> dict:
    """Run all checks and build consolidated incident report."""
    encrypted = scan_encrypted_files(target_dir, max_files)
    notes = find_ransom_notes(target_dir)
    file_hashes = collect_file_hashes([f["path"] for f in encrypted[:50]])
    shadow_status = check_shadow_copies()
    actions = generate_containment_actions(len(encrypted), len(notes))

    return {
        "report": "ransomware_incident_response",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target_directory": target_dir,
        "encrypted_files_found": len(encrypted),
        "ransom_notes_found": len(notes),
        "shadow_copy_status": shadow_status,
        "containment_actions": actions,
        "encrypted_files_sample": encrypted[:20],
        "ransom_notes": notes[:10],
        "file_hashes": file_hashes,
    }


def main():
    parser = argparse.ArgumentParser(description="Ransomware Incident Response Agent")
    parser.add_argument("--target", required=True, help="Directory to scan for ransomware artifacts")
    parser.add_argument("--max-files", type=int, default=5000, help="Max files to scan (default: 5000)")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.target, args.max_files)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
