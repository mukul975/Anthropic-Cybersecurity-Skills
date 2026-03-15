#!/usr/bin/env python3
"""
Ransomware Attack Artifact Investigation Agent
Collects and analyzes ransomware artifacts including ransom notes, encrypted
file samples, registry modifications, and event logs to identify the variant,
attack vector, and encryption scope.
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


RANSOMWARE_ID_URL = "https://id-ransomware.malwarehunterteam.com/api/"
VT_API_KEY = ""


def collect_ransom_notes(search_root: str) -> list[dict]:
    """Search filesystem for common ransom note filenames."""
    ransom_note_patterns = [
        "README.txt", "DECRYPT*.txt", "HOW_TO_DECRYPT*", "RECOVER*",
        "_readme.txt", "!README!*", "HELP_DECRYPT*", "YOUR_FILES*",
        "ATTENTION*.txt", "RESTORE*FILES*", "#DECRYPT#*", "info.hta",
    ]
    found_notes = []
    root = Path(search_root)

    for pattern in ransom_note_patterns:
        for match in root.rglob(pattern):
            if match.is_file() and match.stat().st_size < 1_000_000:
                with open(match, "r", errors="ignore") as f:
                    content = f.read(4096)
                found_notes.append({
                    "path": str(match),
                    "filename": match.name,
                    "size": match.stat().st_size,
                    "content_preview": content[:500],
                    "sha256": hashlib.sha256(content.encode()).hexdigest(),
                })

    return found_notes


def identify_encrypted_files(search_root: str) -> dict:
    """Identify encrypted files by extension and calculate scope."""
    known_extensions = [
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
        ".locky", ".zepto", ".cerber", ".dharma", ".phobos",
        ".ryuk", ".conti", ".lockbit", ".blackcat", ".hive",
        ".akira", ".royal", ".play", ".clop", ".alphv",
    ]
    encrypted_files = []
    extension_counts = {}
    total_size = 0

    root = Path(search_root)
    for filepath in root.rglob("*"):
        if filepath.is_file():
            ext = filepath.suffix.lower()
            if ext in known_extensions:
                encrypted_files.append(str(filepath))
                extension_counts[ext] = extension_counts.get(ext, 0) + 1
                total_size += filepath.stat().st_size

    return {
        "total_encrypted_files": len(encrypted_files),
        "total_encrypted_size_gb": round(total_size / (1024**3), 2),
        "extensions_found": extension_counts,
        "sample_files": encrypted_files[:20],
    }


def analyze_ransom_note_content(notes: list[dict]) -> dict:
    """Extract IOCs and payment details from ransom notes."""
    bitcoin_pattern = re.compile(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59}")
    monero_pattern = re.compile(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")
    tor_pattern = re.compile(r"[a-z2-7]{16,56}\.onion")
    email_pattern = re.compile(r"[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}")

    iocs = {"bitcoin_addresses": set(), "monero_addresses": set(),
            "tor_sites": set(), "email_contacts": set(), "ransom_amounts": []}

    for note in notes:
        content = note.get("content_preview", "")
        for match in bitcoin_pattern.findall(content):
            iocs["bitcoin_addresses"].add(match)
        for match in monero_pattern.findall(content):
            iocs["monero_addresses"].add(match)
        for match in tor_pattern.findall(content):
            iocs["tor_sites"].add(match)
        for match in email_pattern.findall(content):
            iocs["email_contacts"].add(match)

        amount_match = re.search(r"\$\s?([\d,]+)", content)
        if amount_match:
            iocs["ransom_amounts"].append(amount_match.group(0))

    return {k: sorted(v) if isinstance(v, set) else v for k, v in iocs.items()}


def check_hash_virustotal(file_hash: str, api_key: str) -> dict:
    """Look up file hash on VirusTotal for ransomware identification."""
    if not api_key:
        return {"error": "VT_API_KEY not configured"}
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": api_key}, timeout=30,
    )
    if resp.status_code == 200:
        attrs = resp.json().get("data", {}).get("attributes", {})
        return {
            "threat_label": attrs.get("popular_threat_classification", {}).get(
                "suggested_threat_label", "unknown"),
            "detection_ratio": f"{attrs.get('last_analysis_stats', {}).get('malicious', 0)}"
                               f"/{sum(attrs.get('last_analysis_stats', {}).values())}",
            "first_seen": attrs.get("first_submission_date", ""),
            "names": attrs.get("names", [])[:5],
        }
    return {"error": f"VT lookup failed: {resp.status_code}"}


def parse_windows_event_logs(evtx_export_path: str) -> list[dict]:
    """Parse exported Windows event log CSV for ransomware indicators."""
    events = []
    if not os.path.exists(evtx_export_path):
        return events

    import csv
    with open(evtx_export_path, "r", newline="", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("EventID", row.get("event_id", ""))
            suspicious_ids = ["1102", "4688", "4697", "7045", "1116", "4624"]
            if str(event_id) in suspicious_ids:
                events.append({
                    "timestamp": row.get("TimeCreated", row.get("timestamp", "")),
                    "event_id": event_id,
                    "source": row.get("ProviderName", row.get("source", "")),
                    "message": row.get("Message", row.get("message", ""))[:300],
                })

    return events


def generate_report(notes: list, encrypted: dict, iocs: dict, events: list) -> str:
    """Generate ransomware investigation report."""
    lines = [
        "RANSOMWARE ATTACK ARTIFACT INVESTIGATION REPORT",
        "=" * 55,
        f"Investigation Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "RANSOM NOTES:",
        f"  Notes Found: {len(notes)}",
    ]
    for note in notes[:5]:
        lines.append(f"  - {note['filename']} ({note['path']})")

    lines.extend([
        "",
        "ENCRYPTION SCOPE:",
        f"  Encrypted Files: {encrypted['total_encrypted_files']}",
        f"  Total Size: {encrypted['total_encrypted_size_gb']} GB",
        f"  Extensions: {json.dumps(encrypted['extensions_found'])}",
        "",
        "EXTRACTED IOCs:",
        f"  Bitcoin Addresses: {len(iocs.get('bitcoin_addresses', []))}",
        f"  Tor Sites: {len(iocs.get('tor_sites', []))}",
        f"  Contact Emails: {len(iocs.get('email_contacts', []))}",
        "",
        f"SUSPICIOUS EVENTS: {len(events)}",
    ])
    for evt in events[:10]:
        lines.append(f"  [{evt['event_id']}] {evt['timestamp']} - {evt['message'][:80]}")

    return "\n".join(lines)


if __name__ == "__main__":
    VT_API_KEY = os.getenv("VT_API_KEY", VT_API_KEY)
    search_root = sys.argv[1] if len(sys.argv) > 1 else "."
    evtx_path = sys.argv[2] if len(sys.argv) > 2 else "events.csv"

    print(f"[*] Investigating ransomware artifacts in: {search_root}")

    notes = collect_ransom_notes(search_root)
    print(f"[*] Found {len(notes)} ransom notes")

    encrypted = identify_encrypted_files(search_root)
    print(f"[*] Found {encrypted['total_encrypted_files']} encrypted files")

    iocs = analyze_ransom_note_content(notes)
    events = parse_windows_event_logs(evtx_path)

    report = generate_report(notes, encrypted, iocs, events)
    print(report)

    output = f"ransomware_investigation_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump({"ransom_notes": notes, "encrypted_files": encrypted, "iocs": iocs, "events": events}, f, indent=2)
    print(f"\n[*] Results saved to {output}")
