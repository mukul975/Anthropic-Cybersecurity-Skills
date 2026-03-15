#!/usr/bin/env python3
"""Browser forensics analysis agent using Hindsight concepts.

Parses Chromium-based browser artifacts (Chrome, Edge, Brave) including
history, downloads, cookies, autofill, and extensions from SQLite databases.
"""

import os
import sys
import json
import sqlite3
import datetime
import hashlib
from collections import defaultdict


def chrome_time_to_datetime(chrome_time):
    """Convert Chrome timestamp (microseconds since 1601-01-01) to datetime."""
    if not chrome_time or chrome_time == 0:
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1)
        delta = datetime.timedelta(microseconds=chrome_time)
        return (epoch + delta).isoformat() + "Z"
    except (OverflowError, OSError):
        return None


def find_browser_profiles(base_path=None):
    """Locate Chromium-based browser profile directories."""
    if base_path and os.path.isdir(base_path):
        return [base_path]
    profiles = []
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default"),
        os.path.join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default"),
        os.path.join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default"),
        os.path.join(home, ".config", "google-chrome", "Default"),
        os.path.join(home, ".config", "chromium", "Default"),
        os.path.join(home, ".config", "microsoft-edge", "Default"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            profiles.append(path)
    return profiles


def parse_history(profile_path):
    """Parse browsing history from History SQLite database."""
    db_path = os.path.join(profile_path, "History")
    if not os.path.exists(db_path):
        return []
    entries = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.url, u.title, v.visit_time, v.transition, u.visit_count
            FROM visits v JOIN urls u ON v.url = u.id
            ORDER BY v.visit_time DESC LIMIT 5000
        """)
        for url, title, visit_time, transition, count in cursor.fetchall():
            entries.append({
                "url": url, "title": title or "",
                "visit_time": chrome_time_to_datetime(visit_time),
                "transition": transition & 0xFF,
                "visit_count": count,
            })
        conn.close()
    except sqlite3.Error as e:
        entries.append({"error": str(e)})
    return entries


def parse_downloads(profile_path):
    """Parse download history from History database."""
    db_path = os.path.join(profile_path, "History")
    if not os.path.exists(db_path):
        return []
    downloads = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT target_path, tab_url, total_bytes, start_time, end_time,
                   danger_type, interrupt_reason, mime_type
            FROM downloads ORDER BY start_time DESC LIMIT 1000
        """)
        for row in cursor.fetchall():
            downloads.append({
                "target_path": row[0], "source_url": row[1],
                "total_bytes": row[2],
                "start_time": chrome_time_to_datetime(row[3]),
                "end_time": chrome_time_to_datetime(row[4]),
                "danger_type": row[5], "interrupt_reason": row[6],
                "mime_type": row[7],
            })
        conn.close()
    except sqlite3.Error as e:
        downloads.append({"error": str(e)})
    return downloads


def parse_cookies(profile_path):
    """Parse cookies from Cookies database."""
    db_path = os.path.join(profile_path, "Cookies")
    if not os.path.exists(db_path):
        db_path = os.path.join(profile_path, "Network", "Cookies")
    if not os.path.exists(db_path):
        return []
    cookies = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT host_key, name, path, creation_utc, expires_utc,
                   is_secure, is_httponly, samesite
            FROM cookies ORDER BY creation_utc DESC LIMIT 2000
        """)
        for row in cursor.fetchall():
            cookies.append({
                "host": row[0], "name": row[1], "path": row[2],
                "created": chrome_time_to_datetime(row[3]),
                "expires": chrome_time_to_datetime(row[4]),
                "secure": bool(row[5]), "httponly": bool(row[6]),
                "samesite": row[7],
            })
        conn.close()
    except sqlite3.Error as e:
        cookies.append({"error": str(e)})
    return cookies


def parse_autofill(profile_path):
    """Parse autofill data from Web Data database."""
    db_path = os.path.join(profile_path, "Web Data")
    if not os.path.exists(db_path):
        return []
    entries = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name, value, count, date_created, date_last_used
            FROM autofill ORDER BY date_last_used DESC LIMIT 500
        """)
        for row in cursor.fetchall():
            entries.append({
                "field_name": row[0], "value": row[1][:50] + "..." if len(row[1]) > 50 else row[1],
                "usage_count": row[2],
                "created": chrome_time_to_datetime(row[3] * 1000000 if row[3] else 0),
                "last_used": chrome_time_to_datetime(row[4] * 1000000 if row[4] else 0),
            })
        conn.close()
    except sqlite3.Error as e:
        entries.append({"error": str(e)})
    return entries


def parse_extensions(profile_path):
    """Parse installed browser extensions."""
    ext_dir = os.path.join(profile_path, "Extensions")
    extensions = []
    if not os.path.isdir(ext_dir):
        return extensions
    for ext_id in os.listdir(ext_dir):
        ext_path = os.path.join(ext_dir, ext_id)
        if os.path.isdir(ext_path):
            versions = sorted(os.listdir(ext_path))
            manifest_path = os.path.join(ext_path, versions[-1], "manifest.json") if versions else None
            name = ext_id
            if manifest_path and os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)
                    name = manifest.get("name", ext_id)
                    extensions.append({
                        "id": ext_id, "name": name,
                        "version": manifest.get("version", "?"),
                        "permissions": manifest.get("permissions", [])[:10],
                    })
                except (json.JSONDecodeError, IOError):
                    extensions.append({"id": ext_id, "name": name, "version": "unknown"})
    return extensions


def detect_suspicious_activity(history, downloads):
    """Flag suspicious browsing and download patterns."""
    findings = []
    suspicious_domains = ["pastebin.com", "ngrok.io", "raw.githubusercontent.com",
                          "transfer.sh", "file.io", "temp.sh", "anonfiles.com"]
    for entry in history:
        url = entry.get("url", "").lower()
        for domain in suspicious_domains:
            if domain in url:
                findings.append({
                    "type": "suspicious_url", "url": entry["url"],
                    "domain": domain, "time": entry.get("visit_time"),
                })
    dangerous_mimes = ["application/x-msdownload", "application/x-msdos-program",
                       "application/x-executable", "application/vnd.ms-excel.sheet.macroEnabled"]
    for dl in downloads:
        if dl.get("danger_type", 0) > 0:
            findings.append({
                "type": "dangerous_download", "path": dl.get("target_path"),
                "source": dl.get("source_url"), "danger_type": dl.get("danger_type"),
            })
        if dl.get("mime_type", "") in dangerous_mimes:
            findings.append({
                "type": "suspicious_mime", "mime": dl.get("mime_type"),
                "path": dl.get("target_path"),
            })
    return findings


if __name__ == "__main__":
    print("=" * 60)
    print("Browser Forensics Analysis Agent")
    print("Chromium history, downloads, cookies, extensions")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None
    profiles = find_browser_profiles(target)

    if not profiles:
        print("\n[!] No browser profiles found.")
        print("[DEMO] Usage: python agent.py <profile_path>")
        print("  e.g. python agent.py ~/AppData/Local/Google/Chrome/User\\ Data/Default")
        sys.exit(0)

    for profile in profiles:
        print(f"\n[*] Profile: {profile}")

        history = parse_history(profile)
        print(f"  History entries: {len(history)}")
        for h in history[:5]:
            print(f"    {h.get('visit_time', '?')} | {h.get('title', '')[:50]} | {h.get('url', '')[:60]}")

        downloads = parse_downloads(profile)
        print(f"  Downloads: {len(downloads)}")
        for d in downloads[:5]:
            print(f"    {d.get('start_time', '?')} | {d.get('mime_type', '?')} | {os.path.basename(d.get('target_path', ''))}")

        cookies = parse_cookies(profile)
        print(f"  Cookies: {len(cookies)}")

        extensions = parse_extensions(profile)
        print(f"  Extensions: {len(extensions)}")
        for ext in extensions[:5]:
            print(f"    {ext.get('name', '?')} v{ext.get('version', '?')} [{ext.get('id', '')[:20]}]")

        findings = detect_suspicious_activity(history, downloads)
        print(f"\n  --- Suspicious Activity: {len(findings)} findings ---")
        for f in findings[:10]:
            print(f"    [{f['type']}] {f.get('url', f.get('path', ''))}")
