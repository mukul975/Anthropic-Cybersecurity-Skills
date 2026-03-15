---
name: analyzing-browser-forensics-with-hindsight
description: Analyze Chromium-based browser artifacts using Hindsight to extract browsing history, downloads, cookies, cached content, autofill data, saved passwords, and browser extensions from Chrome, Edge, Brave, and Opera for forensic investigation.
domain: cybersecurity
subdomain: digital-forensics
tags: [browser-forensics, hindsight, chrome-forensics, chromium, edge, browsing-history, cookies, downloads, cache, web-artifacts]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Browser Forensics with Hindsight

## Overview

Hindsight is an open-source browser forensics tool designed to parse artifacts from Google Chrome and other Chromium-based browsers (Microsoft Edge, Brave, Opera, Vivaldi). It extracts and correlates data from multiple browser database files to create a unified timeline of web activity. Hindsight can parse URLs, download history, cache records, bookmarks, autofill records, saved passwords, preferences, browser extensions, HTTP cookies, Local Storage (HTML5 cookies), login data, and session/tab information. The tool produces chronological timelines in multiple output formats (XLSX, JSON, SQLite) that enable investigators to reconstruct user web activity for incident response, insider threat investigations, and criminal cases.

## Prerequisites

- Python 3.8+ with Hindsight installed (`pip install pyhindsight`)
- Access to browser profile directories from forensic image
- Browser profile data (not encrypted with OS-level encryption)
- Timeline Explorer or spreadsheet application for analysis

## Browser Profile Locations

| Browser | Windows Profile Path |
|---------|---------------------|
| Chrome | %LOCALAPPDATA%\Google\Chrome\User Data\Default\ |
| Edge | %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\ |
| Brave | %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\ |
| Opera | %APPDATA%\Opera Software\Opera Stable\ |
| Vivaldi | %LOCALAPPDATA%\Vivaldi\User Data\Default\ |
| Chrome (macOS) | ~/Library/Application Support/Google/Chrome/Default/ |
| Chrome (Linux) | ~/.config/google-chrome/Default/ |

## Key Artifact Files

| File | Contents |
|------|----------|
| History | URL visits, downloads, keyword searches |
| Cookies | HTTP cookies with domain, expiry, values |
| Web Data | Autofill entries, saved credit cards |
| Login Data | Saved usernames/passwords (encrypted) |
| Bookmarks | JSON bookmark tree |
| Preferences | Browser configuration and extensions |
| Local Storage/ | HTML5 Local Storage per domain |
| Session Storage/ | Session-specific storage per domain |
| Network Action Predictor | Previously typed URLs |
| Shortcuts | Omnibox shortcuts and predictions |
| Top Sites | Frequently visited sites |

## Running Hindsight

### Command Line

```bash
# Basic analysis of a Chrome profile
hindsight.exe -i "C:\Evidence\Users\suspect\AppData\Local\Google\Chrome\User Data\Default" -o C:\Output\chrome_analysis

# Specify browser type
hindsight.exe -i "/path/to/profile" -o /output/analysis -b Chrome

# JSON output format
hindsight.exe -i "C:\Evidence\Chrome\Default" -o C:\Output\chrome --format jsonl

# With cache parsing (slower but more complete)
hindsight.exe -i "C:\Evidence\Chrome\Default" -o C:\Output\chrome --cache
```

### Web UI

```bash
# Start Hindsight web interface
hindsight_gui.exe
# Navigate to http://localhost:8080
# Upload or point to browser profile directory
# Configure output format and analysis options
# Generate and download report
```

## Artifact Analysis Details

### URL History and Visits

```sql
-- Chrome History database schema (key tables)
-- urls table: id, url, title, visit_count, typed_count, last_visit_time
-- visits table: id, url, visit_time, from_visit, transition, segment_id

-- Timestamps are Chrome/WebKit format: microseconds since 1601-01-01
-- Convert: datetime((visit_time/1000000)-11644473600, 'unixepoch')
```

### Download History

```sql
-- downloads table: id, current_path, target_path, start_time, end_time,
--   received_bytes, total_bytes, state, danger_type, interrupt_reason,
--   url, referrer, tab_url, mime_type, original_mime_type
```

### Cookie Analysis

```sql
-- cookies table: creation_utc, host_key, name, value, encrypted_value,
--   path, expires_utc, is_secure, is_httponly, last_access_utc,
--   has_expires, is_persistent, priority, samesite
```

## Python Analysis Script

```python
import sqlite3
import os
import json
import sys
from datetime import datetime, timedelta


CHROME_EPOCH = datetime(1601, 1, 1)


def chrome_time_to_datetime(chrome_ts: int):
    """Convert Chrome timestamp to datetime."""
    if chrome_ts == 0:
        return None
    try:
        return CHROME_EPOCH + timedelta(microseconds=chrome_ts)
    except (OverflowError, OSError):
        return None


def analyze_chrome_history(profile_path: str, output_dir: str) -> dict:
    """Analyze Chrome History database for forensic evidence."""
    history_db = os.path.join(profile_path, "History")
    if not os.path.exists(history_db):
        return {"error": "History database not found"}

    os.makedirs(output_dir, exist_ok=True)
    conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)

    # URL visits with timestamps
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.url, u.title, v.visit_time, u.visit_count,
               v.transition & 0xFF as transition_type
        FROM visits v JOIN urls u ON v.url = u.id
        ORDER BY v.visit_time DESC LIMIT 5000
    """)
    visits = [{
        "url": r[0], "title": r[1],
        "visit_time": str(chrome_time_to_datetime(r[2])),
        "total_visits": r[3], "transition": r[4]
    } for r in cursor.fetchall()]

    # Downloads
    cursor.execute("""
        SELECT target_path, tab_url, start_time, end_time,
               received_bytes, total_bytes, mime_type, state
        FROM downloads ORDER BY start_time DESC LIMIT 1000
    """)
    downloads = [{
        "path": r[0], "source_url": r[1],
        "start_time": str(chrome_time_to_datetime(r[2])),
        "end_time": str(chrome_time_to_datetime(r[3])),
        "received_bytes": r[4], "total_bytes": r[5],
        "mime_type": r[6], "state": r[7]
    } for r in cursor.fetchall()]

    # Keyword searches
    cursor.execute("""
        SELECT k.term, u.url, k.url_id
        FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id
        ORDER BY u.last_visit_time DESC LIMIT 1000
    """)
    searches = [{"term": r[0], "url": r[1]} for r in cursor.fetchall()]

    conn.close()

    report = {
        "analysis_timestamp": datetime.now().isoformat(),
        "profile_path": profile_path,
        "total_visits": len(visits),
        "total_downloads": len(downloads),
        "total_searches": len(searches),
        "visits": visits,
        "downloads": downloads,
        "searches": searches
    }

    report_path = os.path.join(output_dir, "browser_forensics.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return report


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <chrome_profile_path> <output_dir>")
        sys.exit(1)
    analyze_chrome_history(sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()
```

## References

- Hindsight GitHub: https://github.com/obsidianforensics/hindsight
- Chrome Forensics Guide: https://allenace.medium.com/hindsight-chrome-forensics-made-simple-425db99fa5ed
- Browser Forensics Tools: https://www.cyberforensicacademy.com/blog/browser-forensics-tools-how-to-extract-user-activity
- Chromium Source (History): https://source.chromium.org/chromium/chromium/src/+/main:components/history/
