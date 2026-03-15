#!/usr/bin/env python3
"""Browser Forensics Analyzer - Parses Chrome History SQLite for investigation."""
import sqlite3, json, os, sys
from datetime import datetime, timedelta

CHROME_EPOCH = datetime(1601, 1, 1)

def chrome_ts(ts):
    if not ts: return None
    try: return str(CHROME_EPOCH + timedelta(microseconds=ts))
    except: return None

def analyze_chrome(profile: str, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    history_db = os.path.join(profile, "History")
    conn = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True)
    c = conn.cursor()
    c.execute("SELECT u.url, u.title, v.visit_time, u.visit_count FROM visits v JOIN urls u ON v.url=u.id ORDER BY v.visit_time DESC LIMIT 2000")
    visits = [{"url": r[0], "title": r[1], "time": chrome_ts(r[2]), "count": r[3]} for r in c.fetchall()]
    c.execute("SELECT target_path, tab_url, start_time, total_bytes, mime_type FROM downloads ORDER BY start_time DESC LIMIT 500")
    downloads = [{"path": r[0], "url": r[1], "time": chrome_ts(r[2]), "size": r[3], "mime": r[4]} for r in c.fetchall()]
    conn.close()
    report = {"visits": len(visits), "downloads": len(downloads), "visit_data": visits, "download_data": downloads}
    out = os.path.join(output_dir, "browser_forensics.json")
    with open(out, "w") as f: json.dump(report, f, indent=2)
    print(f"[*] Visits: {len(visits)}, Downloads: {len(downloads)}")
    return out

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: process.py <chrome_profile> <output>"); sys.exit(1)
    analyze_chrome(sys.argv[1], sys.argv[2])
