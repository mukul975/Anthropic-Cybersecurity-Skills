#!/usr/bin/env python3
"""Browser history artifact extraction agent using sqlite3 for Chrome/Firefox/Edge forensics."""

import argparse
import csv
import json
import logging
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CHROME_EPOCH = datetime(1601, 1, 1)
UNIX_EPOCH = datetime(1970, 1, 1)


def chrome_time_to_utc(chrome_ts: int) -> str:
    """Convert Chrome/WebKit timestamp (microseconds since 1601-01-01) to ISO UTC."""
    if not chrome_ts or chrome_ts < 0:
        return ""
    try:
        dt = CHROME_EPOCH + timedelta(microseconds=chrome_ts)
        return dt.isoformat() + "Z"
    except (OverflowError, ValueError):
        return ""


def firefox_time_to_utc(ff_ts: int) -> str:
    """Convert Firefox timestamp (microseconds since Unix epoch) to ISO UTC."""
    if not ff_ts or ff_ts < 0:
        return ""
    try:
        dt = UNIX_EPOCH + timedelta(microseconds=ff_ts)
        return dt.isoformat() + "Z"
    except (OverflowError, ValueError):
        return ""


def extract_chrome_history(db_path: str, limit: int = 5000) -> List[dict]:
    """Extract browsing history from Chrome/Edge History database."""
    if not os.path.exists(db_path):
        logger.warning("Chrome History DB not found: %s", db_path)
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT urls.url, urls.title, urls.last_visit_time, urls.visit_count, urls.typed_count
        FROM urls ORDER BY urls.last_visit_time DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    results = []
    for url, title, last_visit, visit_count, typed_count in rows:
        results.append({
            "url": url, "title": title or "",
            "last_visit": chrome_time_to_utc(last_visit),
            "visit_count": visit_count, "typed_count": typed_count,
        })
    logger.info("Extracted %d Chrome history entries from %s", len(results), db_path)
    return results


def extract_chrome_downloads(db_path: str, limit: int = 1000) -> List[dict]:
    """Extract downloads from Chrome/Edge History database."""
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT current_path, tab_url, total_bytes, start_time, end_time, mime_type, danger_type
        FROM downloads ORDER BY start_time DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "path": r[0], "source_url": r[1], "size_bytes": r[2],
        "start_time": chrome_time_to_utc(r[3]), "end_time": chrome_time_to_utc(r[4]),
        "mime_type": r[5], "danger_type": r[6],
    } for r in rows]


def extract_chrome_cookies(db_path: str, limit: int = 5000) -> List[dict]:
    """Extract cookies from Chrome Cookies database."""
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT host_key, name, path, creation_utc, last_access_utc, is_secure, is_httponly
        FROM cookies ORDER BY last_access_utc DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "host": r[0], "name": r[1], "path": r[2],
        "created": chrome_time_to_utc(r[3]), "last_access": chrome_time_to_utc(r[4]),
        "secure": bool(r[5]), "httponly": bool(r[6]),
    } for r in rows]


def extract_firefox_history(db_path: str, limit: int = 5000) -> List[dict]:
    """Extract browsing history from Firefox places.sqlite."""
    if not os.path.exists(db_path):
        logger.warning("Firefox places.sqlite not found: %s", db_path)
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date,
               moz_places.visit_count, moz_historyvisits.visit_type
        FROM moz_places
        JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
        ORDER BY moz_historyvisits.visit_date DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "url": r[0], "title": r[1] or "",
        "visit_date": firefox_time_to_utc(r[2]),
        "visit_count": r[3], "visit_type": r[4],
    } for r in rows]


def extract_firefox_cookies(db_path: str, limit: int = 5000) -> List[dict]:
    """Extract cookies from Firefox cookies.sqlite."""
    if not os.path.exists(db_path):
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT host, name, path, creationTime, lastAccessed, isSecure, isHttpOnly
        FROM moz_cookies ORDER BY lastAccessed DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "host": r[0], "name": r[1], "path": r[2],
        "created": firefox_time_to_utc(r[3]), "last_access": firefox_time_to_utc(r[4]),
        "secure": bool(r[5]), "httponly": bool(r[6]),
    } for r in rows]


def export_to_csv(data: List[dict], output_path: str) -> None:
    """Export extracted data to CSV."""
    if not data:
        return
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    logger.info("Exported %d rows to %s", len(data), output_path)


def generate_report(chrome_dir: str = "", firefox_dir: str = "",
                     output_dir: str = ".") -> dict:
    """Generate comprehensive browser forensics report."""
    report = {"analysis_date": datetime.utcnow().isoformat(), "browsers": {}}

    if chrome_dir and os.path.isdir(chrome_dir):
        history = extract_chrome_history(os.path.join(chrome_dir, "History"))
        downloads = extract_chrome_downloads(os.path.join(chrome_dir, "History"))
        cookies = extract_chrome_cookies(os.path.join(chrome_dir, "Cookies"))
        report["browsers"]["chrome"] = {
            "history_count": len(history), "download_count": len(downloads),
            "cookie_count": len(cookies),
        }
        export_to_csv(history, os.path.join(output_dir, "chrome_history.csv"))
        export_to_csv(downloads, os.path.join(output_dir, "chrome_downloads.csv"))

    if firefox_dir and os.path.isdir(firefox_dir):
        history = extract_firefox_history(os.path.join(firefox_dir, "places.sqlite"))
        cookies = extract_firefox_cookies(os.path.join(firefox_dir, "cookies.sqlite"))
        report["browsers"]["firefox"] = {
            "history_count": len(history), "cookie_count": len(cookies),
        }
        export_to_csv(history, os.path.join(output_dir, "firefox_history.csv"))

    return report


def main():
    parser = argparse.ArgumentParser(description="Browser History Extraction Agent")
    parser.add_argument("--chrome-dir", default="", help="Path to Chrome/Edge User Data/Default")
    parser.add_argument("--firefox-dir", default="", help="Path to Firefox profile directory")
    parser.add_argument("--output-dir", default=".", help="Output directory for CSVs and report")
    parser.add_argument("--output", default="browser_report.json")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    report = generate_report(args.chrome_dir, args.firefox_dir, args.output_dir)
    with open(os.path.join(args.output_dir, args.output), "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
