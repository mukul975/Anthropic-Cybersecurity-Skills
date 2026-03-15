#!/usr/bin/env python3
"""Agent for performing mobile device forensics.

Analyzes mobile device extractions by parsing SQLite databases
for messages, call logs, contacts, and location data from
iOS and Android file system extractions.
"""

import sqlite3
import json
import sys
import csv
import os
from pathlib import Path
from datetime import datetime


class MobileForensicsAgent:
    """Parses mobile device extraction data for forensic analysis."""

    def __init__(self, extraction_dir, output_dir, platform="android"):
        self.extraction_dir = Path(extraction_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.platform = platform

    def _query_db(self, db_path, query, params=None):
        """Execute a query against a SQLite database."""
        if not Path(db_path).exists():
            return []
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params or [])
            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return results
        except sqlite3.Error as e:
            return [{"error": str(e), "db": str(db_path)}]

    def extract_sms_android(self):
        """Extract SMS/MMS messages from Android mmssms.db."""
        db_path = self.extraction_dir / "data/data/com.android.providers.telephony/databases/mmssms.db"
        return self._query_db(str(db_path), """
            SELECT address, body, type,
                   datetime(date/1000, 'unixepoch') AS msg_time,
                   read, seen
            FROM sms ORDER BY date DESC LIMIT 5000
        """)

    def extract_sms_ios(self):
        """Extract iMessage/SMS from iOS sms.db."""
        db_path = self.extraction_dir / "HomeDomain/Library/SMS/sms.db"
        return self._query_db(str(db_path), """
            SELECT h.id AS phone_number,
                   CASE WHEN m.is_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
                   m.text,
                   datetime(m.date/1000000000 + 978307200, 'unixepoch') AS msg_time,
                   m.service
            FROM message m
            JOIN handle h ON m.handle_id = h.ROWID
            ORDER BY m.date DESC LIMIT 5000
        """)

    def extract_call_log_android(self):
        """Extract call logs from Android contacts2.db."""
        db_path = self.extraction_dir / "data/data/com.android.providers.contacts/databases/calllog.db"
        return self._query_db(str(db_path), """
            SELECT number, name,
                   CASE type WHEN 1 THEN 'INCOMING' WHEN 2 THEN 'OUTGOING'
                        WHEN 3 THEN 'MISSED' ELSE 'UNKNOWN' END AS call_type,
                   duration,
                   datetime(date/1000, 'unixepoch') AS call_time
            FROM calls ORDER BY date DESC LIMIT 2000
        """)

    def extract_contacts_android(self):
        """Extract contacts from Android contacts database."""
        db_path = self.extraction_dir / "data/data/com.android.providers.contacts/databases/contacts2.db"
        return self._query_db(str(db_path), """
            SELECT display_name, data1 AS phone_or_email, mimetype
            FROM raw_contacts rc
            JOIN data d ON rc._id = d.raw_contact_id
            WHERE mimetype IN (
                'vnd.android.cursor.item/phone_v2',
                'vnd.android.cursor.item/email_v2'
            ) ORDER BY display_name LIMIT 5000
        """)

    def extract_whatsapp_messages(self):
        """Extract WhatsApp messages from msgstore.db."""
        db_path = self.extraction_dir / "data/data/com.whatsapp/databases/msgstore.db"
        return self._query_db(str(db_path), """
            SELECT key_remote_jid AS contact,
                   CASE WHEN key_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
                   data AS message_text,
                   datetime(timestamp/1000, 'unixepoch') AS msg_time,
                   media_mime_type,
                   media_size
            FROM messages
            WHERE data IS NOT NULL
            ORDER BY timestamp DESC LIMIT 5000
        """)

    def extract_browser_history_android(self):
        """Extract Chrome browser history from Android."""
        db_path = self.extraction_dir / "data/data/com.android.chrome/app_chrome/Default/History"
        return self._query_db(str(db_path), """
            SELECT url, title, visit_count,
                   datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS visit_time
            FROM urls ORDER BY last_visit_time DESC LIMIT 2000
        """)

    def extract_wifi_history(self):
        """Extract saved WiFi networks."""
        if self.platform == "android":
            wifi_conf = self.extraction_dir / "data/misc/wifi/WifiConfigStore.xml"
            if wifi_conf.exists():
                content = wifi_conf.read_text(errors="ignore")
                import re
                ssids = re.findall(r'"SSID"[^>]*>([^<]+)', content)
                return [{"ssid": s} for s in ssids]
        return []

    def extract_installed_apps(self):
        """List installed applications."""
        apps = []
        if self.platform == "android":
            app_dir = self.extraction_dir / "data/data"
            if app_dir.exists():
                for pkg in sorted(app_dir.iterdir()):
                    if pkg.is_dir():
                        apps.append({
                            "package": pkg.name,
                            "has_databases": (pkg / "databases").exists(),
                        })
        return apps

    def search_keyword(self, keyword):
        """Search across extracted databases for a keyword."""
        hits = []
        for db_file in self.extraction_dir.rglob("*.db"):
            try:
                conn = sqlite3.connect(str(db_file))
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                for table in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{table}] LIMIT 1")
                        columns = [desc[0] for desc in cursor.description]
                        for col in columns:
                            cursor.execute(
                                f"SELECT [{col}] FROM [{table}] WHERE [{col}] LIKE ?",
                                [f"%{keyword}%"]
                            )
                            matches = cursor.fetchall()
                            if matches:
                                hits.append({
                                    "database": str(db_file.relative_to(self.extraction_dir)),
                                    "table": table,
                                    "column": col,
                                    "match_count": len(matches),
                                })
                    except sqlite3.Error:
                        continue
                conn.close()
            except sqlite3.Error:
                continue
        return hits

    def generate_report(self):
        """Generate comprehensive mobile forensics report."""
        report = {
            "extraction_dir": str(self.extraction_dir),
            "platform": self.platform,
            "report_date": datetime.utcnow().isoformat(),
        }

        if self.platform == "android":
            report["sms"] = {"count": len(self.extract_sms_android())}
            report["call_log"] = {"count": len(self.extract_call_log_android())}
            report["contacts"] = {"count": len(self.extract_contacts_android())}
            report["whatsapp"] = {"count": len(self.extract_whatsapp_messages())}
            report["browser_history"] = {"count": len(self.extract_browser_history_android())}
        elif self.platform == "ios":
            report["imessage_sms"] = {"count": len(self.extract_sms_ios())}

        report["wifi_networks"] = self.extract_wifi_history()
        report["installed_apps"] = {"count": len(self.extract_installed_apps())}

        report_path = self.output_dir / "mobile_forensics_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <extraction_dir> <output_dir> [android|ios]")
        sys.exit(1)

    extraction_dir = sys.argv[1]
    output_dir = sys.argv[2]
    platform = sys.argv[3] if len(sys.argv) > 3 else "android"

    agent = MobileForensicsAgent(extraction_dir, output_dir, platform)
    agent.generate_report()


if __name__ == "__main__":
    main()
