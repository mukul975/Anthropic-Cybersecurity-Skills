#!/usr/bin/env python3
"""Vulnerability Exception Tracking System.

Manages vulnerability exception requests, approvals, expiration tracking,
and compensating controls documentation.
"""

import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

DB_PATH = os.environ.get("EXCEPTION_DB_PATH", "vulnerability_exceptions.db")


def init_db(db_path=DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_exceptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            asset_hostname TEXT,
            severity TEXT,
            cvss_score REAL,
            category TEXT NOT NULL,
            justification TEXT NOT NULL,
            compensating_controls TEXT,
            status TEXT DEFAULT 'pending',
            requested_by TEXT NOT NULL,
            approved_by TEXT,
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            expires_at TEXT NOT NULL,
            risk_rating TEXT,
            review_notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exception_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exception_id INTEGER,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (exception_id) REFERENCES vulnerability_exceptions(id)
        )
    """)
    conn.commit()
    return conn


def create_exception(conn, data):
    max_days = {
        "remediation_delay": 30,
        "no_fix": 90,
        "business_critical": 60,
        "false_positive": 365,
        "compensating_control": 180,
    }
    category = data.get("category", "remediation_delay")
    expires = data.get("expires_at")
    if expires:
        exp_date = datetime.fromisoformat(expires)
        max_exp = datetime.now(timezone.utc) + timedelta(days=max_days.get(category, 30))
        if exp_date.replace(tzinfo=timezone.utc) > max_exp:
            print(f"[-] Expiration exceeds maximum {max_days[category]} days for {category}")
            return None

    cursor = conn.execute(
        """INSERT INTO vulnerability_exceptions
           (cve_id, finding_id, asset_hostname, severity, cvss_score, category,
            justification, compensating_controls, requested_by, expires_at, risk_rating)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["cve_id"], data["finding_id"], data.get("asset_hostname", ""),
            data.get("severity", ""), data.get("cvss_score", 0),
            category, data["justification"],
            json.dumps(data.get("compensating_controls", [])),
            data["requestor_email"], expires, data.get("risk_rating", "medium"),
        ),
    )
    exc_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO exception_audit_log (exception_id, action, actor, details) VALUES (?, ?, ?, ?)",
        (exc_id, "created", data["requestor_email"], f"Exception request for {data['cve_id']}"),
    )
    conn.commit()
    print(f"[+] Exception created: ID {exc_id} for {data['cve_id']}")
    return exc_id


def approve_exception(conn, exc_id, approver_email, notes=""):
    conn.execute(
        """UPDATE vulnerability_exceptions
           SET status = 'approved', approved_by = ?, approved_at = ?, review_notes = ?
           WHERE id = ?""",
        (approver_email, datetime.now(timezone.utc).isoformat(), notes, exc_id),
    )
    conn.execute(
        "INSERT INTO exception_audit_log (exception_id, action, actor, details) VALUES (?, ?, ?, ?)",
        (exc_id, "approved", approver_email, notes),
    )
    conn.commit()
    print(f"[+] Exception {exc_id} approved by {approver_email}")


def reject_exception(conn, exc_id, reviewer_email, reason):
    conn.execute(
        "UPDATE vulnerability_exceptions SET status = 'rejected', review_notes = ? WHERE id = ?",
        (reason, exc_id),
    )
    conn.execute(
        "INSERT INTO exception_audit_log (exception_id, action, actor, details) VALUES (?, ?, ?, ?)",
        (exc_id, "rejected", reviewer_email, reason),
    )
    conn.commit()
    print(f"[+] Exception {exc_id} rejected by {reviewer_email}: {reason}")


def check_expirations(conn, slack_webhook=None):
    now = datetime.now(timezone.utc).isoformat()
    warn_date = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()

    expiring_soon = conn.execute(
        "SELECT * FROM vulnerability_exceptions WHERE status = 'approved' AND expires_at BETWEEN ? AND ?",
        (now, warn_date),
    ).fetchall()

    expired = conn.execute(
        "SELECT * FROM vulnerability_exceptions WHERE status = 'approved' AND expires_at < ?",
        (now,),
    ).fetchall()

    columns = [d[0] for d in conn.execute("SELECT * FROM vulnerability_exceptions LIMIT 0").description]

    for row in expired:
        record = dict(zip(columns, row))
        conn.execute("UPDATE vulnerability_exceptions SET status = 'expired' WHERE id = ?", (record["id"],))
        conn.execute(
            "INSERT INTO exception_audit_log (exception_id, action, actor, details) VALUES (?, ?, ?, ?)",
            (record["id"], "expired", "system", f"Exception expired on {record['expires_at']}"),
        )
        print(f"[!] Exception {record['id']} ({record['cve_id']}) EXPIRED")

    conn.commit()

    print(f"\n[*] Expiration Check Results:")
    print(f"    Expired: {len(expired)}")
    print(f"    Expiring within 14 days: {len(expiring_soon)}")

    if slack_webhook and (expired or expiring_soon):
        payload = {
            "text": f"Vulnerability Exception Alert: {len(expired)} expired, {len(expiring_soon)} expiring soon"
        }
        requests.post(slack_webhook, json=payload, timeout=10)

    return {"expired": len(expired), "expiring_soon": len(expiring_soon)}


def generate_report(conn, output_path):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {},
        "exceptions": [],
    }
    cursor = conn.execute(
        """SELECT status, COUNT(*) as count FROM vulnerability_exceptions GROUP BY status"""
    )
    for row in cursor.fetchall():
        report["summary"][row[0]] = row[1]

    cursor = conn.execute(
        "SELECT * FROM vulnerability_exceptions ORDER BY CASE status "
        "WHEN 'expired' THEN 1 WHEN 'pending' THEN 2 WHEN 'approved' THEN 3 ELSE 4 END"
    )
    columns = [d[0] for d in cursor.description]
    for row in cursor.fetchall():
        report["exceptions"].append(dict(zip(columns, row)))

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Exception report written to {output_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Exception Tracking System")
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--create", help="JSON file with exception request")
    parser.add_argument("--approve", type=int, help="Exception ID to approve")
    parser.add_argument("--reject", type=int, help="Exception ID to reject")
    parser.add_argument("--approver", help="Approver email")
    parser.add_argument("--reason", help="Rejection reason")
    parser.add_argument("--notes", default="", help="Approval notes")
    parser.add_argument("--check-expirations", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--output", default="exception_report.json")
    parser.add_argument("--slack-webhook", help="Slack webhook for notifications")
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.create:
        with open(args.create, "r") as f:
            data = json.load(f)
        create_exception(conn, data)
    elif args.approve and args.approver:
        approve_exception(conn, args.approve, args.approver, args.notes)
    elif args.reject and args.approver and args.reason:
        reject_exception(conn, args.reject, args.approver, args.reason)
    elif args.check_expirations:
        check_expirations(conn, args.slack_webhook)
    elif args.report:
        generate_report(conn, args.output)
    else:
        parser.print_help()

    conn.close()


if __name__ == "__main__":
    main()
