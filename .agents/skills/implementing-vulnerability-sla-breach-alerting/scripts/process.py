#!/usr/bin/env python3
"""Vulnerability SLA Breach Alerting System.

Tracks vulnerability remediation timelines, detects SLA breaches,
and dispatches notifications through multiple channels.
"""

import argparse
import csv
import json
import os
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import yaml

DB_PATH = os.environ.get("SLA_DB_PATH", "vulnerability_sla.db")

SLA_TIERS = {
    "critical": {"cvss_min": 9.0, "cvss_max": 10.0, "days": 2},
    "high": {"cvss_min": 7.0, "cvss_max": 8.9, "days": 15},
    "medium": {"cvss_min": 4.0, "cvss_max": 6.9, "days": 60},
    "low": {"cvss_min": 0.1, "cvss_max": 3.9, "days": 90},
}


def init_db(db_path=DB_PATH):
    """Initialize SQLite database for SLA tracking."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_sla (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            asset_hostname TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            discovered_at TEXT NOT NULL,
            sla_deadline TEXT NOT NULL,
            remediated_at TEXT,
            status TEXT DEFAULT 'open',
            owner_email TEXT,
            escalation_level INTEGER DEFAULT 0,
            last_alert_sent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def get_severity_tier(cvss_score):
    """Map CVSS score to severity tier."""
    for tier_name, tier in SLA_TIERS.items():
        if tier["cvss_min"] <= cvss_score <= tier["cvss_max"]:
            return tier_name, tier["days"]
    return "low", 90


def import_findings(conn, csv_path):
    """Import vulnerability findings from CSV and assign SLA deadlines."""
    imported = 0
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("cve_id", "").strip()
            cvss = float(row.get("cvss_score", 0))
            if not cve_id or cvss == 0:
                continue
            discovered = row.get("discovered_at", datetime.now(timezone.utc).isoformat())
            discovered_dt = datetime.fromisoformat(discovered.replace("Z", "+00:00"))
            severity, sla_days = get_severity_tier(cvss)
            deadline = discovered_dt + timedelta(days=sla_days)

            conn.execute(
                """INSERT INTO vulnerability_sla
                   (cve_id, finding_id, asset_hostname, severity, cvss_score,
                    discovered_at, sla_deadline, owner_email, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
                (
                    cve_id,
                    row.get("finding_id", f"{cve_id}_{row.get('host', 'unknown')}"),
                    row.get("host", "unknown"),
                    severity,
                    cvss,
                    discovered_dt.isoformat(),
                    deadline.isoformat(),
                    row.get("owner_email", ""),
                ),
            )
            imported += 1
    conn.commit()
    print(f"[+] Imported {imported} findings with SLA deadlines")
    return imported


def check_sla_breaches(conn):
    """Check all open findings for SLA status and return categorized results."""
    now = datetime.now(timezone.utc)
    cursor = conn.execute(
        "SELECT * FROM vulnerability_sla WHERE status = 'open'"
    )
    columns = [d[0] for d in cursor.description]
    breached = []
    approaching = []
    within_sla = []

    for row in cursor.fetchall():
        record = dict(zip(columns, row))
        deadline = datetime.fromisoformat(record["sla_deadline"])
        discovered = datetime.fromisoformat(record["discovered_at"])
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        if discovered.tzinfo is None:
            discovered = discovered.replace(tzinfo=timezone.utc)

        if now > deadline:
            overdue_days = (now - deadline).days
            record["sla_status"] = f"breached_{overdue_days}d_overdue"
            record["overdue_days"] = overdue_days
            breached.append(record)
        else:
            total_window = (deadline - discovered).total_seconds()
            elapsed = (now - discovered).total_seconds()
            pct = (elapsed / total_window * 100) if total_window > 0 else 0
            if pct >= 80:
                record["sla_status"] = "approaching_breach"
                record["pct_elapsed"] = round(pct, 1)
                approaching.append(record)
            else:
                record["sla_status"] = "within_sla"
                record["pct_elapsed"] = round(pct, 1)
                within_sla.append(record)

    return {"breached": breached, "approaching": approaching, "within_sla": within_sla}


def send_slack_notification(webhook_url, findings, alert_type):
    """Send SLA alert to Slack channel."""
    if not webhook_url or not findings:
        return
    color_map = {"breached": "#FF0000", "approaching": "#FFA500", "within_sla": "#36A64F"}
    for finding in findings[:10]:
        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert_type, "#808080"),
                    "title": f"SLA {alert_type.upper()}: {finding['cve_id']}",
                    "fields": [
                        {"title": "Severity", "value": finding["severity"], "short": True},
                        {"title": "CVSS", "value": str(finding["cvss_score"]), "short": True},
                        {"title": "Asset", "value": finding["asset_hostname"], "short": True},
                        {"title": "Deadline", "value": finding["sla_deadline"][:16], "short": True},
                        {"title": "Owner", "value": finding.get("owner_email", "Unassigned"), "short": True},
                        {"title": "Status", "value": finding["sla_status"], "short": True},
                    ],
                }
            ]
        }
        try:
            requests.post(webhook_url, json=payload, timeout=10)
        except requests.RequestException as e:
            print(f"[-] Slack notification failed: {e}")


def send_email_notification(smtp_config, findings, alert_type):
    """Send SLA alert via email."""
    if not smtp_config or not findings:
        return
    recipients = set()
    for f in findings:
        if f.get("owner_email"):
            recipients.add(f["owner_email"])
    if not recipients:
        return

    body_lines = [f"Vulnerability SLA {alert_type.upper()} Report", "=" * 50, ""]
    for f in findings:
        body_lines.extend([
            f"CVE: {f['cve_id']}",
            f"Severity: {f['severity']} (CVSS {f['cvss_score']})",
            f"Asset: {f['asset_hostname']}",
            f"Deadline: {f['sla_deadline'][:16]}",
            f"Status: {f['sla_status']}",
            "-" * 40,
        ])

    msg = MIMEMultipart()
    msg["Subject"] = f"[VULN SLA {alert_type.upper()}] {len(findings)} findings require attention"
    msg["From"] = smtp_config.get("from_address", "vuln-alerts@company.com")
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText("\n".join(body_lines), "plain"))

    try:
        with smtplib.SMTP(smtp_config["host"], smtp_config.get("port", 587)) as server:
            server.starttls()
            if smtp_config.get("username"):
                server.login(smtp_config["username"], smtp_config["password"])
            server.send_message(msg)
        print(f"[+] Email sent to {len(recipients)} recipients")
    except Exception as e:
        print(f"[-] Email notification failed: {e}")


def generate_compliance_report(conn, output_path, period_days=30):
    """Generate SLA compliance report."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=period_days)).isoformat()
    cursor = conn.execute(
        """SELECT severity,
                  COUNT(*) as total,
                  SUM(CASE WHEN remediated_at IS NOT NULL
                       AND remediated_at <= sla_deadline THEN 1 ELSE 0 END) as within_sla,
                  SUM(CASE WHEN remediated_at IS NOT NULL
                       AND remediated_at > sla_deadline THEN 1 ELSE 0 END) as breached_remediated,
                  SUM(CASE WHEN status = 'open'
                       AND datetime('now') > sla_deadline THEN 1 ELSE 0 END) as currently_overdue
           FROM vulnerability_sla
           WHERE discovered_at >= ?
           GROUP BY severity
           ORDER BY CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4 END""",
        (cutoff,),
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period_days": period_days,
        "tiers": [],
    }
    total_findings = 0
    total_compliant = 0
    for row in cursor.fetchall():
        severity, total, within_sla, breached_remediated, currently_overdue = row
        compliance_rate = (within_sla / total * 100) if total > 0 else 0
        report["tiers"].append({
            "severity": severity,
            "total": total,
            "within_sla": within_sla,
            "breached_remediated": breached_remediated,
            "currently_overdue": currently_overdue,
            "compliance_rate": round(compliance_rate, 1),
        })
        total_findings += total
        total_compliant += within_sla

    report["overall_compliance"] = round(
        (total_compliant / total_findings * 100) if total_findings > 0 else 0, 1
    )
    report["total_findings"] = total_findings

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Compliance report written to {output_path}")
    print(f"    Overall SLA Compliance: {report['overall_compliance']}%")
    return report


def main():
    parser = argparse.ArgumentParser(description="Vulnerability SLA Breach Alerting System")
    parser.add_argument("--import-findings", help="Import findings from CSV")
    parser.add_argument("--check-sla", action="store_true", help="Check for SLA breaches")
    parser.add_argument("--report", action="store_true", help="Generate compliance report")
    parser.add_argument("--output", default="sla_compliance_report.json", help="Report output path")
    parser.add_argument("--period", type=int, default=30, help="Report period in days")
    parser.add_argument("--slack-webhook", help="Slack webhook URL for notifications")
    parser.add_argument("--db", default=DB_PATH, help="Database path")
    args = parser.parse_args()

    conn = init_db(args.db)

    if args.import_findings:
        import_findings(conn, args.import_findings)

    if args.check_sla:
        results = check_sla_breaches(conn)
        print(f"\n[*] SLA Check Results:")
        print(f"    Breached: {len(results['breached'])}")
        print(f"    Approaching: {len(results['approaching'])}")
        print(f"    Within SLA: {len(results['within_sla'])}")

        if args.slack_webhook:
            if results["breached"]:
                send_slack_notification(args.slack_webhook, results["breached"], "breached")
            if results["approaching"]:
                send_slack_notification(args.slack_webhook, results["approaching"], "approaching")

    if args.report:
        generate_compliance_report(conn, args.output, args.period)

    conn.close()


if __name__ == "__main__":
    main()
