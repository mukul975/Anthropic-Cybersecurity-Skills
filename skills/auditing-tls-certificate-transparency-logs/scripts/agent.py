#!/usr/bin/env python3
"""CT Log Monitoring Agent - Monitors Certificate Transparency logs for unauthorized
certificate issuance, subdomain discovery, and certificate alerting.

For authorized security monitoring and defensive operations only.
"""

import argparse
import json
import logging
import smtplib
import socket
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

CRTSH_BASE = "https://crt.sh"
CRTSH_JSON = f"{CRTSH_BASE}/?output=json"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 2


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database for certificate tracking."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY,
            crtsh_id INTEGER UNIQUE,
            domain TEXT NOT NULL,
            common_name TEXT,
            name_value TEXT,
            issuer_name TEXT,
            issuer_ca_id INTEGER,
            not_before TEXT,
            not_after TEXT,
            serial_number TEXT,
            fingerprint_sha256 TEXT,
            entry_timestamp TEXT,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            is_precert INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY,
            subdomain TEXT UNIQUE NOT NULL,
            parent_domain TEXT NOT NULL,
            first_seen TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen TEXT,
            dns_resolved INTEGER DEFAULT 0,
            resolved_ip TEXT,
            cname_target TEXT
        );

        CREATE TABLE IF NOT EXISTS authorized_cas (
            id INTEGER PRIMARY KEY,
            ca_name TEXT UNIQUE NOT NULL,
            issuer_ca_id INTEGER,
            added_on TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            domain TEXT,
            details TEXT,
            certificate_id INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            acknowledged INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_certs_domain ON certificates(domain);
        CREATE INDEX IF NOT EXISTS idx_certs_issuer ON certificates(issuer_ca_id);
        CREATE INDEX IF NOT EXISTS idx_subs_parent ON subdomains(parent_domain);
        CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
    """)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# crt.sh API interaction
# ---------------------------------------------------------------------------

def query_crtsh(domain: str, exclude_expired: bool = True, timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """Query crt.sh JSON API for certificates matching domain pattern.

    Args:
        domain: Domain pattern, e.g. '%.example.com' for wildcard search.
        exclude_expired: If True, exclude expired certificates from results.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of certificate records from crt.sh.
    """
    params = {"q": domain, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"

    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.get(
                CRTSH_BASE,
                params=params,
                headers={"User-Agent": "CT-Monitor-Agent/1.0 (security-monitoring)"},
                timeout=timeout,
            )
            if resp.status_code == 429:
                wait = RETRY_BACKOFF ** (attempt + 1)
                logger.warning("Rate limited by crt.sh, waiting %ds before retry", wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json()
            logger.info("crt.sh returned %d certificates for %s", len(data), domain)
            return data
        except requests.exceptions.JSONDecodeError:
            logger.warning("Empty or invalid JSON response from crt.sh for %s", domain)
            return []
        except requests.exceptions.RequestException as exc:
            wait = RETRY_BACKOFF ** (attempt + 1)
            logger.warning("crt.sh query failed (attempt %d/%d): %s", attempt + 1, MAX_RETRIES, exc)
            if attempt < MAX_RETRIES - 1:
                time.sleep(wait)
    return []


def get_certificate_detail(crtsh_id: int, timeout: int = DEFAULT_TIMEOUT) -> dict | None:
    """Fetch detailed certificate information from crt.sh by ID."""
    try:
        resp = requests.get(
            f"{CRTSH_BASE}/?d={crtsh_id}",
            headers={"User-Agent": "CT-Monitor-Agent/1.0"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return {"crtsh_id": crtsh_id, "pem": resp.text}
    except requests.exceptions.RequestException as exc:
        logger.warning("Failed to fetch certificate %d: %s", crtsh_id, exc)
        return None


# ---------------------------------------------------------------------------
# Certificate processing
# ---------------------------------------------------------------------------

def extract_subdomains_from_names(name_value: str) -> list[str]:
    """Extract individual subdomain entries from a crt.sh name_value field.

    The name_value field can contain multiple DNS names separated by newlines.
    """
    if not name_value:
        return []
    names = []
    for line in name_value.strip().split("\n"):
        name = line.strip().lower().rstrip(".")
        if name and "*" not in name:
            names.append(name)
        elif name and name.startswith("*."):
            # Record the wildcard parent
            names.append(name[2:])
    return list(set(names))


def store_certificates(conn: sqlite3.Connection, certs: list[dict], monitored_domain: str) -> list[dict]:
    """Store certificates in database, return list of newly discovered ones."""
    new_certs = []
    cursor = conn.cursor()
    for cert in certs:
        crtsh_id = cert.get("id")
        if not crtsh_id:
            continue
        cursor.execute("SELECT 1 FROM certificates WHERE crtsh_id = ?", (crtsh_id,))
        if cursor.fetchone():
            continue
        name_value = cert.get("name_value", "")
        issuer_name = cert.get("issuer_name", "")
        entry_ts = cert.get("entry_timestamp", "")
        not_before = cert.get("not_before", "")
        not_after = cert.get("not_after", "")
        common_name = cert.get("common_name", "")
        serial = cert.get("serial_number", "")
        issuer_ca_id = cert.get("issuer_ca_id")

        is_precert = 1 if (entry_ts and "precert" in entry_ts.lower()) else 0

        cursor.execute(
            """INSERT OR IGNORE INTO certificates
               (crtsh_id, domain, common_name, name_value, issuer_name,
                issuer_ca_id, not_before, not_after, serial_number,
                entry_timestamp, is_precert)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (crtsh_id, monitored_domain, common_name, name_value,
             issuer_name, issuer_ca_id, not_before, not_after, serial,
             entry_ts, is_precert),
        )
        new_certs.append(cert)
    conn.commit()
    return new_certs


def discover_subdomains(conn: sqlite3.Connection, certs: list[dict], parent_domain: str) -> list[str]:
    """Extract and store unique subdomains from certificate name_value fields."""
    new_subdomains = []
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    for cert in certs:
        names = extract_subdomains_from_names(cert.get("name_value", ""))
        for name in names:
            if not name.endswith(parent_domain):
                continue
            cursor.execute("SELECT 1 FROM subdomains WHERE subdomain = ?", (name,))
            if cursor.fetchone():
                cursor.execute(
                    "UPDATE subdomains SET last_seen = ? WHERE subdomain = ?",
                    (now, name),
                )
            else:
                cursor.execute(
                    """INSERT INTO subdomains (subdomain, parent_domain, first_seen, last_seen)
                       VALUES (?, ?, ?, ?)""",
                    (name, parent_domain, now, now),
                )
                new_subdomains.append(name)
    conn.commit()
    return new_subdomains


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_subdomain(subdomain: str, timeout: float = 5.0) -> dict:
    """Resolve a subdomain to IP addresses and CNAME targets."""
    result = {"subdomain": subdomain, "resolved": False, "ips": [], "cname": None}
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        # Check CNAME first
        try:
            import dns.resolver
            answers = dns.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                result["cname"] = str(rdata.target).rstrip(".")
        except Exception:
            pass

        # A record resolution
        ips = socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = set()
        for family, _type, _proto, _canonname, sockaddr in ips:
            ip = sockaddr[0]
            if ip not in seen:
                result["ips"].append(ip)
                seen.add(ip)
        result["resolved"] = len(result["ips"]) > 0
    except socket.gaierror:
        pass
    except Exception as exc:
        logger.debug("DNS resolution failed for %s: %s", subdomain, exc)
    finally:
        socket.setdefaulttimeout(old_timeout)
    return result


def resolve_all_subdomains(conn: sqlite3.Connection, parent_domain: str) -> list[dict]:
    """Resolve all unresolved subdomains for a parent domain."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT subdomain FROM subdomains WHERE parent_domain = ? AND dns_resolved = 0",
        (parent_domain,),
    )
    rows = cursor.fetchall()
    results = []
    for (subdomain,) in rows:
        dns_result = resolve_subdomain(subdomain)
        results.append(dns_result)
        cursor.execute(
            """UPDATE subdomains SET dns_resolved = 1, resolved_ip = ?, cname_target = ?
               WHERE subdomain = ?""",
            (
                ",".join(dns_result["ips"]) if dns_result["ips"] else None,
                dns_result["cname"],
                subdomain,
            ),
        )
    conn.commit()
    logger.info("Resolved %d subdomains for %s", len(results), parent_domain)
    return results


# ---------------------------------------------------------------------------
# Alerting engine
# ---------------------------------------------------------------------------

def check_unauthorized_ca(conn: sqlite3.Connection, new_certs: list[dict]) -> list[dict]:
    """Check if any new certificates were issued by unauthorized CAs."""
    cursor = conn.cursor()
    cursor.execute("SELECT ca_name, issuer_ca_id FROM authorized_cas")
    authorized = {row[1]: row[0] for row in cursor.fetchall()}

    if not authorized:
        logger.info("No authorized CAs configured; skipping CA validation")
        return []

    alerts = []
    for cert in new_certs:
        ca_id = cert.get("issuer_ca_id")
        if ca_id and ca_id not in authorized:
            alert = {
                "alert_type": "unauthorized_ca",
                "severity": "critical",
                "domain": cert.get("common_name", ""),
                "details": json.dumps({
                    "issuer": cert.get("issuer_name", ""),
                    "issuer_ca_id": ca_id,
                    "common_name": cert.get("common_name", ""),
                    "name_value": cert.get("name_value", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "crtsh_id": cert.get("id"),
                }),
                "certificate_id": cert.get("id"),
            }
            cursor.execute(
                """INSERT INTO alerts (alert_type, severity, domain, details, certificate_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (alert["alert_type"], alert["severity"], alert["domain"],
                 alert["details"], alert["certificate_id"]),
            )
            alerts.append(alert)
            logger.warning(
                "ALERT: Unauthorized CA '%s' issued cert for %s",
                cert.get("issuer_name"), cert.get("common_name"),
            )
    conn.commit()
    return alerts


def check_new_subdomain_alerts(conn: sqlite3.Connection, new_subdomains: list[str], parent_domain: str) -> list[dict]:
    """Generate alerts for newly discovered subdomains."""
    alerts = []
    cursor = conn.cursor()
    for sub in new_subdomains:
        alert = {
            "alert_type": "new_subdomain",
            "severity": "medium",
            "domain": sub,
            "details": json.dumps({
                "subdomain": sub,
                "parent_domain": parent_domain,
                "discovered_via": "certificate_transparency",
            }),
        }
        cursor.execute(
            """INSERT INTO alerts (alert_type, severity, domain, details)
               VALUES (?, ?, ?, ?)""",
            (alert["alert_type"], alert["severity"], alert["domain"], alert["details"]),
        )
        alerts.append(alert)
        logger.info("ALERT: New subdomain discovered: %s", sub)
    conn.commit()
    return alerts


def check_wildcard_certs(conn: sqlite3.Connection, new_certs: list[dict]) -> list[dict]:
    """Alert on new wildcard certificate issuances."""
    alerts = []
    cursor = conn.cursor()
    for cert in new_certs:
        cn = cert.get("common_name", "")
        nv = cert.get("name_value", "")
        if cn.startswith("*.") or (nv and "*." in nv):
            alert = {
                "alert_type": "wildcard_certificate",
                "severity": "high",
                "domain": cn,
                "details": json.dumps({
                    "common_name": cn,
                    "issuer": cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "crtsh_id": cert.get("id"),
                }),
                "certificate_id": cert.get("id"),
            }
            cursor.execute(
                """INSERT INTO alerts (alert_type, severity, domain, details, certificate_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (alert["alert_type"], alert["severity"], alert["domain"],
                 alert["details"], alert["certificate_id"]),
            )
            alerts.append(alert)
            logger.warning("ALERT: Wildcard certificate issued for %s", cn)
    conn.commit()
    return alerts


def check_short_lived_certs(conn: sqlite3.Connection, new_certs: list[dict], threshold_hours: int = 24) -> list[dict]:
    """Alert on certificates with unusually short validity periods."""
    alerts = []
    cursor = conn.cursor()
    for cert in new_certs:
        not_before = cert.get("not_before", "")
        not_after = cert.get("not_after", "")
        if not not_before or not not_after:
            continue
        try:
            nb = datetime.fromisoformat(not_before.replace("T", " ").split(".")[0])
            na = datetime.fromisoformat(not_after.replace("T", " ").split(".")[0])
            validity_hours = (na - nb).total_seconds() / 3600
            if validity_hours < threshold_hours:
                alert = {
                    "alert_type": "short_lived_certificate",
                    "severity": "high",
                    "domain": cert.get("common_name", ""),
                    "details": json.dumps({
                        "common_name": cert.get("common_name", ""),
                        "validity_hours": round(validity_hours, 2),
                        "not_before": not_before,
                        "not_after": not_after,
                        "issuer": cert.get("issuer_name", ""),
                        "crtsh_id": cert.get("id"),
                    }),
                    "certificate_id": cert.get("id"),
                }
                cursor.execute(
                    """INSERT INTO alerts (alert_type, severity, domain, details, certificate_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (alert["alert_type"], alert["severity"], alert["domain"],
                     alert["details"], alert["certificate_id"]),
                )
                alerts.append(alert)
                logger.warning(
                    "ALERT: Short-lived cert (%dh) for %s",
                    int(validity_hours), cert.get("common_name"),
                )
        except (ValueError, TypeError):
            continue
    conn.commit()
    return alerts


def check_expiring_certs(conn: sqlite3.Connection, domain: str, days_warning: list[int] = None) -> list[dict]:
    """Check for certificates approaching expiration."""
    if days_warning is None:
        days_warning = [30, 14, 7]
    alerts = []
    cursor = conn.cursor()
    now = datetime.now(timezone.utc)
    for days in days_warning:
        threshold = (now + timedelta(days=days)).isoformat()
        cursor.execute(
            """SELECT crtsh_id, common_name, not_after, issuer_name
               FROM certificates
               WHERE domain = ? AND not_after <= ? AND not_after > ?""",
            (domain, threshold, now.isoformat()),
        )
        for row in cursor.fetchall():
            crtsh_id, cn, not_after, issuer = row
            alert = {
                "alert_type": "certificate_expiring",
                "severity": "medium" if days > 7 else "high",
                "domain": cn,
                "details": json.dumps({
                    "common_name": cn,
                    "not_after": not_after,
                    "days_until_expiry": days,
                    "issuer": issuer,
                    "crtsh_id": crtsh_id,
                }),
                "certificate_id": crtsh_id,
            }
            alerts.append(alert)
    return alerts


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------

def generate_typosquat_candidates(domain: str) -> list[str]:
    """Generate domain permutations for typosquat detection.

    Implements omission, insertion, transposition, replacement, and
    bitsquatting techniques on the second-level domain label.
    """
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    label = parts[0]
    suffix = ".".join(parts[1:])
    candidates = set()

    # Omission: remove one character at a time
    for i in range(len(label)):
        c = label[:i] + label[i + 1:]
        if c:
            candidates.add(f"{c}.{suffix}")

    # Transposition: swap adjacent characters
    for i in range(len(label) - 1):
        c = list(label)
        c[i], c[i + 1] = c[i + 1], c[i]
        candidates.add(f"{''.join(c)}.{suffix}")

    # Replacement: replace each char with adjacent keyboard keys
    keyboard_neighbors = {
        "q": "wa", "w": "qeas", "e": "wrds", "r": "etdf", "t": "ryfg",
        "y": "tugh", "u": "yijh", "i": "uokj", "o": "iplk", "p": "ol",
        "a": "qwsz", "s": "wedxza", "d": "erfcxs", "f": "rtgvcd",
        "g": "tyhbvf", "h": "yujnbg", "j": "uikmnh", "k": "ioljm",
        "l": "opk", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
        "b": "vghn", "n": "bhjm", "m": "njk",
    }
    for i, ch in enumerate(label):
        for neighbor in keyboard_neighbors.get(ch.lower(), ""):
            c = label[:i] + neighbor + label[i + 1:]
            candidates.add(f"{c}.{suffix}")

    # Bitsquatting: flip each bit of each character
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped.isalnum():
                c = label[:i] + flipped + label[i + 1:]
                candidates.add(f"{c}.{suffix}")

    candidates.discard(domain)
    return sorted(candidates)


def scan_typosquats(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """Check CT logs for certificates issued to typosquat domains."""
    candidates = generate_typosquat_candidates(domain)
    logger.info("Generated %d typosquat candidates for %s", len(candidates), domain)
    found = []
    for candidate in candidates:
        certs = query_crtsh(candidate, exclude_expired=True, timeout=timeout)
        if certs:
            found.append({
                "typosquat_domain": candidate,
                "original_domain": domain,
                "certificate_count": len(certs),
                "issuers": list({c.get("issuer_name", "") for c in certs}),
                "earliest_cert": min(
                    (c.get("not_before", "") for c in certs if c.get("not_before")),
                    default="",
                ),
            })
            logger.warning(
                "Typosquat found: %s has %d certificates", candidate, len(certs),
            )
        # Rate-limit to avoid hammering crt.sh
        time.sleep(1)
    return found


# ---------------------------------------------------------------------------
# Notification delivery
# ---------------------------------------------------------------------------

def send_email_alert(
    alerts: list[dict],
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    from_addr: str,
    to_addrs: list[str],
    use_tls: bool = True,
) -> bool:
    """Send alert notifications via email."""
    if not alerts:
        return True

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"CT Monitor Alert: {len(alerts)} new finding(s)"
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    text_body = "Certificate Transparency Monitor - Alert Summary\n"
    text_body += "=" * 55 + "\n\n"
    for alert in alerts:
        text_body += f"Type: {alert['alert_type']}\n"
        text_body += f"Severity: {alert['severity']}\n"
        text_body += f"Domain: {alert.get('domain', 'N/A')}\n"
        details = json.loads(alert.get("details", "{}"))
        for k, v in details.items():
            text_body += f"  {k}: {v}\n"
        text_body += "-" * 40 + "\n\n"

    html_body = "<html><body>"
    html_body += "<h2>Certificate Transparency Monitor - Alert Summary</h2>"
    html_body += f"<p><strong>{len(alerts)} alert(s) generated</strong></p>"
    for alert in alerts:
        severity_color = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
        }.get(alert["severity"], "#6c757d")
        html_body += f'<div style="border-left:4px solid {severity_color};padding:10px;margin:10px 0;">'
        html_body += f'<strong style="color:{severity_color};">[{alert["severity"].upper()}]</strong> '
        html_body += f'{alert["alert_type"]}<br/>'
        html_body += f'Domain: {alert.get("domain", "N/A")}<br/>'
        details = json.loads(alert.get("details", "{}"))
        for k, v in details.items():
            html_body += f"<small>{k}: {v}</small><br/>"
        html_body += "</div>"
    html_body += "</body></html>"

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
            server.starttls()
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, to_addrs, msg.as_string())
        server.quit()
        logger.info("Email alert sent to %s", ", ".join(to_addrs))
        return True
    except Exception as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False


def send_webhook_alert(alerts: list[dict], webhook_url: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Send alert notifications to a webhook (Slack, Teams, generic)."""
    if not alerts:
        return True

    payload = {
        "text": f"CT Monitor: {len(alerts)} new alert(s)",
        "blocks": [],
    }
    for alert in alerts:
        severity_emoji = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]",
            "medium": "[MEDIUM]",
            "low": "[LOW]",
        }.get(alert["severity"], "[INFO]")
        block_text = f"{severity_emoji} *{alert['alert_type']}*\n"
        block_text += f"Domain: `{alert.get('domain', 'N/A')}`\n"
        details = json.loads(alert.get("details", "{}"))
        for k, v in details.items():
            block_text += f"  {k}: {v}\n"
        payload["blocks"].append({"type": "section", "text": {"type": "mrkdwn", "text": block_text}})

    try:
        resp = requests.post(webhook_url, json=payload, timeout=timeout)
        resp.raise_for_status()
        logger.info("Webhook alert sent successfully")
        return True
    except requests.exceptions.RequestException as exc:
        logger.error("Failed to send webhook alert: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_report(conn: sqlite3.Connection, domain: str, output_path: str = None) -> dict:
    """Generate a comprehensive CT monitoring report."""
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM certificates WHERE domain = ?", (domain,))
    total_certs = cursor.fetchone()[0]

    cursor.execute(
        """SELECT COUNT(*) FROM certificates
           WHERE domain = ? AND first_seen >= datetime('now', '-24 hours')""",
        (domain,),
    )
    new_certs_24h = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM subdomains WHERE parent_domain = ?", (domain,))
    total_subdomains = cursor.fetchone()[0]

    cursor.execute(
        """SELECT COUNT(*) FROM subdomains
           WHERE parent_domain = ? AND first_seen >= datetime('now', '-24 hours')""",
        (domain,),
    )
    new_subdomains_24h = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM alerts WHERE domain LIKE ? AND acknowledged = 0",
        (f"%{domain}%",),
    )
    open_alerts = cursor.fetchone()[0]

    # Top issuers
    cursor.execute(
        """SELECT issuer_name, COUNT(*) as cnt
           FROM certificates WHERE domain = ?
           GROUP BY issuer_name ORDER BY cnt DESC LIMIT 10""",
        (domain,),
    )
    top_issuers = [{"issuer": r[0], "count": r[1]} for r in cursor.fetchall()]

    # Recent alerts
    cursor.execute(
        """SELECT alert_type, severity, domain, details, created_at
           FROM alerts WHERE domain LIKE ?
           ORDER BY created_at DESC LIMIT 20""",
        (f"%{domain}%",),
    )
    recent_alerts = [
        {
            "type": r[0], "severity": r[1], "domain": r[2],
            "details": json.loads(r[3]) if r[3] else {}, "created_at": r[4],
        }
        for r in cursor.fetchall()
    ]

    # Subdomains with DNS status
    cursor.execute(
        """SELECT subdomain, dns_resolved, resolved_ip, cname_target, first_seen
           FROM subdomains WHERE parent_domain = ? ORDER BY first_seen DESC""",
        (domain,),
    )
    subdomain_list = [
        {
            "subdomain": r[0], "dns_resolved": bool(r[1]),
            "ips": r[2].split(",") if r[2] else [],
            "cname": r[3], "first_seen": r[4],
        }
        for r in cursor.fetchall()
    ]

    report = {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "monitored_domain": domain,
        "summary": {
            "total_certificates": total_certs,
            "new_certificates_24h": new_certs_24h,
            "total_subdomains": total_subdomains,
            "new_subdomains_24h": new_subdomains_24h,
            "open_alerts": open_alerts,
        },
        "top_issuers": top_issuers,
        "recent_alerts": recent_alerts,
        "subdomains": subdomain_list,
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Report saved to %s", output_path)

    return report


# ---------------------------------------------------------------------------
# Authorized CA management
# ---------------------------------------------------------------------------

def add_authorized_ca(conn: sqlite3.Connection, ca_name: str, ca_id: int = None):
    """Add a CA to the authorized issuers list."""
    conn.execute(
        "INSERT OR IGNORE INTO authorized_cas (ca_name, issuer_ca_id) VALUES (?, ?)",
        (ca_name, ca_id),
    )
    conn.commit()
    logger.info("Added authorized CA: %s (ID: %s)", ca_name, ca_id)


def auto_populate_authorized_cas(conn: sqlite3.Connection, domain: str):
    """Auto-populate authorized CAs from existing certificate baseline."""
    cursor = conn.cursor()
    cursor.execute(
        """SELECT DISTINCT issuer_name, issuer_ca_id
           FROM certificates WHERE domain = ?""",
        (domain,),
    )
    for issuer_name, issuer_ca_id in cursor.fetchall():
        if issuer_name:
            add_authorized_ca(conn, issuer_name, issuer_ca_id)
    logger.info("Auto-populated authorized CAs from baseline for %s", domain)


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def run_monitor_cycle(
    conn: sqlite3.Connection,
    domains: list[str],
    resolve_dns: bool = True,
    check_typosquats: bool = False,
    webhook_url: str = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Run a single monitoring cycle for all configured domains."""
    cycle_results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domains_checked": len(domains),
        "new_certificates": 0,
        "new_subdomains": 0,
        "alerts": [],
    }

    for domain in domains:
        root_domain = domain.lstrip("%.")
        query_pattern = f"%.{root_domain}"

        logger.info("Monitoring domain: %s (query: %s)", root_domain, query_pattern)

        # Query crt.sh
        certs = query_crtsh(query_pattern, exclude_expired=True, timeout=timeout)
        if not certs:
            logger.warning("No certificates returned for %s", query_pattern)
            continue

        # Store and detect new certs
        new_certs = store_certificates(conn, certs, root_domain)
        cycle_results["new_certificates"] += len(new_certs)

        # Subdomain discovery
        new_subs = discover_subdomains(conn, certs, root_domain)
        cycle_results["new_subdomains"] += len(new_subs)

        # DNS resolution
        if resolve_dns and new_subs:
            resolve_all_subdomains(conn, root_domain)

        # Alert checks
        ca_alerts = check_unauthorized_ca(conn, new_certs)
        sub_alerts = check_new_subdomain_alerts(conn, new_subs, root_domain)
        wc_alerts = check_wildcard_certs(conn, new_certs)
        sl_alerts = check_short_lived_certs(conn, new_certs)
        exp_alerts = check_expiring_certs(conn, root_domain)

        all_alerts = ca_alerts + sub_alerts + wc_alerts + sl_alerts + exp_alerts
        cycle_results["alerts"].extend(all_alerts)

        # Typosquat scanning (expensive, run periodically)
        if check_typosquats:
            typosquats = scan_typosquats(root_domain, timeout=timeout)
            for ts in typosquats:
                alert = {
                    "alert_type": "typosquat_detected",
                    "severity": "high",
                    "domain": ts["typosquat_domain"],
                    "details": json.dumps(ts),
                }
                all_alerts.append(alert)
                cycle_results["alerts"].append(alert)

        # Send notifications
        if all_alerts and webhook_url:
            send_webhook_alert(all_alerts, webhook_url, timeout=timeout)

    logger.info(
        "Monitoring cycle complete: %d new certs, %d new subdomains, %d alerts",
        cycle_results["new_certificates"],
        cycle_results["new_subdomains"],
        len(cycle_results["alerts"]),
    )
    return cycle_results


def main():
    parser = argparse.ArgumentParser(
        description="CT Log Monitoring Agent - Monitor Certificate Transparency logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot scan for a domain
  python agent.py --domains example.com --db ct_monitor.db --report report.json

  # Continuous monitoring with Slack webhook
  python agent.py --domains example.com bank.example.com --continuous --interval 900 \\
      --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

  # Scan with typosquat detection
  python agent.py --domains example.com --typosquats --report report.json

  # Auto-populate authorized CAs from baseline
  python agent.py --domains example.com --auto-baseline --db ct_monitor.db
        """,
    )
    parser.add_argument(
        "--domains", nargs="+", required=True,
        help="Domain(s) to monitor (e.g., example.com bank.example.com)",
    )
    parser.add_argument("--db", default="ct_monitor.db", help="SQLite database path (default: ct_monitor.db)")
    parser.add_argument("--report", help="Output JSON report to this path")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP request timeout in seconds")
    parser.add_argument("--continuous", action="store_true", help="Run continuous monitoring loop")
    parser.add_argument("--interval", type=int, default=900, help="Monitoring interval in seconds (default: 900)")
    parser.add_argument("--resolve-dns", action="store_true", default=True, help="Resolve discovered subdomains via DNS")
    parser.add_argument("--no-resolve-dns", action="store_false", dest="resolve_dns", help="Disable DNS resolution")
    parser.add_argument("--typosquats", action="store_true", help="Enable typosquat domain scanning (slow)")
    parser.add_argument("--webhook", help="Webhook URL for alert notifications (Slack, Teams)")
    parser.add_argument("--auto-baseline", action="store_true", help="Auto-populate authorized CAs from current certs")
    parser.add_argument(
        "--add-ca", nargs=2, metavar=("CA_NAME", "CA_ID"),
        help="Manually add an authorized CA (name and crt.sh CA ID)",
    )
    parser.add_argument("--smtp-host", help="SMTP server for email alerts")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP port (default: 587)")
    parser.add_argument("--smtp-user", help="SMTP username")
    parser.add_argument("--smtp-pass", help="SMTP password")
    parser.add_argument("--email-from", help="Alert email sender address")
    parser.add_argument("--email-to", nargs="+", help="Alert email recipient address(es)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    conn = init_database(args.db)
    logger.info("Database initialized: %s", args.db)

    # Add authorized CA manually
    if args.add_ca:
        add_authorized_ca(conn, args.add_ca[0], int(args.add_ca[1]))
        return

    # Auto-baseline mode
    if args.auto_baseline:
        for domain in args.domains:
            logger.info("Building baseline for %s...", domain)
            certs = query_crtsh(f"%.{domain}", exclude_expired=True, timeout=args.timeout)
            if certs:
                store_certificates(conn, certs, domain)
                discover_subdomains(conn, certs, domain)
                auto_populate_authorized_cas(conn, domain)
                if args.resolve_dns:
                    resolve_all_subdomains(conn, domain)
            logger.info("Baseline complete for %s", domain)
        if args.report:
            for domain in args.domains:
                generate_report(conn, domain, args.report)
        conn.close()
        return

    # Run monitoring
    if args.continuous:
        logger.info(
            "Starting continuous monitoring for %s (interval: %ds)",
            ", ".join(args.domains), args.interval,
        )
        try:
            while True:
                cycle = run_monitor_cycle(
                    conn, args.domains,
                    resolve_dns=args.resolve_dns,
                    check_typosquats=args.typosquats,
                    webhook_url=args.webhook,
                    timeout=args.timeout,
                )
                # Email alerts if configured
                if cycle["alerts"] and args.smtp_host and args.email_to:
                    send_email_alert(
                        cycle["alerts"],
                        args.smtp_host, args.smtp_port,
                        args.smtp_user, args.smtp_pass,
                        args.email_from or args.smtp_user,
                        args.email_to,
                    )
                if args.report:
                    for domain in args.domains:
                        generate_report(conn, domain, args.report)
                logger.info("Sleeping %ds until next cycle...", args.interval)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
    else:
        cycle = run_monitor_cycle(
            conn, args.domains,
            resolve_dns=args.resolve_dns,
            check_typosquats=args.typosquats,
            webhook_url=args.webhook,
            timeout=args.timeout,
        )
        if cycle["alerts"] and args.smtp_host and args.email_to:
            send_email_alert(
                cycle["alerts"],
                args.smtp_host, args.smtp_port,
                args.smtp_user, args.smtp_pass,
                args.email_from or args.smtp_user,
                args.email_to,
            )
        if args.report:
            for domain in args.domains:
                generate_report(conn, domain, args.report)

    conn.close()
    logger.info("CT monitoring agent finished")


if __name__ == "__main__":
    main()
