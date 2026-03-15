#!/usr/bin/env python3
"""
Deception Technology Deployment Agent
Deploys and manages honeypots, honeytokens, and canary files to detect
lateral movement and credential abuse with near-zero false positive alerts.
"""

import hashlib
import json
import os
import secrets
import socket
import sys
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler


def generate_honeytoken_credentials(count: int = 5) -> list[dict]:
    """Generate fake credential honeytokens for deployment in AD and databases."""
    honeytokens = []
    templates = [
        ("svc_backup_admin", "Service account - backup system"),
        ("admin_legacy", "Legacy admin account"),
        ("db_migration_user", "Database migration service account"),
        ("api_service_prod", "Production API service account"),
        ("deploy_automation", "CI/CD deployment service account"),
    ]

    for i in range(min(count, len(templates))):
        username, description = templates[i]
        token_id = secrets.token_hex(4)
        honeytokens.append({
            "token_id": f"HT-{token_id}",
            "type": "credential",
            "username": f"{username}_{token_id[:4]}",
            "password": secrets.token_urlsafe(24),
            "description": description,
            "deployment_location": "Active Directory / LSASS memory",
            "alert_on": "Any authentication attempt",
            "created": datetime.now(timezone.utc).isoformat(),
        })

    return honeytokens


def generate_canary_files(output_dir: str, count: int = 5) -> list[dict]:
    """Generate canary files that trigger alerts when accessed."""
    canary_templates = [
        ("passwords.xlsx", "Fake password spreadsheet"),
        ("salary_data_2024.csv", "Fake salary data"),
        ("aws_credentials.txt", "Fake AWS access keys"),
        ("vpn_config_backup.ovpn", "Fake VPN configuration"),
        ("database_backup_prod.sql", "Fake database backup"),
    ]

    canary_files = []
    os.makedirs(output_dir, exist_ok=True)

    for i in range(min(count, len(canary_templates))):
        filename, description = canary_templates[i]
        filepath = os.path.join(output_dir, filename)
        token_id = secrets.token_hex(4)

        content = f"# CANARY FILE - Token: {token_id}\n"
        content += f"# This file is a decoy. Any access triggers a security alert.\n"
        content += f"# Description: {description}\n"
        content += f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n"

        if "credentials" in filename or "password" in filename:
            content += "admin:P@ssw0rd_fake_canary_2024\n"
            content += "root:SuperSecret_fake_canary!\n"
        elif "aws" in filename:
            content += f"[default]\naws_access_key_id = AKIA{secrets.token_hex(8).upper()}\n"
            content += f"aws_secret_access_key = {secrets.token_hex(20)}\n"

        with open(filepath, "w") as f:
            f.write(content)

        canary_files.append({
            "token_id": f"CF-{token_id}",
            "type": "canary_file",
            "filename": filename,
            "filepath": filepath,
            "description": description,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "alert_on": "File open / read access",
            "created": datetime.now(timezone.utc).isoformat(),
        })

    return canary_files


def generate_dns_canary_tokens(domain: str, count: int = 3) -> list[dict]:
    """Generate DNS canary tokens that alert on resolution."""
    tokens = []
    for i in range(count):
        token_id = secrets.token_hex(8)
        hostname = f"{token_id}.{domain}"
        tokens.append({
            "token_id": f"DNS-{token_id[:8]}",
            "type": "dns_canary",
            "hostname": hostname,
            "usage": f"Embed in config files, documents, or network shares",
            "alert_on": "DNS resolution of hostname",
            "created": datetime.now(timezone.utc).isoformat(),
        })

    return tokens


class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    """Simple HTTP honeypot handler that logs all requests."""

    alerts = []

    def do_GET(self):
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "method": "GET",
            "path": self.path,
            "headers": dict(self.headers),
            "severity": "HIGH",
        }
        HoneypotHTTPHandler.alerts.append(alert)
        print(f"[ALERT] Honeypot hit: {alert['source_ip']} -> GET {self.path}")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Restricted Area"')
        self.end_headers()
        self.wfile.write(b"Authentication Required")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")

        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "method": "POST",
            "path": self.path,
            "body_preview": body[:200],
            "severity": "CRITICAL",
        }
        HoneypotHTTPHandler.alerts.append(alert)
        print(f"[ALERT] Honeypot credential capture: {alert['source_ip']}")
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"Access Denied")

    def log_message(self, format, *args):
        pass


def start_http_honeypot(host: str = "0.0.0.0", port: int = 8888) -> HTTPServer:
    """Start an HTTP honeypot server in a background thread."""
    server = HTTPServer((host, port), HoneypotHTTPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] HTTP honeypot listening on {host}:{port}")
    return server


def generate_deployment_report(
    credentials: list, canary_files: list, dns_tokens: list
) -> str:
    """Generate deception technology deployment report."""
    total = len(credentials) + len(canary_files) + len(dns_tokens)
    lines = [
        "DECEPTION TECHNOLOGY DEPLOYMENT REPORT",
        "=" * 50,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total Decoys Deployed: {total}",
        "",
        f"HONEYTOKEN CREDENTIALS ({len(credentials)}):",
    ]
    for cred in credentials:
        lines.append(f"  [{cred['token_id']}] {cred['username']} - {cred['description']}")

    lines.append(f"\nCANARY FILES ({len(canary_files)}):")
    for cf in canary_files:
        lines.append(f"  [{cf['token_id']}] {cf['filename']} - {cf['description']}")

    lines.append(f"\nDNS CANARY TOKENS ({len(dns_tokens)}):")
    for dns in dns_tokens:
        lines.append(f"  [{dns['token_id']}] {dns['hostname']}")

    return "\n".join(lines)


if __name__ == "__main__":
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "canary_files"
    dns_domain = sys.argv[2] if len(sys.argv) > 2 else "canary.example.com"

    print("[*] Deploying deception technology...")

    credentials = generate_honeytoken_credentials(5)
    canary_files = generate_canary_files(output_dir, 5)
    dns_tokens = generate_dns_canary_tokens(dns_domain, 3)

    report = generate_deployment_report(credentials, canary_files, dns_tokens)
    print(report)

    inventory = {
        "credentials": credentials,
        "canary_files": canary_files,
        "dns_tokens": dns_tokens,
    }
    output = f"deception_inventory_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump(inventory, f, indent=2)
    print(f"\n[*] Inventory saved to {output}")
