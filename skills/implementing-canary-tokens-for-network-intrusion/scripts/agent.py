#!/usr/bin/env python3
"""
Agent for deploying and managing canary tokens for network intrusion detection.

Supports DNS, HTTP, and AWS API key canary tokens via Canarytokens.org API
and Thinkst Canary enterprise console. Provides webhook alert integration
with Slack, Microsoft Teams, email, and generic HTTP endpoints.
"""

import os
import json
import uuid
import argparse
import logging
import smtplib
import socket
import re
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("canary-token-agent")

_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")

# ---------------------------------------------------------------------------
# Canarytokens.org API integration
# ---------------------------------------------------------------------------

CANARYTOKENS_API_URL = os.getenv(
    "CANARYTOKENS_API_URL", "https://canarytokens.org/generate"
)

SUPPORTED_TOKEN_TYPES = {
    "dns": "DNS resolution beacon -- triggers on any DNS lookup of the FQDN",
    "http": "HTTP URL token -- triggers on HTTP GET, reveals source IP and User-Agent",
    "aws_keys": "AWS API key pair -- triggers when keys are used against any AWS endpoint",
    "web_image": "Web bug / image beacon -- triggers when image is loaded in browser",
    "cloned_web": "Cloned website token -- triggers when cloned page is visited",
    "svn": "SVN repository token -- triggers on SVN checkout",
    "sql_server": "SQL Server token -- triggers on database login attempt",
    "qr_code": "QR code token -- triggers when QR code is scanned and URL visited",
    "slack_api": "Slack API token -- triggers when token is used against Slack API",
}


def generate_token_id():
    """Generate a unique canary token tracking identifier."""
    return f"CT-{uuid.uuid4().hex[:12].upper()}"


def create_canarytoken(token_type, email, memo, webhook_url=None):
    """
    Create a canary token via Canarytokens.org public API.

    Args:
        token_type: One of the SUPPORTED_TOKEN_TYPES keys
        email: Notification email address
        memo: Human-readable description for alert context
        webhook_url: Optional webhook URL for real-time alerts

    Returns:
        dict with token details from the API
    """
    if token_type not in SUPPORTED_TOKEN_TYPES:
        raise ValueError(
            f"Unsupported token type: {token_type}. "
            f"Supported: {list(SUPPORTED_TOKEN_TYPES.keys())}"
        )

    data = {
        "type": token_type,
        "email": email,
        "memo": memo,
    }
    if webhook_url:
        data["webhook_url"] = webhook_url

    logger.info("Creating %s canary token: %s", token_type, memo)
    resp = requests.post(CANARYTOKENS_API_URL, data=data, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    logger.info("Token created successfully: %s", token_type)
    return result


def create_dns_token(email, memo, webhook_url=None):
    """Create a DNS canary token that alerts on any DNS resolution."""
    result = create_canarytoken("dns", email, memo, webhook_url)
    return {
        "type": "dns",
        "hostname": result.get("hostname", ""),
        "token_id": generate_token_id(),
        "memo": memo,
        "manage_url": result.get("url", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def create_http_token(email, memo, webhook_url=None):
    """Create an HTTP canary token that alerts on HTTP requests."""
    result = create_canarytoken("http", email, memo, webhook_url)
    return {
        "type": "http",
        "url": result.get("url", ""),
        "token_id": generate_token_id(),
        "memo": memo,
        "manage_url": result.get("url", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def create_aws_key_token(email, memo, webhook_url=None):
    """Create an AWS API key canary token that alerts on any AWS API usage."""
    result = create_canarytoken("aws_keys", email, memo, webhook_url)
    return {
        "type": "aws_keys",
        "access_key_id": result.get("access_key_id", ""),
        "secret_access_key": result.get("secret_access_key", ""),
        "token_id": generate_token_id(),
        "memo": memo,
        "manage_url": result.get("url", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def create_web_image_token(email, memo, webhook_url=None):
    """Create a web image beacon canary token."""
    result = create_canarytoken("web_image", email, memo, webhook_url)
    return {
        "type": "web_image",
        "image_url": result.get("url", ""),
        "token_id": generate_token_id(),
        "memo": memo,
        "manage_url": result.get("url", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Thinkst Canary Enterprise API integration
# ---------------------------------------------------------------------------

def thinkst_create_token(console_domain, auth_token, kind, memo, flock_id=None):
    """
    Create a canary token via Thinkst Canary enterprise console API.

    Args:
        console_domain: Your Thinkst Canary console domain (e.g., 'yourcompany')
        auth_token: API authentication token
        kind: Token kind (dns, http, aws-id, doc-msword, etc.)
        memo: Description for the token
        flock_id: Optional flock identifier for grouping

    Returns:
        dict with token details from the Thinkst API
    """
    url = f"https://{console_domain}.canary.tools/api/v1/canarytoken/create"
    payload = {
        "auth_token": auth_token,
        "memo": memo,
        "kind": kind,
    }
    if flock_id:
        payload["flock_id"] = flock_id

    logger.info("Creating Thinkst %s token: %s", kind, memo)
    resp = requests.post(url, data=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def thinkst_list_tokens(console_domain, auth_token):
    """List all canary tokens from the Thinkst Canary console."""
    url = f"https://{console_domain}.canary.tools/api/v1/canarytokens/fetch"
    resp = requests.get(url, params={"auth_token": auth_token}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("tokens", [])


def thinkst_get_alerts(console_domain, auth_token):
    """Retrieve triggered canary token alerts from Thinkst Canary console."""
    url = f"https://{console_domain}.canary.tools/api/v1/canarytokens/alerts"
    resp = requests.get(url, params={"auth_token": auth_token}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("alerts", [])


# ---------------------------------------------------------------------------
# Token deployment helpers
# ---------------------------------------------------------------------------

def deploy_aws_credentials_file(target_path, access_key_id, secret_access_key,
                                profile="default", region="us-east-1"):
    """
    Deploy a fake AWS credentials file as a canary token.

    Places realistic-looking AWS credentials in the target path. When an attacker
    finds and uses these credentials, the canary token triggers an alert.
    """
    content = (
        f"[{profile}]\n"
        f"aws_access_key_id = {access_key_id}\n"
        f"aws_secret_access_key = {secret_access_key}\n"
        f"region = {region}\n"
    )
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    logger.info("Deployed AWS credential canary at: %s", target_path)
    return {
        "type": "aws_credentials_file",
        "path": str(target),
        "profile": profile,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


def deploy_dns_token_in_config(config_path, dns_hostname, key_name="backup_server",
                               comment="Backup replication endpoint"):
    """
    Embed a DNS canary token hostname in a configuration file.

    The token triggers when anyone or any tool resolves the hostname,
    such as during network scanning, config parsing, or manual inspection.
    """
    entry = f"\n# {comment}\n{key_name} = {dns_hostname}\n"
    config = Path(config_path)
    if not config.exists():
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(entry, encoding="utf-8")
    else:
        with open(config, "a", encoding="utf-8") as f:
            f.write(entry)
    logger.info("Deployed DNS canary in config: %s (key=%s)", config_path, key_name)
    return {
        "type": "dns_config_embed",
        "config_path": str(config),
        "key_name": key_name,
        "dns_hostname": dns_hostname,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


def deploy_http_token_in_html(html_path, http_token_url, page_title="IT Admin Portal"):
    """
    Embed an HTTP canary token as a hidden image tag in an HTML page.

    The token triggers when the page is rendered in a browser and the
    hidden image is loaded, revealing the attacker's IP and User-Agent.
    """
    html_content = f"""<!DOCTYPE html>
<html>
<head><title>{page_title}</title></head>
<body>
<h1>{page_title}</h1>
<p>Access restricted. Contact IT for credentials.</p>
<!-- Canary token beacon -->
<img src="{http_token_url}" style="display:none" alt="" width="1" height="1" />
</body>
</html>"""
    target = Path(html_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html_content, encoding="utf-8")
    logger.info("Deployed HTTP canary in HTML: %s", html_path)
    return {
        "type": "http_html_beacon",
        "html_path": str(target),
        "token_url": http_token_url,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


def deploy_ssh_config_token(ssh_config_path, dns_hostname,
                            host_alias="backup-gateway"):
    """
    Plant a DNS canary token in an SSH config file.

    Attackers performing recon on SSH configurations will trigger the token
    when they attempt to resolve or connect to the canary hostname.
    """
    entry = (
        f"\n# Legacy backup gateway\n"
        f"Host {host_alias}\n"
        f"    HostName {dns_hostname}\n"
        f"    User backup\n"
        f"    Port 22\n"
        f"    IdentityFile ~/.ssh/backup_key\n"
    )
    config = Path(ssh_config_path)
    config.parent.mkdir(parents=True, exist_ok=True)
    if config.exists():
        with open(config, "a", encoding="utf-8") as f:
            f.write(entry)
    else:
        config.write_text(entry, encoding="utf-8")
    logger.info("Deployed DNS canary in SSH config: %s", ssh_config_path)
    return {
        "type": "ssh_config_canary",
        "ssh_config_path": str(config),
        "host_alias": host_alias,
        "dns_hostname": dns_hostname,
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


def deploy_env_file_token(env_path, access_key_id, secret_access_key,
                          additional_vars=None):
    """
    Deploy a fake .env file containing canary AWS credentials and optional extras.

    Attackers harvesting environment files from repos or servers will trigger
    the token when they attempt to use the credentials.
    """
    lines = [
        "# Application configuration",
        f"AWS_ACCESS_KEY_ID={access_key_id}",
        f"AWS_SECRET_ACCESS_KEY={secret_access_key}",
        "AWS_DEFAULT_REGION=us-east-1",
        "DATABASE_URL=postgresql://readonly:readonly@db.internal:5432/app",
    ]
    if additional_vars:
        for k, v in additional_vars.items():
            lines.append(f"{k}={v}")

    target = Path(env_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Deployed canary .env file: %s", env_path)
    return {
        "type": "env_file_canary",
        "path": str(target),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Webhook alert processing and forwarding
# ---------------------------------------------------------------------------

def send_slack_alert(webhook_url, alert_data):
    """
    Forward a canary token alert to a Slack channel via incoming webhook.

    Args:
        webhook_url: Slack incoming webhook URL
        alert_data: Dict with alert details (memo, src_ip, channel, time, etc.)
    """
    payload = {
        "text": ":rotating_light: *Canary Token Triggered -- Possible Intrusion*",
        "attachments": [
            {
                "color": "#FF0000",
                "fields": [
                    {
                        "title": "Token Description",
                        "value": alert_data.get("memo", "Unknown token"),
                        "short": True,
                    },
                    {
                        "title": "Source IP",
                        "value": alert_data.get("src_ip", "Unknown"),
                        "short": True,
                    },
                    {
                        "title": "Token Type",
                        "value": alert_data.get("channel", alert_data.get("token_type", "Unknown")),
                        "short": True,
                    },
                    {
                        "title": "Triggered At",
                        "value": alert_data.get("time", datetime.now(timezone.utc).isoformat()),
                        "short": True,
                    },
                    {
                        "title": "User Agent",
                        "value": alert_data.get("additional_data", {}).get("useragent", "N/A"),
                        "short": False,
                    },
                    {
                        "title": "Management URL",
                        "value": alert_data.get("manage_url", "N/A"),
                        "short": False,
                    },
                ],
                "footer": "Canary Token Intrusion Detection System",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ],
    }
    resp = requests.post(webhook_url, json=payload, timeout=10)
    resp.raise_for_status()
    logger.info("Slack alert sent for: %s", alert_data.get("memo", ""))


def send_teams_alert(webhook_url, alert_data):
    """
    Forward a canary token alert to Microsoft Teams via incoming webhook.

    Args:
        webhook_url: Teams incoming webhook URL
        alert_data: Dict with alert details
    """
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": "Canary Token Triggered",
        "sections": [
            {
                "activityTitle": "Canary Token Triggered -- Possible Intrusion",
                "facts": [
                    {"name": "Token", "value": alert_data.get("memo", "Unknown")},
                    {"name": "Source IP", "value": alert_data.get("src_ip", "Unknown")},
                    {"name": "Type", "value": alert_data.get("channel", "Unknown")},
                    {"name": "Time", "value": alert_data.get("time", "Unknown")},
                ],
                "markdown": True,
            }
        ],
    }
    resp = requests.post(webhook_url, json=payload, timeout=10)
    resp.raise_for_status()
    logger.info("Teams alert sent for: %s", alert_data.get("memo", ""))


def send_email_alert(smtp_config, alert_data):
    """
    Send a canary token alert via email.

    Args:
        smtp_config: Dict with server, port, username, password, from_addr, to_addr
        alert_data: Dict with alert details
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CANARY ALERT] Token Triggered: {alert_data.get('memo', 'Unknown')}"
    msg["From"] = smtp_config["from_addr"]
    msg["To"] = smtp_config["to_addr"]

    text_body = (
        f"CANARY TOKEN ALERT\n"
        f"{'=' * 50}\n"
        f"Token: {alert_data.get('memo', 'Unknown')}\n"
        f"Type: {alert_data.get('channel', 'Unknown')}\n"
        f"Source IP: {alert_data.get('src_ip', 'Unknown')}\n"
        f"Time: {alert_data.get('time', 'Unknown')}\n"
        f"Management: {alert_data.get('manage_url', 'N/A')}\n"
        f"{'=' * 50}\n"
        f"This alert was generated by the Canary Token Intrusion Detection System.\n"
    )

    html_body = f"""<html>
<body>
<h2 style="color:red;">Canary Token Triggered</h2>
<table border="1" cellpadding="8">
<tr><td><b>Token</b></td><td>{alert_data.get('memo', 'Unknown')}</td></tr>
<tr><td><b>Type</b></td><td>{alert_data.get('channel', 'Unknown')}</td></tr>
<tr><td><b>Source IP</b></td><td>{alert_data.get('src_ip', 'Unknown')}</td></tr>
<tr><td><b>Time</b></td><td>{alert_data.get('time', 'Unknown')}</td></tr>
<tr><td><b>Management</b></td><td><a href="{alert_data.get('manage_url', '#')}">{alert_data.get('manage_url', 'N/A')}</a></td></tr>
</table>
</body>
</html>"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(smtp_config["server"], smtp_config.get("port", 587)) as server:
        server.starttls()
        server.login(smtp_config["username"], smtp_config["password"])
        server.send_message(msg)
    logger.info("Email alert sent to %s for: %s", smtp_config["to_addr"], alert_data.get("memo", ""))


def forward_to_siem(siem_url, alert_data, api_key=None):
    """
    Forward canary token alert to a SIEM system via HTTP API.

    Formats the alert as a structured security event suitable for
    ingestion by Splunk HEC, Elastic, or similar SIEM platforms.
    """
    siem_event = {
        "event_type": "canarytoken_triggered",
        "severity": "high",
        "source": "canary_token_ids",
        "timestamp": alert_data.get("time", datetime.now(timezone.utc).isoformat()),
        "details": {
            "memo": alert_data.get("memo"),
            "token_type": alert_data.get("channel"),
            "source_ip": alert_data.get("src_ip"),
            "user_agent": alert_data.get("additional_data", {}).get("useragent"),
            "manage_url": alert_data.get("manage_url"),
        },
        "mitre_attack": {
            "tactic": "Discovery",
            "technique": "T1083",
            "description": "File and Directory Discovery -- attacker accessed canary resource",
        },
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    resp = requests.post(siem_url, json=siem_event, headers=headers, timeout=15)
    resp.raise_for_status()
    logger.info("SIEM event forwarded for: %s", alert_data.get("memo", ""))


# ---------------------------------------------------------------------------
# Token inventory and monitoring
# ---------------------------------------------------------------------------

def create_deployment_plan(environment, zones=None):
    """
    Generate a comprehensive canary token deployment plan for an environment.

    Args:
        environment: Target environment name (production, staging, corporate)
        zones: Optional list of network zones to include

    Returns:
        Deployment plan with recommended token placements
    """
    default_zones = {
        "dmz": [
            {"type": "http", "location": "/var/www/admin/index.html",
             "memo": f"DMZ admin panel -- {environment}",
             "description": "Hidden image beacon in web server admin page"},
            {"type": "dns", "location": "/etc/nginx/conf.d/upstream.conf",
             "memo": f"DMZ nginx upstream -- {environment}",
             "description": "DNS canary in nginx upstream config"},
        ],
        "internal": [
            {"type": "aws_keys", "location": "/home/deploy/.aws/credentials",
             "memo": f"Internal deploy creds -- {environment}",
             "description": "Fake AWS credentials on deployment server"},
            {"type": "dns", "location": "/etc/app/database.yml",
             "memo": f"Internal DB config -- {environment}",
             "description": "DNS canary in database configuration"},
            {"type": "http", "location": "/opt/wiki/pages/emergency-passwords.html",
             "memo": f"Internal wiki passwords page -- {environment}",
             "description": "HTTP beacon in internal wiki sensitive page"},
        ],
        "production": [
            {"type": "aws_keys", "location": "/opt/app/.env",
             "memo": f"Production .env file -- {environment}",
             "description": "Canary AWS keys in production env file"},
            {"type": "dns", "location": "/etc/ssh/ssh_config",
             "memo": f"Production SSH config -- {environment}",
             "description": "DNS canary in SSH configuration"},
            {"type": "dns", "location": "/opt/backup/config.ini",
             "memo": f"Production backup config -- {environment}",
             "description": "DNS canary in backup server config"},
        ],
        "cloud": [
            {"type": "aws_keys", "location": "s3://config-bucket/.env.backup",
             "memo": f"Cloud S3 env backup -- {environment}",
             "description": "Canary AWS keys in S3 configuration bucket"},
            {"type": "dns", "location": "terraform/modules/networking/vars.tf",
             "memo": f"Cloud Terraform vars -- {environment}",
             "description": "DNS canary in Terraform variable definitions"},
        ],
    }

    selected_zones = zones or list(default_zones.keys())
    plan_tokens = []
    for zone in selected_zones:
        if zone in default_zones:
            for token_spec in default_zones[zone]:
                token_spec["zone"] = zone
                plan_tokens.append(token_spec)

    return {
        "environment": environment,
        "zones": selected_zones,
        "total_tokens": len(plan_tokens),
        "tokens": plan_tokens,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def build_token_inventory(report_dir):
    """
    Build an inventory of all deployed canary tokens from report files.

    Scans the report directory for deployment reports and consolidates
    them into a single inventory.
    """
    inventory = {"tokens": [], "total": 0, "by_type": {}, "by_zone": {}}
    report_path = Path(report_dir)

    if not report_path.exists():
        logger.warning("Report directory not found: %s", report_dir)
        return inventory

    for report_file in report_path.glob("*.json"):
        with open(report_file, encoding="utf-8") as f:
            report = json.load(f)

        for token_key, token_data in report.get("tokens", {}).items():
            if isinstance(token_data, dict):
                inventory["tokens"].append(token_data)
                token_type = token_data.get("type", "unknown")
                inventory["by_type"][token_type] = (
                    inventory["by_type"].get(token_type, 0) + 1
                )

        if "deployment_plan" in report:
            for token_spec in report["deployment_plan"].get("tokens", []):
                zone = token_spec.get("zone", "unknown")
                inventory["by_zone"][zone] = (
                    inventory["by_zone"].get(zone, 0) + 1
                )

    inventory["total"] = len(inventory["tokens"])
    inventory["generated_at"] = datetime.now(timezone.utc).isoformat()
    return inventory


def check_token_alerts(webhook_log_path):
    """
    Parse webhook logs to identify triggered canary token alerts.

    Args:
        webhook_log_path: Path to the JSON log file from webhook receiver

    Returns:
        List of alert dicts with token details and trigger information
    """
    log_path = Path(webhook_log_path)
    if not log_path.exists():
        logger.warning("Webhook log not found: %s", webhook_log_path)
        return []

    alerts = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("event_type") == "canarytoken_triggered":
                alerts.append({
                    "token_memo": entry.get("memo", ""),
                    "token_type": entry.get("token_type", ""),
                    "source_ip": entry.get("src_ip", ""),
                    "triggered_at": entry.get("time", ""),
                    "user_agent": entry.get("additional_data", {}).get("useragent", ""),
                    "manage_url": entry.get("manage_url", ""),
                    "severity": "high",
                })

    logger.info("Found %d triggered alerts in %s", len(alerts), webhook_log_path)
    return alerts


def test_token_connectivity(token_hostname=None, token_url=None):
    """
    Validate that a canary token is reachable and can trigger alerts.

    WARNING: This will trigger the actual canary token alert.
    Only use during initial deployment validation.
    """
    results = {"dns": None, "http": None}

    if token_hostname:
        try:
            resolved = socket.getaddrinfo(token_hostname, None)
            results["dns"] = {
                "status": "resolved",
                "hostname": token_hostname,
                "addresses": [r[4][0] for r in resolved],
            }
            logger.info("DNS token test: %s resolved successfully", token_hostname)
        except socket.gaierror as e:
            results["dns"] = {
                "status": "resolution_failed",
                "hostname": token_hostname,
                "error": str(e),
            }
            logger.warning("DNS token test failed for %s: %s", token_hostname, e)

    if token_url:
        try:
            resp = requests.get(token_url, timeout=10, allow_redirects=True)
            results["http"] = {
                "status": "reachable",
                "url": token_url,
                "http_status": resp.status_code,
            }
            logger.info("HTTP token test: %s returned %d", token_url, resp.status_code)
        except requests.RequestException as e:
            results["http"] = {
                "status": "unreachable",
                "url": token_url,
                "error": str(e),
            }
            logger.warning("HTTP token test failed for %s: %s", token_url, e)

    return results


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Canary Token Network Intrusion Detection Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Actions:
  create_dns      Create a DNS canary token via Canarytokens.org
  create_http     Create an HTTP canary token
  create_aws      Create an AWS API key canary token
  create_web_img  Create a web image beacon canary token
  plan            Generate a deployment plan for an environment
  full_deploy     Create all token types and generate deployment plan
  monitor         Check for triggered alerts in webhook logs
  inventory       Build inventory from deployment reports
  test            Test connectivity to deployed tokens (triggers alerts!)

Examples:
  python agent.py --action plan --environment production
  python agent.py --action create_dns --email soc@company.com --webhook https://hooks.slack.com/...
  python agent.py --action full_deploy --email soc@company.com --output deploy_report.json
  python agent.py --action monitor --webhook-log /var/log/canary_alerts.json
        """,
    )
    parser.add_argument("--action", required=True, choices=[
        "create_dns", "create_http", "create_aws", "create_web_img",
        "plan", "full_deploy", "monitor", "inventory", "test",
    ])
    parser.add_argument("--email", default=os.getenv("CANARY_EMAIL", "soc@company.com"),
                        help="Notification email for token alerts")
    parser.add_argument("--webhook", default=os.getenv("CANARY_WEBHOOK"),
                        help="Webhook URL for real-time alerts (Slack/Teams/generic)")
    parser.add_argument("--memo", default=None,
                        help="Human-readable description for the token")
    parser.add_argument("--environment", default="production",
                        help="Target environment for deployment plan")
    parser.add_argument("--zones", nargs="*", default=None,
                        help="Network zones to include in deployment plan")
    parser.add_argument("--output", default="canary_token_report.json",
                        help="Output file path for report")
    parser.add_argument("--webhook-log", default="/var/log/canary_alerts.json",
                        help="Path to webhook alert log for monitoring")
    parser.add_argument("--report-dir", default="./reports",
                        help="Directory containing deployment reports for inventory")
    parser.add_argument("--console-domain", default=os.getenv("THINKST_DOMAIN"),
                        help="Thinkst Canary console domain (enterprise)")
    parser.add_argument("--api-key", default=os.getenv("THINKST_API_KEY"),
                        help="Thinkst Canary API auth token (enterprise)")
    parser.add_argument("--test-hostname", default=None,
                        help="DNS hostname to test connectivity")
    parser.add_argument("--test-url", default=None,
                        help="HTTP URL to test connectivity")
    args = parser.parse_args()

    report = {
        "agent": "canary-token-intrusion-detection",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "action": args.action,
        "tokens": {},
    }

    # --- Deployment Plan ---
    if args.action == "plan":
        plan = create_deployment_plan(args.environment, args.zones)
        report["deployment_plan"] = plan
        print(f"[+] Deployment plan generated: {plan['total_tokens']} tokens across "
              f"{len(plan['zones'])} zones")
        for token in plan["tokens"]:
            print(f"    [{token['zone']}] {token['type']:10s} -> {token['location']}")

    # --- DNS Token ---
    if args.action in ("create_dns", "full_deploy"):
        memo = args.memo or f"DNS canary -- {args.environment}"
        token = create_dns_token(args.email, memo, args.webhook)
        report["tokens"]["dns"] = token
        print(f"[+] DNS canary token created: {token.get('hostname', 'N/A')}")

    # --- HTTP Token ---
    if args.action in ("create_http", "full_deploy"):
        memo = args.memo or f"HTTP canary -- {args.environment}"
        token = create_http_token(args.email, memo, args.webhook)
        report["tokens"]["http"] = token
        print(f"[+] HTTP canary token created: {token.get('url', 'N/A')}")

    # --- AWS Key Token ---
    if args.action in ("create_aws", "full_deploy"):
        memo = args.memo or f"AWS key canary -- {args.environment}"
        token = create_aws_key_token(args.email, memo, args.webhook)
        report["tokens"]["aws_keys"] = token
        print(f"[+] AWS key canary token created: {token.get('access_key_id', 'N/A')}")

    # --- Web Image Token ---
    if args.action in ("create_web_img", "full_deploy"):
        memo = args.memo or f"Web beacon canary -- {args.environment}"
        token = create_web_image_token(args.email, memo, args.webhook)
        report["tokens"]["web_image"] = token
        print(f"[+] Web image canary token created: {token.get('image_url', 'N/A')}")

    # --- Full Deploy also generates plan ---
    if args.action == "full_deploy":
        plan = create_deployment_plan(args.environment, args.zones)
        report["deployment_plan"] = plan
        print(f"[+] Deployment plan: {plan['total_tokens']} tokens planned")

    # --- Monitor ---
    if args.action == "monitor":
        if args.console_domain and args.api_key:
            alerts = thinkst_get_alerts(args.console_domain, args.api_key)
            report["enterprise_alerts"] = alerts
            print(f"[+] Thinkst Canary: {len(alerts)} triggered alerts found")
            for alert in alerts:
                print(f"    [ALERT] {alert}")
        else:
            alerts = check_token_alerts(args.webhook_log)
            report["webhook_alerts"] = alerts
            print(f"[+] Webhook log: {len(alerts)} triggered alerts found")
            for alert in alerts:
                print(f"    [ALERT] {alert.get('token_memo', 'Unknown')} "
                      f"from {alert.get('source_ip', 'Unknown')} "
                      f"at {alert.get('triggered_at', 'Unknown')}")

    # --- Inventory ---
    if args.action == "inventory":
        inventory = build_token_inventory(args.report_dir)
        report["inventory"] = inventory
        print(f"[+] Token inventory: {inventory['total']} tokens")
        for token_type, count in inventory.get("by_type", {}).items():
            print(f"    {token_type}: {count}")

    # --- Test ---
    if args.action == "test":
        print("[!] WARNING: Testing tokens will trigger real alerts!")
        results = test_token_connectivity(args.test_hostname, args.test_url)
        report["test_results"] = results
        for test_type, result in results.items():
            if result:
                print(f"    [{test_type}] {result.get('status', 'unknown')}")

    # --- Write report ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
