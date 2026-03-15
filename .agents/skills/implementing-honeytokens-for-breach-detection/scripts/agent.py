#!/usr/bin/env python3
"""Agent for deploying and managing honeytokens for breach detection."""

import os
import json
import uuid
import hashlib
import argparse
from datetime import datetime

import requests


def create_dns_canarytoken(email, memo, webhook_url=None):
    """Create a DNS canary token via Canarytokens.org API."""
    data = {
        "type": "dns",
        "email": email,
        "memo": memo,
    }
    if webhook_url:
        data["webhook_url"] = webhook_url
    resp = requests.post("https://canarytokens.org/generate", data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()


def create_web_bug_token(email, memo, webhook_url=None):
    """Create a web bug (image beacon) canary token."""
    data = {
        "type": "web_image",
        "email": email,
        "memo": memo,
    }
    if webhook_url:
        data["webhook_url"] = webhook_url
    resp = requests.post("https://canarytokens.org/generate", data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()


def create_aws_key_token(email, memo, webhook_url=None):
    """Create an AWS credential canary token."""
    data = {
        "type": "aws_keys",
        "email": email,
        "memo": memo,
    }
    if webhook_url:
        data["webhook_url"] = webhook_url
    resp = requests.post("https://canarytokens.org/generate", data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()


def generate_honeytoken_id():
    """Generate a unique honeytoken identifier."""
    return f"HT-{uuid.uuid4().hex[:12].upper()}"


def deploy_aws_credential_token(target_path, canary_key_id, canary_secret):
    """Deploy fake AWS credentials file as a honeytoken."""
    content = (
        "[default]\n"
        f"aws_access_key_id = {canary_key_id}\n"
        f"aws_secret_access_key = {canary_secret}\n"
        "region = us-east-1\n"
    )
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w") as f:
        f.write(content)
    return {
        "type": "aws_credentials",
        "path": target_path,
        "token_id": generate_honeytoken_id(),
        "deployed_at": datetime.utcnow().isoformat(),
    }


def deploy_database_honeytoken(db_connection_string, table_name="users"):
    """Generate SQL to insert honeytoken records into a database."""
    token_id = generate_honeytoken_id()
    fake_users = [
        {
            "username": "svc_backup_admin",
            "email": f"{token_id}@canary.internal",
            "role": "admin",
            "api_key": hashlib.sha256(token_id.encode()).hexdigest()[:40],
        },
        {
            "username": "emergency_break_glass",
            "email": f"bg-{token_id}@canary.internal",
            "role": "superadmin",
            "api_key": hashlib.sha256(f"bg-{token_id}".encode()).hexdigest()[:40],
        },
    ]
    sql_statements = []
    for user in fake_users:
        sql = (
            f"INSERT INTO {table_name} (username, email, role, api_key) "
            f"VALUES ('{user['username']}', '{user['email']}', "
            f"'{user['role']}', '{user['api_key']}');"
        )
        sql_statements.append(sql)
    return {"token_id": token_id, "sql_statements": sql_statements, "records": fake_users}


def deploy_dns_token_in_config(config_path, dns_hostname, key_name="backup_server"):
    """Embed a DNS canary token in a configuration file."""
    config_entry = f"{key_name} = {dns_hostname}\n"
    with open(config_path, "a") as f:
        f.write(f"\n# Backup configuration\n{config_entry}")
    return {
        "type": "dns_config",
        "config_path": config_path,
        "dns_hostname": dns_hostname,
        "deployed_at": datetime.utcnow().isoformat(),
    }


def create_deployment_plan(target_environment):
    """Create a honeytoken deployment plan for an environment."""
    plan = {
        "environment": target_environment,
        "tokens": [
            {"type": "aws_credentials", "location": "/opt/backup/.aws/credentials",
             "description": "Fake AWS creds in backup directory"},
            {"type": "dns", "location": "/etc/app/config.yml",
             "description": "DNS canary in app config"},
            {"type": "database", "location": "users table",
             "description": "Honeytoken admin accounts"},
            {"type": "web_bug", "location": "internal wiki",
             "description": "Image beacon in sensitive docs"},
            {"type": "dns", "location": "/root/.ssh/config",
             "description": "DNS canary in SSH config"},
        ],
    }
    return plan


def check_token_alerts(webhook_log_path):
    """Parse webhook logs to check for honeytoken trigger alerts."""
    if not os.path.exists(webhook_log_path):
        return []
    with open(webhook_log_path) as f:
        logs = json.load(f)
    alerts = []
    for entry in logs:
        if entry.get("type") == "canarytoken_triggered":
            alerts.append({
                "token_memo": entry.get("memo", ""),
                "source_ip": entry.get("src_ip", ""),
                "triggered_at": entry.get("time", ""),
                "token_type": entry.get("token_type", ""),
            })
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Honeytoken Deployment Agent")
    parser.add_argument("--email", default=os.getenv("CANARY_EMAIL", "soc@company.com"))
    parser.add_argument("--webhook", default=os.getenv("CANARY_WEBHOOK"))
    parser.add_argument("--output", default="honeytoken_report.json")
    parser.add_argument("--action", choices=[
        "create_dns", "create_aws", "create_web", "plan", "full_deploy"
    ], default="plan")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "tokens": {}}

    if args.action == "plan":
        plan = create_deployment_plan("production")
        report["deployment_plan"] = plan
        print(f"[+] Deployment plan: {len(plan['tokens'])} tokens")

    if args.action in ("create_dns", "full_deploy"):
        token = create_dns_canarytoken(args.email, "Production honeytoken", args.webhook)
        report["tokens"]["dns"] = token
        print(f"[+] DNS canary token created")

    if args.action in ("create_aws", "full_deploy"):
        token = create_aws_key_token(args.email, "AWS credential honeytoken", args.webhook)
        report["tokens"]["aws"] = token
        print(f"[+] AWS credential token created")

    if args.action in ("create_web", "full_deploy"):
        token = create_web_bug_token(args.email, "Web beacon honeytoken", args.webhook)
        report["tokens"]["web_bug"] = token
        print(f"[+] Web bug token created")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
