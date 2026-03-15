#!/usr/bin/env python3
"""Mimecast Targeted Attack Protection Agent - monitors TAP events and URL/attachment threats."""

import json
import argparse
import logging
import subprocess
import hashlib
import hmac
import base64
import uuid
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MIMECAST_BASE = "https://us-api.mimecast.com"


def mimecast_request(base_url, app_id, app_key, access_key, secret_key, endpoint, data=None):
    """Execute authenticated Mimecast API request."""
    request_id = str(uuid.uuid4())
    hdr_date = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"
    data_to_sign = f"{hdr_date}:{request_id}:{endpoint}:{app_key}"
    hmac_sha1 = hmac.new(base64.b64decode(secret_key), data_to_sign.encode(), hashlib.sha1)
    sig = base64.b64encode(hmac_sha1.digest()).decode()
    headers = {
        "Authorization": f"MC {access_key}:{sig}",
        "x-mc-app-id": app_id,
        "x-mc-date": hdr_date,
        "x-mc-req-id": request_id,
        "Content-Type": "application/json",
    }
    cmd = ["curl", "-s", "-X", "POST", f"{base_url}{endpoint}"]
    for k, v in headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", json.dumps({"data": [data]})])
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def get_url_logs(base_url, app_id, app_key, access_key, secret_key, date_from=None):
    """Get URL Protection logs."""
    data = {}
    if date_from:
        data["from"] = date_from
    return mimecast_request(base_url, app_id, app_key, access_key, secret_key,
                            "/api/ttp/url/get-logs", data)


def get_impersonation_logs(base_url, app_id, app_key, access_key, secret_key, date_from=None):
    """Get impersonation protection logs."""
    data = {}
    if date_from:
        data["from"] = date_from
    return mimecast_request(base_url, app_id, app_key, access_key, secret_key,
                            "/api/ttp/impersonation/get-logs", data)


def get_attachment_logs(base_url, app_id, app_key, access_key, secret_key, date_from=None):
    """Get attachment protection logs."""
    data = {}
    if date_from:
        data["from"] = date_from
    return mimecast_request(base_url, app_id, app_key, access_key, secret_key,
                            "/api/ttp/attachment/get-logs", data)


def analyze_url_threats(url_logs):
    """Analyze URL click patterns and threat categories."""
    categories = defaultdict(int)
    blocked = 0
    permitted = 0
    users_clicked = defaultdict(int)
    for entry in url_logs:
        cat = entry.get("scanResult", "unknown")
        categories[cat] += 1
        if entry.get("action") == "block":
            blocked += 1
        else:
            permitted += 1
        users_clicked[entry.get("userEmailAddress", "")] += 1
    top_clickers = sorted(users_clicked.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "total_url_events": len(url_logs),
        "blocked": blocked,
        "permitted": permitted,
        "categories": dict(categories),
        "top_clickers": [{"email": e, "clicks": c} for e, c in top_clickers],
    }


def analyze_impersonation(imp_logs):
    """Analyze impersonation attack patterns."""
    senders = defaultdict(int)
    targets = defaultdict(int)
    for entry in imp_logs:
        senders[entry.get("senderAddress", "")] += 1
        targets[entry.get("recipientAddress", "")] += 1
    return {
        "total_impersonation_events": len(imp_logs),
        "unique_senders": len(senders),
        "top_impersonated_senders": dict(sorted(senders.items(), key=lambda x: x[1], reverse=True)[:10]),
        "most_targeted_users": dict(sorted(targets.items(), key=lambda x: x[1], reverse=True)[:10]),
    }


def generate_report(url_analysis, imp_analysis, attachment_count):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "url_protection": url_analysis,
        "impersonation_protection": imp_analysis,
        "attachment_threats": attachment_count,
        "total_threats": url_analysis["blocked"] + imp_analysis["total_impersonation_events"] + attachment_count,
    }


def main():
    parser = argparse.ArgumentParser(description="Mimecast Targeted Attack Protection Agent")
    parser.add_argument("--base-url", default=MIMECAST_BASE)
    parser.add_argument("--app-id", required=True, help="Mimecast Application ID")
    parser.add_argument("--app-key", required=True, help="Mimecast Application Key")
    parser.add_argument("--access-key", required=True, help="Mimecast Access Key")
    parser.add_argument("--secret-key", required=True, help="Mimecast Secret Key")
    parser.add_argument("--date-from", help="Start date YYYY-MM-DD")
    parser.add_argument("--output", default="mimecast_tap_report.json")
    args = parser.parse_args()

    url_resp = get_url_logs(args.base_url, args.app_id, args.app_key, args.access_key, args.secret_key, args.date_from)
    url_logs = url_resp.get("data", [{}])[0].get("clickLogs", [])
    imp_resp = get_impersonation_logs(args.base_url, args.app_id, args.app_key, args.access_key, args.secret_key, args.date_from)
    imp_logs = imp_resp.get("data", [{}])[0].get("impersonationLogs", [])
    att_resp = get_attachment_logs(args.base_url, args.app_id, args.app_key, args.access_key, args.secret_key, args.date_from)
    att_logs = att_resp.get("data", [{}])[0].get("attachmentLogs", [])

    url_analysis = analyze_url_threats(url_logs)
    imp_analysis = analyze_impersonation(imp_logs)
    report = generate_report(url_analysis, imp_analysis, len(att_logs))
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Total threats: %d (URL blocked: %d, impersonation: %d, attachments: %d)",
                report["total_threats"], url_analysis["blocked"],
                imp_analysis["total_impersonation_events"], len(att_logs))
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
