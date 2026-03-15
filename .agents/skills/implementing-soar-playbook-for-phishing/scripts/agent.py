#!/usr/bin/env python3
"""Splunk SOAR phishing playbook automation via REST API."""

import argparse
import email
import json
import re
import sys
import time

import requests
from email import policy
from email.parser import BytesParser


URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


class SOARClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "ph-auth-token": token,
            "Content-Type": "application/json",
        })
        self.session.verify = verify_ssl

    def create_container(self, name: str, description: str, severity: str,
                         label: str = "events") -> dict:
        payload = {
            "name": name,
            "description": description,
            "severity": severity,
            "label": label,
            "status": "new",
            "sensitivity": "amber",
        }
        resp = self.session.post(f"{self.base_url}/rest/container", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return {"container_id": data.get("id"), "success": data.get("success", False)}

    def add_artifact(self, container_id: int, name: str, cef: dict,
                     label: str = "event", severity: str = "medium",
                     artifact_type: str = "network", run_automation: bool = False) -> dict:
        payload = {
            "container_id": container_id,
            "name": name,
            "label": label,
            "severity": severity,
            "type": artifact_type,
            "cef": cef,
            "run_automation": run_automation,
        }
        resp = self.session.post(f"{self.base_url}/rest/artifact", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return {"artifact_id": data.get("id"), "success": data.get("success", False)}

    def trigger_playbook(self, playbook_name: str, container_id: int,
                         scope: str = "new") -> dict:
        payload = {
            "container_id": container_id,
            "playbook_id": playbook_name,
            "scope": scope,
            "run": True,
        }
        resp = self.session.post(f"{self.base_url}/rest/playbook_run", json=payload)
        resp.raise_for_status()
        return resp.json()

    def get_action_runs(self, container_id: int) -> list:
        resp = self.session.get(
            f"{self.base_url}/rest/action_run",
            params={"_filter_container": container_id, "page_size": 100}
        )
        resp.raise_for_status()
        return resp.json().get("data", [])

    def poll_playbook(self, container_id: int, timeout: int = 300,
                      interval: int = 10) -> list:
        terminal_states = {"success", "failed", "cancelled"}
        elapsed = 0
        while elapsed < timeout:
            runs = self.get_action_runs(container_id)
            if runs and all(r.get("status") in terminal_states for r in runs):
                return runs
            time.sleep(interval)
            elapsed += interval
        return self.get_action_runs(container_id)


def parse_email_file(email_path: str) -> dict:
    with open(email_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "date": msg.get("Date", ""),
        "x_mailer": msg.get("X-Mailer", ""),
    }

    received_headers = msg.get_all("Received", [])
    auth_results = msg.get("Authentication-Results", "")
    spf_result = "none"
    dkim_result = "none"
    dmarc_result = "none"
    if "spf=pass" in auth_results.lower():
        spf_result = "pass"
    elif "spf=fail" in auth_results.lower():
        spf_result = "fail"
    if "dkim=pass" in auth_results.lower():
        dkim_result = "pass"
    elif "dkim=fail" in auth_results.lower():
        dkim_result = "fail"
    if "dmarc=pass" in auth_results.lower():
        dmarc_result = "pass"
    elif "dmarc=fail" in auth_results.lower():
        dmarc_result = "fail"

    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_text += part.get_content()
            elif part.get_content_type() == "text/html":
                body_text += part.get_content()
    else:
        body_text = msg.get_content()

    urls = list(set(URL_PATTERN.findall(body_text)))
    originating_ips = []
    for recv in received_headers:
        originating_ips.extend(IP_PATTERN.findall(recv))
    originating_ips = list(set(originating_ips))

    return {
        "headers": headers,
        "received_count": len(received_headers),
        "auth": {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result},
        "urls": urls,
        "originating_ips": originating_ips,
    }


def run_phishing_workflow(args) -> dict:
    email_data = parse_email_file(args.email_file)
    client = SOARClient(args.soar_url, args.token, verify_ssl=not args.no_verify)

    sender = email_data["headers"]["from"]
    subject = email_data["headers"]["subject"]
    severity = "high" if email_data["auth"]["spf"] == "fail" else "medium"

    container = client.create_container(
        name=f"Phishing Report: {subject[:80]}",
        description=f"Reported phishing email from {sender}",
        severity=severity,
        label="phishing",
    )
    cid = container["container_id"]

    artifacts_created = 0
    client.add_artifact(cid, "Email Headers", {
        "fromAddress": sender,
        "toAddress": email_data["headers"]["to"],
        "emailSubject": subject,
        "emailMessageId": email_data["headers"]["message_id"],
        "emailReplyTo": email_data["headers"]["reply_to"],
        "emailReturnPath": email_data["headers"]["return_path"],
    }, label="email", artifact_type="email", severity=severity)
    artifacts_created += 1

    for ip in email_data["originating_ips"]:
        client.add_artifact(cid, f"Originating IP: {ip}", {
            "sourceAddress": ip,
        }, label="email", artifact_type="ip", severity="medium")
        artifacts_created += 1

    url_list = email_data["urls"]
    for i, url in enumerate(url_list):
        is_last = (i == len(url_list) - 1) and not args.playbook
        client.add_artifact(cid, f"Embedded URL: {url[:60]}", {
            "requestURL": url,
        }, label="email", artifact_type="url", severity="high",
            run_automation=is_last)
        artifacts_created += 1

    playbook_result = None
    if args.playbook:
        playbook_result = client.trigger_playbook(args.playbook, cid)
        action_runs = client.poll_playbook(cid, timeout=args.poll_timeout)
        playbook_result["action_runs"] = len(action_runs)
        playbook_result["actions_completed"] = sum(
            1 for r in action_runs if r.get("status") == "success"
        )

    return {
        "incident": {
            "container_id": cid,
            "status": "new",
            "severity": severity,
            "artifacts_created": artifacts_created,
        },
        "email_analysis": {
            "sender": sender,
            "subject": subject,
            "urls_found": len(url_list),
            "originating_ips": email_data["originating_ips"],
            "auth": email_data["auth"],
        },
        "playbook": playbook_result,
    }


def main():
    parser = argparse.ArgumentParser(description="SOAR Phishing Playbook Automation")
    parser.add_argument("--soar-url", required=True, help="Splunk SOAR base URL")
    parser.add_argument("--token", required=True, help="SOAR API auth token")
    parser.add_argument("--email-file", required=True, help="Path to .eml phishing email file")
    parser.add_argument("--playbook", default=None,
                        help="Playbook name or ID to trigger")
    parser.add_argument("--poll-timeout", type=int, default=300,
                        help="Max seconds to poll for playbook completion")
    parser.add_argument("--no-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    result = run_phishing_workflow(args)
    report = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
    print(report)


if __name__ == "__main__":
    main()
