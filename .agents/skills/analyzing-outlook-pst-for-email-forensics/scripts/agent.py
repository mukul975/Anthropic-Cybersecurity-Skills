#!/usr/bin/env python3
"""Outlook PST file forensic analysis agent.

Parses PST/OST files using pypff (libpff) to extract emails, attachments,
metadata, and deleted items for forensic investigation.
"""

import os
import sys
import json
import hashlib
import re
from datetime import datetime
from collections import defaultdict

try:
    import pypff
    HAS_PYPFF = True
except ImportError:
    HAS_PYPFF = False


def compute_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def open_pst(filepath):
    if not HAS_PYPFF:
        return None, "pypff not installed. pip install libpff-python"
    pst = pypff.file()
    pst.open(filepath)
    return pst, None


def extract_messages(folder, max_messages=1000):
    messages = []
    for i in range(min(folder.number_of_sub_messages, max_messages)):
        msg = folder.get_sub_message(i)
        entry = {
            "subject": msg.subject or "",
            "sender": msg.sender_name or "",
            "headers": (msg.transport_headers or "")[:500],
            "creation_time": str(msg.creation_time) if msg.creation_time else "",
            "delivery_time": str(msg.delivery_time) if msg.delivery_time else "",
            "has_attachments": msg.number_of_attachments > 0,
            "attachment_count": msg.number_of_attachments,
            "body_size": len(msg.plain_text_body or "") if msg.plain_text_body else 0,
        }
        # Extract attachment metadata
        attachments = []
        for j in range(msg.number_of_attachments):
            att = msg.get_attachment(j)
            attachments.append({
                "name": att.name or f"attachment_{j}",
                "size": att.size,
            })
        entry["attachments"] = attachments
        messages.append(entry)
    return messages


def walk_folders(folder, path="", results=None):
    if results is None:
        results = []
    current_path = f"{path}/{folder.name}" if folder.name else path or "/Root"
    messages = extract_messages(folder)
    if messages:
        results.append({
            "folder": current_path,
            "message_count": len(messages),
            "messages": messages,
        })
    for i in range(folder.number_of_sub_folders):
        subfolder = folder.get_sub_folder(i)
        walk_folders(subfolder, current_path, results)
    return results


def extract_email_addresses(messages):
    addresses = set()
    email_pattern = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
    for msg in messages:
        for field in [msg.get("sender", ""), msg.get("headers", "")]:
            addresses.update(email_pattern.findall(field))
    return sorted(addresses)


def detect_suspicious_emails(messages):
    findings = []
    suspicious_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                       ".js", ".hta", ".lnk", ".iso", ".img"]
    for msg in messages:
        for att in msg.get("attachments", []):
            name = (att.get("name") or "").lower()
            for ext in suspicious_exts:
                if name.endswith(ext):
                    findings.append({
                        "type": "suspicious_attachment",
                        "subject": msg.get("subject", "")[:80],
                        "attachment": att.get("name"),
                        "extension": ext,
                        "severity": "HIGH",
                    })
        subject = (msg.get("subject") or "").lower()
        urgency_words = ["urgent", "immediate action", "password expired",
                         "verify your account", "suspended", "click here"]
        for word in urgency_words:
            if word in subject:
                findings.append({
                    "type": "phishing_indicator",
                    "subject": msg.get("subject", "")[:80],
                    "keyword": word,
                    "severity": "MEDIUM",
                })
                break
    return findings


def generate_report(filepath, folder_data):
    all_messages = []
    for fd in folder_data:
        all_messages.extend(fd.get("messages", []))
    addresses = extract_email_addresses(all_messages)
    suspicious = detect_suspicious_emails(all_messages)
    return {
        "file": filepath,
        "sha256": compute_hash(filepath),
        "size": os.path.getsize(filepath),
        "total_folders": len(folder_data),
        "total_messages": len(all_messages),
        "unique_addresses": len(addresses),
        "top_addresses": addresses[:20],
        "suspicious_findings": suspicious,
        "folders": [{
            "path": f["folder"],
            "count": f["message_count"],
        } for f in folder_data],
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Outlook PST Forensic Analysis Agent")
    print("Email extraction, attachment analysis, phishing detection")
    print("=" * 60)

    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target or not os.path.exists(target):
        print("\n[DEMO] Usage: python agent.py <mailbox.pst>")
        print(f"  pypff available: {HAS_PYPFF}")
        sys.exit(0)

    pst, err = open_pst(target)
    if err:
        print(f"[!] {err}")
        sys.exit(1)

    print(f"\n[*] Parsing: {target}")
    root = pst.get_root_folder()
    folder_data = walk_folders(root)
    report = generate_report(target, folder_data)

    print(f"[*] Folders: {report['total_folders']}")
    print(f"[*] Messages: {report['total_messages']}")
    print(f"[*] Unique addresses: {report['unique_addresses']}")

    print("\n--- Folder Structure ---")
    for f in report["folders"]:
        print(f"  {f['path']}: {f['count']} messages")

    print(f"\n--- Suspicious ({len(report['suspicious_findings'])}) ---")
    for s in report["suspicious_findings"][:10]:
        print(f"  [{s['severity']}] {s['type']}: {s.get('attachment', s.get('keyword', ''))}")

    pst.close()
    print(f"\n{json.dumps(report, indent=2, default=str)}")
