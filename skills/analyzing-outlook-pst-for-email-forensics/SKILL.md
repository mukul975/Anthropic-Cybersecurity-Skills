---
name: analyzing-outlook-pst-for-email-forensics
description: Analyze Microsoft Outlook PST and OST files for email forensic evidence including message content, headers, attachments, deleted items, and metadata using libpff, pst-utils, and forensic email analysis tools for legal investigations and incident response.
domain: cybersecurity
subdomain: digital-forensics
tags: [email-forensics, pst, ost, outlook, mapi, email-headers, attachments, deleted-emails, libpff, eml-extraction]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Analyzing Outlook PST for Email Forensics

## Overview

Microsoft Outlook PST (Personal Storage Table) and OST (Offline Storage Table) files are critical evidence sources in digital forensics investigations. PST files store email messages, calendar events, contacts, tasks, and notes in a proprietary binary format based on the MAPI (Messaging Application Programming Interface) property system. Forensic analysis of these files enables recovery of deleted emails (from the Recoverable Items folder), extraction of email headers for tracing message routes, analysis of attachments for malware or exfiltrated data, and reconstruction of communication patterns. Modern PST files use Unicode format with 4KB pages and can grow up to 50GB, while legacy ANSI format is limited to 2GB.

## Prerequisites

- libpff/pffexport (open-source PST parser)
- Python 3.8+ with pypff or libratom libraries
- MailXaminer, Forensic Email Collector, or SysTools PST Forensics (commercial)
- Microsoft Outlook (optional, for native PST access)
- Sufficient disk space for extracted content

## PST File Locations

| Source | Path |
|--------|------|
| Outlook 2016+ Default | %USERPROFILE%\Documents\Outlook Files\*.pst |
| Outlook Legacy | %LOCALAPPDATA%\Microsoft\Outlook\*.pst |
| OST Cache | %LOCALAPPDATA%\Microsoft\Outlook\*.ost |
| Archive | %USERPROFILE%\Documents\Outlook Files\archive.pst |

## Analysis with Open-Source Tools

### libpff / pffexport

```bash
# Export all items from PST file
pffexport -m all evidence.pst -t exported_pst

# Export only email messages
pffexport -m items evidence.pst -t exported_emails

# Export recovered/deleted items
pffexport -m recovered evidence.pst -t recovered_items

# Get PST file information
pffinfo evidence.pst
```

### Python PST Analysis

```python
import pypff
import os
import json
import hashlib
import email
import sys
from datetime import datetime
from collections import defaultdict


class PSTForensicAnalyzer:
    """Forensic analysis of Outlook PST/OST files."""

    def __init__(self, pst_path: str, output_dir: str):
        self.pst_path = pst_path
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.pst = pypff.file()
        self.pst.open(pst_path)
        self.messages = []
        self.attachments = []
        self.stats = defaultdict(int)

    def process_folder(self, folder, folder_path: str = ""):
        """Recursively process PST folders and extract messages."""
        folder_name = folder.name or "Root"
        current_path = f"{folder_path}/{folder_name}" if folder_path else folder_name

        for i in range(folder.number_of_sub_messages):
            try:
                message = folder.get_sub_message(i)
                msg_data = self.extract_message(message, current_path)
                if msg_data:
                    self.messages.append(msg_data)
                    self.stats["total_messages"] += 1
            except Exception as e:
                self.stats["parse_errors"] += 1

        for i in range(folder.number_of_sub_folders):
            try:
                subfolder = folder.get_sub_folder(i)
                self.process_folder(subfolder, current_path)
            except Exception:
                continue

    def extract_message(self, message, folder_path: str) -> dict:
        """Extract forensic metadata from a single email message."""
        msg_data = {
            "folder": folder_path,
            "subject": message.subject or "",
            "sender": message.sender_name or "",
            "sender_email": "",
            "creation_time": str(message.creation_time) if message.creation_time else None,
            "delivery_time": str(message.delivery_time) if message.delivery_time else None,
            "modification_time": str(message.modification_time) if message.modification_time else None,
            "has_attachments": message.number_of_attachments > 0,
            "attachment_count": message.number_of_attachments,
            "body_size": len(message.plain_text_body or b""),
            "html_size": len(message.html_body or b""),
        }

        # Extract transport headers for routing analysis
        headers = message.transport_headers
        if headers:
            msg_data["headers_present"] = True
            msg_data["headers_size"] = len(headers)
            # Parse key headers
            parsed = email.message_from_string(headers)
            msg_data["from_header"] = parsed.get("From", "")
            msg_data["to_header"] = parsed.get("To", "")
            msg_data["date_header"] = parsed.get("Date", "")
            msg_data["message_id"] = parsed.get("Message-ID", "")
            msg_data["x_originating_ip"] = parsed.get("X-Originating-IP", "")
            msg_data["received_headers"] = parsed.get_all("Received", [])

        # Process attachments
        for j in range(message.number_of_attachments):
            try:
                attachment = message.get_attachment(j)
                att_data = {
                    "message_subject": msg_data["subject"],
                    "name": attachment.name or f"attachment_{j}",
                    "size": attachment.size,
                    "content_type": "",
                }
                self.attachments.append(att_data)
                self.stats["total_attachments"] += 1
            except Exception:
                continue

        return msg_data

    def save_attachments(self, max_size_mb: int = 100):
        """Export attachments to disk for analysis."""
        att_dir = os.path.join(self.output_dir, "attachments")
        os.makedirs(att_dir, exist_ok=True)

        root = self.pst.get_root_folder()
        self._save_attachments_recursive(root, att_dir, max_size_mb)

    def _save_attachments_recursive(self, folder, att_dir, max_size_mb):
        for i in range(folder.number_of_sub_messages):
            try:
                message = folder.get_sub_message(i)
                for j in range(message.number_of_attachments):
                    att = message.get_attachment(j)
                    if att.size and att.size < max_size_mb * 1024 * 1024:
                        name = att.name or f"unknown_{i}_{j}"
                        safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in name)
                        path = os.path.join(att_dir, safe_name)
                        try:
                            data = att.read_buffer(att.size)
                            with open(path, "wb") as f:
                                f.write(data)
                        except Exception:
                            continue
            except Exception:
                continue

        for i in range(folder.number_of_sub_folders):
            try:
                self._save_attachments_recursive(folder.get_sub_folder(i), att_dir, max_size_mb)
            except Exception:
                continue

    def generate_report(self) -> str:
        """Generate comprehensive PST forensic analysis report."""
        root = self.pst.get_root_folder()
        self.process_folder(root)

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "pst_file": self.pst_path,
            "pst_size_bytes": os.path.getsize(self.pst_path),
            "statistics": dict(self.stats),
            "messages": self.messages[:500],
            "attachments": self.attachments[:200],
        }

        report_path = os.path.join(self.output_dir, "pst_forensic_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"[*] Total messages: {self.stats['total_messages']}")
        print(f"[*] Total attachments: {self.stats['total_attachments']}")
        print(f"[*] Parse errors: {self.stats['parse_errors']}")
        return report_path

    def close(self):
        self.pst.close()


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <pst_file> <output_dir>")
        sys.exit(1)
    analyzer = PSTForensicAnalyzer(sys.argv[1], sys.argv[2])
    analyzer.generate_report()
    analyzer.close()


if __name__ == "__main__":
    main()
```

## Email Header Analysis

Key headers for forensic investigation:

| Header | Forensic Value |
|--------|---------------|
| Received | Message routing chain (read bottom to top) |
| X-Originating-IP | Sender's actual IP address |
| Message-ID | Unique identifier for correlation |
| Date | Send timestamp |
| Return-Path | Bounce address (may differ from From) |
| DKIM-Signature | Domain authentication signature |
| Authentication-Results | SPF, DKIM, DMARC verification results |
| X-Mailer | Email client used |

## References

- MailXaminer PST Forensics: https://www.mailxaminer.com/blog/outlook-pst-file-forensics/
- libpff Documentation: https://github.com/libyal/libpff
- PST File Format Specification: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/
- SANS Email Forensics: https://www.sans.org/blog/email-forensics/

## Example Output

```text
$ pffexport /evidence/jsmith_archive.pst -t /analysis/pst_output

pffexport 20231205 - libpff PST/OST Export Tool
=================================================
Input: /evidence/jsmith_archive.pst (2.3 GB)

Exporting PST contents...
  Folders:       45
  Messages:      12,456
  Attachments:   3,234
  Contacts:      567
  Calendar:      234
  Tasks:         89

Export completed in 3m 42s.

$ python3 pst_analyzer.py /analysis/pst_output /analysis/email_report

PST Forensic Analysis Report
==============================
Source: jsmith_archive.pst (john.smith@corporate.com)
Date Range: 2023-06-01 to 2024-01-18

--- Mailbox Statistics ---
  Total Emails:       12,456
  Sent:               4,567
  Received:           7,889
  With Attachments:   3,234
  Deleted (recovered): 234

--- Phishing / Suspicious Emails ---
Email #8923
  Date:        2024-01-15 14:30:22 UTC
  From:        "IT Support" <it-support@c0rporate-help.com>
  To:          john.smith@corporate.com
  Subject:     Urgent: Password Reset Required
  Headers:
    Return-Path:    bounce@mail-relay.c0rporate-help.com
    X-Originating-IP: 203.0.113.55
    Received:       from mail-relay.c0rporate-help.com (203.0.113.55)
    SPF:            FAIL (domain c0rporate-help.com)
    DKIM:           NONE
    DMARC:          FAIL
  Attachments:
    - Password_Reset_Form.xlsm (245 KB) SHA-256: 7a3b8c9d...e1f2a3b4
  Body Preview:  "Dear Employee, Your password will expire in 24 hours.
                  Please open the attached form to reset your credentials..."

--- Data Exfiltration Indicators ---
Email #9102
  Date:        2024-01-16 03:15:45 UTC
  From:        john.smith@corporate.com
  To:          j.smith.personal8842@protonmail.com
  Subject:     (no subject)
  Attachments:
    - archive_part1.7z (24.5 MB) - encrypted
    - archive_part2.7z (24.5 MB) - encrypted

Email #9103
  Date:        2024-01-16 03:18:22 UTC
  From:        john.smith@corporate.com
  To:          j.smith.personal8842@protonmail.com
  Subject:     Re:
  Attachments:
    - archive_part3.7z (18.2 MB) - encrypted

--- Keyword Hits ---
  "confidential":     45 emails
  "password":         23 emails
  "transfer":         12 emails
  "resign":           3 emails
  "delete evidence":  1 email (Email #9200, 2024-01-17 22:30:00 UTC)

Summary:
  Phishing emails detected:    1 (initial compromise vector)
  Suspicious sent emails:      5 (to personal accounts with attachments)
  Encrypted attachments:       3 (67.2 MB total - possible exfiltration)
  Report: /analysis/email_report/pst_forensic_report.json
```
