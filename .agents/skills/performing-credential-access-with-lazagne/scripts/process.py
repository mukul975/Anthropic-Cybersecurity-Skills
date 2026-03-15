#!/usr/bin/env python3
"""
LaZagne Output Parser and Credential Analysis Script

Parses LaZagne JSON output, deduplicates credentials, and generates
prioritized reports. For authorized red team engagements only.
"""

import json
import sys
import os
from datetime import datetime
from collections import defaultdict


def load_lazagne_output(filepath: str) -> list:
    """Load LaZagne JSON output file."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading LaZagne output: {e}")
        return []


def parse_credentials(data: list) -> list:
    """Parse LaZagne output into normalized credential entries."""
    credentials = []

    for module_result in data:
        if isinstance(module_result, dict):
            category = module_result.get("Category", "Unknown")
            results = module_result.get("results", [])

            if isinstance(results, list):
                for entry in results:
                    if isinstance(entry, dict):
                        cred = {
                            "category": category,
                            "username": entry.get("Login", entry.get("Username", "")),
                            "password": entry.get("Password", ""),
                            "url": entry.get("URL", entry.get("Host", "")),
                            "port": entry.get("Port", ""),
                            "source": entry.get("Software", entry.get("Module", category)),
                            "raw": entry
                        }
                        if cred["username"] or cred["password"]:
                            credentials.append(cred)

    return credentials


def deduplicate_credentials(credentials: list) -> list:
    """Remove duplicate credential entries."""
    seen = set()
    unique = []

    for cred in credentials:
        key = (
            cred["username"].lower(),
            cred["password"],
            cred["url"].lower() if cred["url"] else ""
        )
        if key not in seen:
            seen.add(key)
            unique.append(cred)

    return unique


def categorize_credentials(credentials: list) -> dict:
    """Categorize credentials by type and priority."""
    categories = {
        "domain": [],
        "cloud": [],
        "database": [],
        "remote_access": [],
        "email": [],
        "web": [],
        "other": []
    }

    cloud_indicators = ["aws", "azure", "gcp", "cloud", "console."]
    remote_indicators = ["rdp", "ssh", "vnc", "vpn", "putty", "winscp"]
    db_indicators = ["postgres", "mysql", "mssql", "oracle", "mongodb", "redis"]
    email_indicators = ["outlook", "thunderbird", "smtp", "imap", "pop3", "mail"]

    for cred in credentials:
        source_lower = cred["source"].lower()
        url_lower = cred["url"].lower() if cred["url"] else ""
        combined = source_lower + " " + url_lower

        if "\\" in cred["username"] or "@" in cred["username"]:
            if any(domain_hint in cred["username"].lower()
                   for domain_hint in [".local", ".corp", ".internal", "\\"]):
                categories["domain"].append(cred)
                continue

        if any(ind in combined for ind in cloud_indicators):
            categories["cloud"].append(cred)
        elif any(ind in combined for ind in db_indicators):
            categories["database"].append(cred)
        elif any(ind in combined for ind in remote_indicators):
            categories["remote_access"].append(cred)
        elif any(ind in combined for ind in email_indicators):
            categories["email"].append(cred)
        elif cred["url"]:
            categories["web"].append(cred)
        else:
            categories["other"].append(cred)

    return categories


def generate_report(credentials: list, categories: dict, source_file: str) -> str:
    """Generate a credential analysis report."""
    report = [
        "=" * 70,
        "LaZagne Credential Analysis Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Source File: {source_file}",
        "=" * 70,
        "",
        f"Total Credentials Recovered: {len(credentials)}",
        "",
        "Breakdown by Priority:",
        f"  [CRITICAL] Domain Credentials: {len(categories['domain'])}",
        f"  [HIGH]     Cloud Credentials: {len(categories['cloud'])}",
        f"  [HIGH]     Remote Access: {len(categories['remote_access'])}",
        f"  [MEDIUM]   Database Credentials: {len(categories['database'])}",
        f"  [MEDIUM]   Email Credentials: {len(categories['email'])}",
        f"  [LOW]      Web Credentials: {len(categories['web'])}",
        f"  [INFO]     Other: {len(categories['other'])}",
        ""
    ]

    priority_order = [
        ("CRITICAL", "Domain Credentials", categories["domain"]),
        ("HIGH", "Cloud Credentials", categories["cloud"]),
        ("HIGH", "Remote Access Credentials", categories["remote_access"]),
        ("MEDIUM", "Database Credentials", categories["database"]),
        ("MEDIUM", "Email Credentials", categories["email"]),
    ]

    for priority, label, creds in priority_order:
        if creds:
            report.append(f"[{priority}] {label}:")
            report.append("-" * 50)
            for cred in creds:
                report.append(f"  Source: {cred['source']}")
                report.append(f"  User: {cred['username']}")
                report.append(f"  Target: {cred['url'] or 'N/A'}")
                report.append("")

    # Source distribution
    source_counts = defaultdict(int)
    for cred in credentials:
        source_counts[cred["source"]] += 1

    report.append("Credentials by Source:")
    report.append("-" * 50)
    for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        report.append(f"  {source}: {count}")

    report.append("")
    report.append("=" * 70)
    return "\n".join(report)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python process.py <lazagne_output.json>")
        return

    input_file = sys.argv[1]
    data = load_lazagne_output(input_file)

    if not data:
        print("No data loaded from LaZagne output.")
        return

    credentials = parse_credentials(data)
    credentials = deduplicate_credentials(credentials)
    categories = categorize_credentials(credentials)

    report = generate_report(credentials, categories, input_file)
    print(report)

    report_file = f"credential_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
