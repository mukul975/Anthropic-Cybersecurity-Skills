#!/usr/bin/env python3
"""
DCSync Rights Auditor and Hash Analysis Script

Audits AD environments for accounts with DCSync rights and
analyzes dumped credential data. For authorized red team engagements only.
"""

import sys
import os
import re
import json
from datetime import datetime
from collections import defaultdict


REPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}


def parse_secretsdump_output(filepath: str) -> dict:
    """Parse Impacket secretsdump.py output for hash extraction."""
    results = {
        "ntds_hashes": [],
        "kerberos_keys": [],
        "cleartext_passwords": [],
        "machine_accounts": [],
        "user_accounts": [],
        "krbtgt_hash": None,
        "admin_hash": None
    }

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return results

    ntds_pattern = re.compile(r"^(.+?):([\d]+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
    cleartext_pattern = re.compile(r"^(.+?):CLEARTEXT:(.+)$")

    for line in lines:
        line = line.strip()

        ntds_match = ntds_pattern.match(line)
        if ntds_match:
            username = ntds_match.group(1)
            rid = ntds_match.group(2)
            lm_hash = ntds_match.group(3)
            nt_hash = ntds_match.group(4)

            entry = {
                "username": username,
                "rid": rid,
                "lm_hash": lm_hash,
                "nt_hash": nt_hash,
                "is_machine": username.endswith("$")
            }

            results["ntds_hashes"].append(entry)

            if entry["is_machine"]:
                results["machine_accounts"].append(entry)
            else:
                results["user_accounts"].append(entry)

            if username.lower() == "krbtgt":
                results["krbtgt_hash"] = entry
            elif username.lower() == "administrator":
                results["admin_hash"] = entry

        cleartext_match = cleartext_pattern.match(line)
        if cleartext_match:
            results["cleartext_passwords"].append({
                "username": cleartext_match.group(1),
                "password": cleartext_match.group(2)
            })

    return results


def analyze_password_reuse(hashes: list) -> dict:
    """Identify password reuse across accounts."""
    hash_groups = defaultdict(list)

    for entry in hashes:
        if entry["nt_hash"] != "31d6cfe0d16ae931b73c59d7e0c089c0":  # Skip empty passwords
            hash_groups[entry["nt_hash"]].append(entry["username"])

    reuse = {nt_hash: users for nt_hash, users in hash_groups.items() if len(users) > 1}
    return reuse


def generate_dcsync_report(results: dict, source_file: str) -> str:
    """Generate DCSync credential analysis report."""
    report = [
        "=" * 70,
        "DCSync Credential Analysis Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Source: {source_file}",
        "=" * 70,
        "",
        "[Summary]",
        f"  Total Hashes: {len(results['ntds_hashes'])}",
        f"  User Accounts: {len(results['user_accounts'])}",
        f"  Machine Accounts: {len(results['machine_accounts'])}",
        f"  Cleartext Passwords: {len(results['cleartext_passwords'])}",
        ""
    ]

    # KRBTGT hash (most critical)
    if results["krbtgt_hash"]:
        report.append("[CRITICAL] KRBTGT Hash Recovered:")
        report.append(f"  NT Hash: {results['krbtgt_hash']['nt_hash']}")
        report.append("  Impact: Golden Ticket creation possible")
        report.append("")

    # Administrator hash
    if results["admin_hash"]:
        report.append("[CRITICAL] Administrator Hash Recovered:")
        report.append(f"  NT Hash: {results['admin_hash']['nt_hash']}")
        report.append("  Impact: Direct Domain Admin access via Pass-the-Hash")
        report.append("")

    # Password reuse analysis
    reuse = analyze_password_reuse(results["user_accounts"])
    if reuse:
        report.append(f"[HIGH] Password Reuse Detected ({len(reuse)} shared passwords):")
        for nt_hash, users in list(reuse.items())[:10]:
            report.append(f"  Hash ...{nt_hash[-8:]}: {', '.join(users[:5])}")
        report.append("")

    # Cleartext passwords
    if results["cleartext_passwords"]:
        report.append(f"[HIGH] Cleartext Passwords Found ({len(results['cleartext_passwords'])}):")
        for entry in results["cleartext_passwords"][:10]:
            report.append(f"  {entry['username']}: [REDACTED]")
        report.append("")

    report.extend([
        "[Persistence Opportunities]",
        "  1. Golden Ticket: Use KRBTGT hash for indefinite domain access",
        "  2. Silver Tickets: Use machine account hashes for service impersonation",
        "  3. Pass-the-Hash: Use NT hashes for immediate lateral movement",
        "  4. Password Cracking: Offline cracking of user hashes",
        "",
        "=" * 70
    ])

    return "\n".join(report)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python process.py <secretsdump_output.txt>")
        return

    source_file = sys.argv[1]
    results = parse_secretsdump_output(source_file)

    if not results["ntds_hashes"]:
        print("No NTDS hashes found in the input file.")
        return

    report = generate_dcsync_report(results, source_file)
    print(report)

    report_file = f"dcsync_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
