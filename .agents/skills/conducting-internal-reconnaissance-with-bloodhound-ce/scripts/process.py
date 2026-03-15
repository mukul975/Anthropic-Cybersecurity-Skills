#!/usr/bin/env python3
"""
BloodHound CE Attack Path Analysis Script

Processes BloodHound CE data exports and generates prioritized
attack path reports. For authorized red team engagements only.
"""

import json
import sys
import os
from datetime import datetime
from collections import defaultdict


def load_bloodhound_data(filepath: str) -> dict:
    """Load BloodHound CE exported JSON data."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading data: {e}")
        return {}


def analyze_users(data: dict) -> dict:
    """Analyze user objects for attack opportunities."""
    analysis = {
        "total_users": 0,
        "enabled_users": 0,
        "kerberoastable": [],
        "asreproastable": [],
        "dcsync_capable": [],
        "admin_count_set": [],
        "password_not_required": [],
        "unconstrained_delegation": []
    }

    users = data.get("data", data.get("users", []))
    if isinstance(users, list):
        for user in users:
            props = user.get("Properties", user.get("properties", {}))
            name = props.get("name", props.get("samaccountname", "Unknown"))
            analysis["total_users"] += 1

            if props.get("enabled", True):
                analysis["enabled_users"] += 1

            if props.get("hasspn", False):
                analysis["kerberoastable"].append(name)

            if not props.get("dontreqpreauth", True) is False:
                if props.get("dontreqpreauth", False):
                    analysis["asreproastable"].append(name)

            if props.get("admincount", False):
                analysis["admin_count_set"].append(name)

            if props.get("passwordnotreqd", False):
                analysis["password_not_required"].append(name)

    return analysis


def analyze_computers(data: dict) -> dict:
    """Analyze computer objects for attack opportunities."""
    analysis = {
        "total_computers": 0,
        "unconstrained_delegation": [],
        "constrained_delegation": [],
        "laps_enabled": [],
        "laps_disabled": [],
        "unsupported_os": [],
        "domain_controllers": []
    }

    computers = data.get("data", data.get("computers", []))
    if isinstance(computers, list):
        for computer in computers:
            props = computer.get("Properties", computer.get("properties", {}))
            name = props.get("name", "Unknown")
            analysis["total_computers"] += 1

            if props.get("unconstraineddelegation", False):
                analysis["unconstrained_delegation"].append(name)

            if props.get("allowedtodelegate", []):
                analysis["constrained_delegation"].append({
                    "name": name,
                    "delegates_to": props.get("allowedtodelegate", [])
                })

            if props.get("haslaps", False):
                analysis["laps_enabled"].append(name)
            else:
                analysis["laps_disabled"].append(name)

            os_name = props.get("operatingsystem", "").lower()
            unsupported = ["2003", "2008", "xp", "vista", "windows 7"]
            if any(ver in os_name for ver in unsupported):
                analysis["unsupported_os"].append({
                    "name": name,
                    "os": props.get("operatingsystem", "Unknown")
                })

            if props.get("isdc", False):
                analysis["domain_controllers"].append(name)

    return analysis


def generate_report(user_analysis: dict, computer_analysis: dict) -> str:
    """Generate a comprehensive attack path analysis report."""
    report = [
        "=" * 70,
        "BloodHound CE Attack Path Analysis Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 70,
        "",
        "[User Analysis]",
        f"  Total Users: {user_analysis['total_users']}",
        f"  Enabled Users: {user_analysis['enabled_users']}",
        f"  Kerberoastable: {len(user_analysis['kerberoastable'])}",
        f"  AS-REP Roastable: {len(user_analysis['asreproastable'])}",
        f"  AdminCount Set: {len(user_analysis['admin_count_set'])}",
        f"  Password Not Required: {len(user_analysis['password_not_required'])}",
        ""
    ]

    if user_analysis["kerberoastable"]:
        report.append("  Kerberoastable Accounts:")
        for acct in user_analysis["kerberoastable"][:20]:
            report.append(f"    - {acct}")

    if user_analysis["asreproastable"]:
        report.append("  AS-REP Roastable Accounts:")
        for acct in user_analysis["asreproastable"][:20]:
            report.append(f"    - {acct}")

    report.extend([
        "",
        "[Computer Analysis]",
        f"  Total Computers: {computer_analysis['total_computers']}",
        f"  Domain Controllers: {len(computer_analysis['domain_controllers'])}",
        f"  Unconstrained Delegation: {len(computer_analysis['unconstrained_delegation'])}",
        f"  Constrained Delegation: {len(computer_analysis['constrained_delegation'])}",
        f"  LAPS Enabled: {len(computer_analysis['laps_enabled'])}",
        f"  LAPS Disabled: {len(computer_analysis['laps_disabled'])}",
        f"  Unsupported OS: {len(computer_analysis['unsupported_os'])}",
        ""
    ])

    if computer_analysis["unconstrained_delegation"]:
        report.append("  Unconstrained Delegation Computers:")
        for comp in computer_analysis["unconstrained_delegation"]:
            report.append(f"    - {comp}")

    if computer_analysis["unsupported_os"]:
        report.append("  Unsupported Operating Systems:")
        for comp in computer_analysis["unsupported_os"]:
            report.append(f"    - {comp['name']}: {comp['os']}")

    report.extend([
        "",
        "[Priority Attack Vectors]",
        "  1. Kerberoastable accounts with path to DA (crack SPN passwords)",
        "  2. AS-REP Roastable accounts (offline password cracking)",
        "  3. Unconstrained delegation abuse (TGT theft via coercion)",
        "  4. ACL-based paths (GenericAll, WriteDACL, ForceChangePassword)",
        "  5. GPO modification paths (code execution on privileged OUs)",
        "  6. Unsupported OS exploitation (unpatched vulnerabilities)",
        "",
        "=" * 70
    ])

    return "\n".join(report)


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python process.py <bloodhound_users.json> [bloodhound_computers.json]")
        return

    users_file = sys.argv[1]
    computers_file = sys.argv[2] if len(sys.argv) > 2 else None

    user_data = load_bloodhound_data(users_file)
    user_analysis = analyze_users(user_data)

    computer_analysis = {
        "total_computers": 0, "unconstrained_delegation": [],
        "constrained_delegation": [], "laps_enabled": [], "laps_disabled": [],
        "unsupported_os": [], "domain_controllers": []
    }

    if computers_file:
        computer_data = load_bloodhound_data(computers_file)
        computer_analysis = analyze_computers(computer_data)

    report = generate_report(user_analysis, computer_analysis)
    print(report)

    report_file = f"bloodhound_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"\nReport saved to: {report_file}")


if __name__ == "__main__":
    main()
