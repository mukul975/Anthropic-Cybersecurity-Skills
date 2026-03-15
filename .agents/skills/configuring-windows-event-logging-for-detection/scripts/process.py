#!/usr/bin/env python3
"""Windows Event Logging Auditor - Checks current audit policy configuration."""

import json, subprocess, sys, os
from datetime import datetime


def get_audit_policy() -> dict:
    """Query current advanced audit policy via auditpol."""
    try:
        result = subprocess.run(
            ["auditpol", "/get", "/category:*"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return {"error": result.stderr}

        policies = {}
        current_category = ""
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "  " not in line and line.endswith(":"):
                continue
            parts = line.rsplit("  ", 1)
            if len(parts) == 2:
                name = parts[0].strip()
                setting = parts[1].strip()
                policies[name] = setting
        return policies
    except FileNotFoundError:
        return {"error": "auditpol not available (requires Windows)"}


RECOMMENDED = {
    "Credential Validation": "Success and Failure",
    "Security Group Management": "Success",
    "User Account Management": "Success and Failure",
    "Logon": "Success and Failure",
    "Logoff": "Success",
    "Special Logon": "Success",
    "Process Creation": "Success",
    "Audit Policy Change": "Success",
    "Sensitive Privilege Use": "Success and Failure",
}


if __name__ == "__main__":
    policies = get_audit_policy()
    if "error" in policies:
        print(f"Error: {policies['error']}")
        sys.exit(1)

    compliant = 0
    total = len(RECOMMENDED)
    for setting, expected in RECOMMENDED.items():
        actual = policies.get(setting, "No Auditing")
        status = "PASS" if expected in actual else "FAIL"
        if status == "PASS":
            compliant += 1
        print(f"[{status}] {setting}: {actual} (expected: {expected})")

    print(f"\nScore: {compliant}/{total} ({round(compliant/total*100)}%)")
