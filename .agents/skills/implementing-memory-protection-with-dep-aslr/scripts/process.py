#!/usr/bin/env python3
"""Memory Protection Auditor - Checks exploit mitigation status on Windows."""

import json, subprocess, sys, os
from datetime import datetime


def check_mitigations() -> dict:
    ps_cmd = """
    $sys = Get-ProcessMitigation -System
    $apps = Get-ProcessMitigation -Name * 2>$null | Select-Object -First 20
    @{System = $sys; Apps = $apps} | ConvertTo-Json -Depth 3
    """
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                          capture_output=True, text=True, timeout=30)
        return json.loads(r.stdout) if r.returncode == 0 else {"error": r.stderr}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    result = check_mitigations()
    if "error" in result:
        print(f"Error: {result['error']}")
        print("This tool requires Windows with Exploit Protection support.")
        sys.exit(1)
    out = sys.argv[1] if len(sys.argv) > 1 else "memory_protection_audit.json"
    with open(out, "w") as f:
        json.dump({"generated": datetime.utcnow().isoformat() + "Z", **result}, f, indent=2)
    print(f"Report: {out}")
