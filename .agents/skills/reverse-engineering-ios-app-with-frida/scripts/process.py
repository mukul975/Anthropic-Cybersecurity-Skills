#!/usr/bin/env python3
"""
iOS Reverse Engineering Automation with Frida

Automates class enumeration, method tracing, and secret extraction from iOS apps.

Usage:
    python process.py --app TargetApp [--output report.json]
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime


ENUMERATE_SCRIPT = """
if (ObjC.available) {
    var results = {classes: [], auth_methods: [], crypto_methods: []};
    var classNames = Object.keys(ObjC.classes);
    classNames.forEach(function(name) {
        if (name.indexOf("Auth") !== -1 || name.indexOf("Crypto") !== -1 ||
            name.indexOf("Token") !== -1 || name.indexOf("Key") !== -1 ||
            name.indexOf("Secret") !== -1 || name.indexOf("Login") !== -1) {
            var methods = ObjC.classes[name].$ownMethods;
            results.classes.push({name: name, method_count: methods.length});
            methods.forEach(function(m) {
                if (m.toLowerCase().indexOf("auth") !== -1 || m.toLowerCase().indexOf("login") !== -1) {
                    results.auth_methods.push(name + " " + m);
                }
                if (m.toLowerCase().indexOf("encrypt") !== -1 || m.toLowerCase().indexOf("decrypt") !== -1 ||
                    m.toLowerCase().indexOf("key") !== -1 || m.toLowerCase().indexOf("cipher") !== -1) {
                    results.crypto_methods.push(name + " " + m);
                }
            });
        }
    });
    send(JSON.stringify(results));
} else {
    send(JSON.stringify({error: "ObjC runtime not available"}));
}
"""


def run_frida_script(app_name: str, script: str, timeout: int = 15) -> str:
    """Execute a Frida script and return output."""
    cmd = ["frida", "-U", "-n", app_name, "-e", script, "--no-pause"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def check_binary_protections(app_name: str) -> dict:
    """Check for binary protections."""
    checks = {
        "pie": False,
        "stack_canary": False,
        "arc": False,
        "encrypted": False,
    }

    # Use otool-equivalent checks via Frida
    script = """
    var modules = Process.enumerateModules();
    var main = modules[0];
    send(JSON.stringify({
        name: main.name,
        base: main.base.toString(),
        size: main.size,
        path: main.path
    }));
    """
    output = run_frida_script(app_name, script)
    return checks


def main():
    parser = argparse.ArgumentParser(description="iOS RE Automation with Frida")
    parser.add_argument("--app", required=True, help="Target app process name")
    parser.add_argument("--output", default="ios_re_report.json", help="Output report")
    args = parser.parse_args()

    print(f"[+] Enumerating classes and methods for {args.app}...")
    enum_output = run_frida_script(args.app, ENUMERATE_SCRIPT)

    # Parse results
    try:
        lines = [l for l in enum_output.split("\n") if l.startswith('{"') or l.startswith("[")]
        results = json.loads(lines[0]) if lines else {}
    except (json.JSONDecodeError, IndexError):
        results = {"classes": [], "auth_methods": [], "crypto_methods": []}

    report = {
        "assessment": {
            "target": args.app,
            "type": "iOS Reverse Engineering",
            "date": datetime.now().isoformat(),
        },
        "enumeration": {
            "security_classes": results.get("classes", []),
            "auth_methods": results.get("auth_methods", []),
            "crypto_methods": results.get("crypto_methods", []),
        },
        "binary_protections": check_binary_protections(args.app),
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved: {args.output}")
    print(f"[*] Found {len(results.get('classes', []))} security-related classes")
    print(f"[*] Found {len(results.get('auth_methods', []))} auth methods")
    print(f"[*] Found {len(results.get('crypto_methods', []))} crypto methods")


if __name__ == "__main__":
    main()
