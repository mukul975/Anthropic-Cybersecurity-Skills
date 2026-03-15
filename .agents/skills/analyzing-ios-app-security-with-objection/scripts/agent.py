#!/usr/bin/env python3
"""iOS app security analysis agent using Objection/Frida concepts.

Performs runtime security assessment of iOS apps including SSL pinning bypass,
keychain dumping, filesystem inspection, and jailbreak detection bypass.
"""

import subprocess
import json
import os
import sys
import re


def run_objection(command, app_id=None, timeout=30):
    """Execute an Objection command against a target app."""
    cmd = ["objection"]
    if app_id:
        cmd.extend(["-g", app_id])
    cmd.extend(["explore", "-c", command])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.returncode
    except FileNotFoundError:
        return "objection not installed (pip install objection)", 1
    except subprocess.TimeoutExpired:
        return "Command timed out", 1


def run_frida(script_code, app_id, timeout=30):
    """Execute a Frida script against target app."""
    cmd = ["frida", "-U", "-n", app_id, "-e", script_code]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.returncode
    except FileNotFoundError:
        return "frida not installed (pip install frida-tools)", 1
    except subprocess.TimeoutExpired:
        return "Command timed out", 1


def dump_keychain(app_id):
    """Dump keychain items accessible by the application."""
    return run_objection("ios keychain dump", app_id)


def dump_cookies(app_id):
    """Dump HTTP cookies stored by the application."""
    return run_objection("ios cookies get", app_id)


def list_classes(app_id, filter_str=None):
    """List Objective-C classes loaded in the app."""
    cmd = "ios hooking list classes"
    if filter_str:
        cmd += f" --include {filter_str}"
    return run_objection(cmd, app_id)


def check_ssl_pinning(app_id):
    """Check and bypass SSL certificate pinning."""
    return run_objection("ios sslpinning disable", app_id)


def check_jailbreak_detection(app_id):
    """Check for and bypass jailbreak detection."""
    return run_objection("ios jailbreak disable", app_id)


def inspect_filesystem(app_id, path="/"):
    """Inspect the application's filesystem sandbox."""
    return run_objection(f"ls {path}", app_id)


def dump_plist(app_id):
    """Dump application plist configuration files."""
    return run_objection("ios plist cat Info.plist", app_id)


def check_pasteboard(app_id):
    """Check pasteboard/clipboard for sensitive data."""
    return run_objection("ios pasteboard monitor", app_id)


def search_binary_strings(app_id, pattern):
    """Search for strings in the app binary."""
    return run_objection(f"memory search '{pattern}'", app_id)


OWASP_MOBILE_CHECKS = {
    "M1_Improper_Platform_Usage": {
        "checks": ["ios keychain dump", "ios plist cat Info.plist"],
        "description": "Check for misuse of platform security features",
    },
    "M2_Insecure_Data_Storage": {
        "checks": ["ios keychain dump", "ios cookies get", "ios nsuserdefaults get"],
        "description": "Check for sensitive data in insecure storage",
    },
    "M3_Insecure_Communication": {
        "checks": ["ios sslpinning disable"],
        "description": "Test SSL/TLS implementation and certificate pinning",
    },
    "M4_Insecure_Authentication": {
        "checks": ["ios hooking list classes --include Auth",
                    "ios hooking list classes --include Login"],
        "description": "Analyze authentication mechanisms",
    },
    "M5_Insufficient_Cryptography": {
        "checks": ["ios hooking list classes --include Crypto",
                    "ios hooking list classes --include AES"],
        "description": "Review cryptographic implementations",
    },
    "M8_Code_Tampering": {
        "checks": ["ios jailbreak disable"],
        "description": "Test runtime integrity and jailbreak detection",
    },
    "M9_Reverse_Engineering": {
        "checks": ["ios hooking list classes"],
        "description": "Assess reverse engineering protections",
    },
}


def run_owasp_assessment(app_id):
    """Run OWASP Mobile Top 10 security checks."""
    results = {}
    for category, config in OWASP_MOBILE_CHECKS.items():
        category_results = {"description": config["description"], "findings": []}
        for check in config["checks"]:
            output, rc = run_objection(check, app_id)
            category_results["findings"].append({
                "command": check,
                "status": "success" if rc == 0 else "failed",
                "output_preview": output[:200] if output else "",
            })
        results[category] = category_results
    return results


FRIDA_SCRIPTS = {
    "ssl_pinning_bypass": """
ObjC.choose(ObjC.classes.NSURLSessionConfiguration, {
    onMatch: function(instance) {
        instance['- setTLSMinimumSupportedProtocol:'](0);
    }, onComplete: function() {}
});
""",
    "jailbreak_bypass": """
var paths = ['/Applications/Cydia.app', '/usr/sbin/sshd', '/etc/apt'];
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) { this.path = ObjC.Object(args[2]).toString(); },
    onLeave: function(retval) {
        if (paths.some(p => this.path.includes(p))) retval.replace(0);
    }
});
""",
    "keychain_dump": """
var kSecClass = ObjC.classes.__NSDictionary.dictionaryWithObject_forKey_(
    ObjC.classes.__NSCFConstantString.alloc().initWithUTF8String_('genp'),
    ObjC.classes.__NSCFConstantString.alloc().initWithUTF8String_('class')
);
console.log('Keychain query prepared');
""",
}


def generate_report(app_id, assessment_results):
    """Generate iOS security assessment report."""
    findings_count = sum(
        len(cat["findings"]) for cat in assessment_results.values()
    )
    return {
        "app_identifier": app_id,
        "assessment_framework": "OWASP Mobile Top 10",
        "categories_tested": len(assessment_results),
        "total_checks": findings_count,
        "results": assessment_results,
    }


if __name__ == "__main__":
    print("=" * 60)
    print("iOS App Security Analysis Agent (Objection/Frida)")
    print("Runtime analysis, SSL bypass, keychain dump, OWASP checks")
    print("=" * 60)

    app_id = sys.argv[1] if len(sys.argv) > 1 else None

    if not app_id:
        print("\n[DEMO] Usage: python agent.py <app_bundle_id>")
        print("  e.g. python agent.py com.example.app")
        print("\nAvailable checks:")
        for category, config in OWASP_MOBILE_CHECKS.items():
            print(f"  {category}: {config['description']}")
        print("\nFrida scripts available:")
        for name in FRIDA_SCRIPTS:
            print(f"  {name}")
        sys.exit(0)

    print(f"\n[*] Target: {app_id}")
    print("[*] Running OWASP Mobile Top 10 assessment...")

    results = run_owasp_assessment(app_id)
    report = generate_report(app_id, results)

    for category, data in results.items():
        status_counts = {"success": 0, "failed": 0}
        for f in data["findings"]:
            status_counts[f["status"]] += 1
        print(f"\n  [{category}] {data['description']}")
        print(f"    Checks: {status_counts['success']} passed, {status_counts['failed']} failed")

    print(f"\n{json.dumps(report, indent=2, default=str)}")
