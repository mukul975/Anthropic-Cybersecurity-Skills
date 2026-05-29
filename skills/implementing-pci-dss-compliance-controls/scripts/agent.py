#!/usr/bin/env python3
"""PCI DSS compliance control audit agent.

Audits systems and configurations against PCI DSS v4.0 requirements
including network segmentation, encryption, access controls, logging,
vulnerability management, and secure configuration checks.
"""
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone


def check_tls_configuration(host, port=443):
    """PCI DSS Req 4.2.1 - Strong cryptography for transmission."""
    findings = []
    print(f"[*] Req 4.2.1: Checking TLS on {host}:{port}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version()
                cipher = ssock.cipher()
                if protocol in ("TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "requirement": "4.2.1", "check": "TLS Protocol Version",
                        "status": "FAIL", "severity": "CRITICAL",
                        "detail": f"Deprecated protocol: {protocol}",
                    })
                else:
                    findings.append({
                        "requirement": "4.2.1", "check": "TLS Protocol Version",
                        "status": "PASS", "severity": "INFO",
                        "detail": f"Protocol: {protocol}",
                    })
                if cipher:
                    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                    if any(w in cipher[0] for w in weak_ciphers):
                        findings.append({
                            "requirement": "4.2.1", "check": "Cipher Strength",
                            "status": "FAIL", "severity": "HIGH",
                            "detail": f"Weak cipher: {cipher[0]}",
                        })
                    else:
                        findings.append({
                            "requirement": "4.2.1", "check": "Cipher Strength",
                            "status": "PASS", "severity": "INFO",
                            "detail": f"Cipher: {cipher[0]} ({cipher[2]} bits)",
                        })
    except Exception as e:
        findings.append({
            "requirement": "4.2.1", "check": "TLS Connection",
            "status": "ERROR", "severity": "HIGH", "detail": str(e)[:100],
        })
    return findings


def check_password_policy():
    """PCI DSS Req 8.3.6 - Password complexity requirements."""
    findings = []
    print("[*] Req 8.3.6: Checking password policy")

    if sys.platform != "win32":
        # Check PAM password quality
        pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth",
                     "/etc/security/pwquality.conf"]
        for pam_file in pam_files:
            if os.path.isfile(pam_file):
                with open(pam_file, "r") as f:
                    content = f.read()
                if "minlen" in content:
                    match = re.search(r'minlen\s*=\s*(\d+)', content)
                    if match and int(match.group(1)) >= 12:
                        findings.append({
                            "requirement": "8.3.6", "check": "Min password length",
                            "status": "PASS", "severity": "INFO",
                            "detail": f"minlen={match.group(1)} in {pam_file}",
                        })
                    else:
                        findings.append({
                            "requirement": "8.3.6", "check": "Min password length",
                            "status": "FAIL", "severity": "HIGH",
                            "detail": f"Password minlen < 12 in {pam_file}",
                        })
                break
        else:
            findings.append({
                "requirement": "8.3.6", "check": "Password policy config",
                "status": "WARN", "severity": "MEDIUM",
                "detail": "Could not find PAM password config",
            })
    return findings


def check_audit_logging():
    """PCI DSS Req 10.2 - Audit logging configuration."""
    findings = []
    print("[*] Req 10.2: Checking audit logging")

    if sys.platform != "win32":
        # Check auditd
        result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, timeout=10,
        )
        if result.stdout.strip() == "active":
            findings.append({
                "requirement": "10.2", "check": "Audit daemon running",
                "status": "PASS", "severity": "INFO",
            })
        else:
            findings.append({
                "requirement": "10.2", "check": "Audit daemon running",
                "status": "FAIL", "severity": "CRITICAL",
                "detail": "auditd is not running",
            })

        # Check syslog
        for syslog in ["rsyslog", "syslog-ng"]:
            result = subprocess.run(
                ["systemctl", "is-active", syslog],
                capture_output=True, text=True, timeout=10,
            )
            if result.stdout.strip() == "active":
                findings.append({
                    "requirement": "10.2", "check": f"{syslog} running",
                    "status": "PASS", "severity": "INFO",
                })
                break
    return findings


def check_file_integrity():
    """PCI DSS Req 11.5.2 - File integrity monitoring."""
    findings = []
    print("[*] Req 11.5.2: Checking file integrity monitoring")

    fim_tools = {
        "aide": ["/usr/bin/aide", "/usr/sbin/aide"],
        "ossec": ["/var/ossec/bin/ossec-syscheckd"],
        "tripwire": ["/usr/sbin/tripwire"],
        "samhain": ["/usr/local/sbin/samhain"],
    }

    found_fim = False
    for tool_name, paths in fim_tools.items():
        for path in paths:
            if os.path.isfile(path):
                findings.append({
                    "requirement": "11.5.2", "check": f"FIM tool: {tool_name}",
                    "status": "PASS", "severity": "INFO",
                    "detail": f"Found at {path}",
                })
                found_fim = True
                break

    if not found_fim:
        findings.append({
            "requirement": "11.5.2", "check": "File integrity monitoring",
            "status": "FAIL", "severity": "HIGH",
            "detail": "No FIM tool detected (AIDE, OSSEC, Tripwire, Samhain)",
        })

    return findings


def check_default_credentials():
    """PCI DSS Req 2.2.2 - Change vendor defaults."""
    findings = []
    print("[*] Req 2.2.2: Checking for default credentials")

    # Check for common default accounts
    if os.path.isfile("/etc/passwd"):
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 7:
                    username = parts[0]
                    shell = parts[6]
                    if username in ("guest", "test", "demo", "admin") and shell not in ("/usr/sbin/nologin", "/bin/false"):
                        findings.append({
                            "requirement": "2.2.2", "check": f"Default account: {username}",
                            "status": "FAIL", "severity": "HIGH",
                            "detail": f"Account '{username}' has login shell: {shell}",
                        })

    return findings


def check_network_segmentation(target_ip, ports=None):
    """PCI DSS Req 1.3 - Network segmentation check."""
    findings = []
    if not ports:
        ports = [22, 80, 443, 3306, 5432, 1433, 6379, 9200, 27017]
    print(f"[*] Req 1.3: Checking network segmentation to {target_ip}")

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                findings.append({
                    "requirement": "1.3", "check": f"Port {port} reachable",
                    "status": "WARN", "severity": "MEDIUM",
                    "detail": f"{target_ip}:{port} is open from this network segment",
                })
        except Exception:
            pass

    if not findings:
        findings.append({
            "requirement": "1.3", "check": "Network segmentation",
            "status": "PASS", "severity": "INFO",
            "detail": f"No tested ports reachable on {target_ip}",
        })

    return findings


def format_summary(all_findings):
    """Print PCI DSS audit summary."""
    print(f"\n{'='*60}")
    print("  PCI DSS v4.0 Compliance Audit Report")
    print(f"{'='*60}")

    pass_count = sum(1 for f in all_findings if f["status"] == "PASS")
    fail_count = sum(1 for f in all_findings if f["status"] == "FAIL")
    warn_count = sum(1 for f in all_findings if f["status"] == "WARN")

    print(f"  Total Checks : {len(all_findings)}")
    print(f"  Passed       : {pass_count}")
    print(f"  Failed       : {fail_count}")
    print(f"  Warnings     : {warn_count}")

    by_req = {}
    for f in all_findings:
        req = f.get("requirement", "unknown")
        by_req.setdefault(req, []).append(f)

    print("\n  Results by Requirement:")
    for req in sorted(by_req.keys()):
        items = by_req[req]
        failed = sum(1 for i in items if i["status"] == "FAIL")
        passed = sum(1 for i in items if i["status"] == "PASS")
        status = "FAIL" if failed > 0 else "PASS"
        print(f"    Req {req:8s}: [{status:4s}] {passed} passed, {failed} failed")

    if fail_count > 0:
        print("\n  Failed Checks:")
        for f in all_findings:
            if f["status"] == "FAIL":
                print(f"    [{f['severity']:8s}] Req {f['requirement']}: {f['check']} - {f.get('detail', '')}")

    severity_counts = {}
    for f in all_findings:
        if f["status"] == "FAIL":
            sev = f.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="PCI DSS compliance control audit agent")
    parser.add_argument("--tls-host", help="Host to check TLS configuration")
    parser.add_argument("--tls-port", type=int, default=443)
    parser.add_argument("--segment-target", help="IP to check network segmentation")
    parser.add_argument("--skip-password", action="store_true")
    parser.add_argument("--skip-logging", action="store_true")
    parser.add_argument("--skip-fim", action="store_true")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    all_findings = []

    if args.tls_host:
        all_findings.extend(check_tls_configuration(args.tls_host, args.tls_port))
    if not args.skip_password:
        all_findings.extend(check_password_policy())
    if not args.skip_logging:
        all_findings.extend(check_audit_logging())
    if not args.skip_fim:
        all_findings.extend(check_file_integrity())
    all_findings.extend(check_default_credentials())
    if args.segment_target:
        all_findings.extend(check_network_segmentation(args.segment_target))

    if not all_findings:
        print("[!] No checks performed. Use --tls-host or other options.", file=sys.stderr)
        sys.exit(1)

    severity_counts = format_summary(all_findings)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "PCI DSS Audit",
        "standard": "PCI DSS v4.0",
        "findings": all_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if severity_counts.get("MEDIUM", 0) > 0
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
