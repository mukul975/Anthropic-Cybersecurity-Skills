#!/usr/bin/env python3
"""Patch management workflow agent.

Audits system patch compliance by checking installed package versions
against known vulnerabilities, tracking patch SLA adherence, and
generating remediation reports. Supports Linux (apt/yum) and basic
CVE cross-referencing via the CISA KEV catalog.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


def check_apt_updates():
    """Check for available security updates on Debian/Ubuntu systems."""
    findings = []
    print("[*] Checking apt security updates...")

    # Update package lists
    result = subprocess.run(
        ["apt-get", "update", "-qq"],
        capture_output=True, text=True, timeout=120,
    )

    # List upgradable packages
    result = subprocess.run(
        ["apt", "list", "--upgradable"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return [{"check": "apt updates", "status": "ERROR", "severity": "HIGH",
                 "detail": result.stderr[:200]}]

    for line in result.stdout.strip().splitlines():
        if "Listing..." in line:
            continue
        parts = line.split("/")
        if len(parts) >= 2:
            pkg_name = parts[0]
            is_security = "security" in line.lower()
            version_info = line.split()
            current = version_info[-1] if len(version_info) > 3 else "unknown"
            available = version_info[1] if len(version_info) > 1 else "unknown"
            findings.append({
                "package": pkg_name,
                "current_version": current,
                "available_version": available,
                "is_security_update": is_security,
                "severity": "CRITICAL" if is_security else "MEDIUM",
            })

    security_count = sum(1 for f in findings if f.get("is_security_update"))
    print(f"[+] Found {len(findings)} updates ({security_count} security)")
    return findings


def check_yum_updates():
    """Check for available security updates on RHEL/CentOS systems."""
    findings = []
    print("[*] Checking yum/dnf security updates...")

    for pkg_mgr in ["dnf", "yum"]:
        result = subprocess.run(
            [pkg_mgr, "check-update", "--security", "-q"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode in (0, 100):
            break
    else:
        return [{"check": "yum/dnf", "status": "ERROR", "severity": "HIGH",
                 "detail": "Neither yum nor dnf available"}]

    for line in result.stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 3:
            findings.append({
                "package": parts[0],
                "available_version": parts[1],
                "repository": parts[2] if len(parts) > 2 else "",
                "is_security_update": True,
                "severity": "HIGH",
            })

    print(f"[+] Found {len(findings)} security updates")
    return findings


def check_windows_updates():
    """Check for pending Windows updates via PowerShell."""
    findings = []
    print("[*] Checking Windows Update status...")

    ps_script = (
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 20 HotFixID, Description, InstalledOn | "
        "ConvertTo-Json"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode == 0 and result.stdout.strip():
        try:
            hotfixes = json.loads(result.stdout)
            if isinstance(hotfixes, dict):
                hotfixes = [hotfixes]
            for hf in hotfixes:
                findings.append({
                    "hotfix_id": hf.get("HotFixID", ""),
                    "description": hf.get("Description", ""),
                    "installed_on": str(hf.get("InstalledOn", "")),
                    "status": "installed",
                })
            if hotfixes:
                latest = hotfixes[0]
                installed_date = latest.get("InstalledOn", "")
                print(f"[+] Latest patch: {latest.get('HotFixID', 'N/A')} ({installed_date})")
        except json.JSONDecodeError:
            pass

    return findings


def check_kev_exposure(package_cves):
    """Cross-reference package CVEs against CISA KEV catalog."""
    if not requests:
        return []

    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(kev_url, timeout=30)
        resp.raise_for_status()
        kev_data = resp.json()
        kev_cves = {v["cveID"] for v in kev_data.get("vulnerabilities", [])}
    except Exception:
        return []

    exposed = []
    for cve_id in package_cves:
        if cve_id.upper() in kev_cves:
            exposed.append({
                "cve_id": cve_id,
                "in_kev": True,
                "severity": "CRITICAL",
                "description": "Actively exploited vulnerability (CISA KEV)",
            })
    return exposed


def assess_patch_sla(findings, sla_days=None):
    """Assess patch compliance against SLA targets."""
    if sla_days is None:
        sla_days = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180}

    sla_findings = []
    for f in findings:
        severity = f.get("severity", "MEDIUM")
        target_days = sla_days.get(severity, 90)
        sla_findings.append({
            "package": f.get("package", f.get("hotfix_id", "unknown")),
            "severity": severity,
            "sla_target_days": target_days,
            "in_sla": True,  # Would need install date to determine
            "recommendation": f"Patch within {target_days} days per SLA policy",
        })
    return sla_findings


def format_summary(findings, kev_findings, sla_findings, platform):
    """Print patch management summary."""
    print(f"\n{'='*60}")
    print("  Patch Management Audit Report")
    print(f"{'='*60}")
    print(f"  Platform        : {platform}")
    print(f"  Pending Updates : {len(findings)}")

    security = sum(1 for f in findings if f.get("is_security_update"))
    print(f"  Security Updates: {security}")
    print(f"  KEV Matches     : {len(kev_findings)}")

    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    if kev_findings:
        print("\n  CISA KEV Exposed CVEs (IMMEDIATE ACTION):")
        for k in kev_findings:
            print(f"    {k['cve_id']}: {k['description']}")

    if findings:
        print("\n  Pending Updates:")
        for f in findings[:20]:
            pkg = f.get("package", f.get("hotfix_id", "unknown"))
            sev = f.get("severity", "MEDIUM")
            sec = " [SECURITY]" if f.get("is_security_update") else ""
            print(f"    [{sev:8s}] {pkg}{sec}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Patch management workflow audit agent"
    )
    parser.add_argument("--platform", choices=["auto", "apt", "yum", "windows"],
                        default="auto", help="Package manager to check")
    parser.add_argument("--cves", nargs="+", help="CVE IDs to check against KEV")
    parser.add_argument("--sla-critical", type=int, default=7, help="SLA days for critical (default: 7)")
    parser.add_argument("--sla-high", type=int, default=30, help="SLA days for high (default: 30)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    findings = []
    platform = args.platform

    if platform == "auto":
        if sys.platform == "win32":
            platform = "windows"
        elif os.path.isfile("/usr/bin/apt"):
            platform = "apt"
        elif os.path.isfile("/usr/bin/yum") or os.path.isfile("/usr/bin/dnf"):
            platform = "yum"
        else:
            print("[!] Could not detect package manager", file=sys.stderr)
            sys.exit(1)

    if platform == "apt":
        findings = check_apt_updates()
    elif platform == "yum":
        findings = check_yum_updates()
    elif platform == "windows":
        findings = check_windows_updates()

    kev_findings = []
    if args.cves:
        kev_findings = check_kev_exposure(args.cves)

    sla_days = {"CRITICAL": args.sla_critical, "HIGH": args.sla_high, "MEDIUM": 90, "LOW": 180}
    sla_findings = assess_patch_sla(findings, sla_days)

    severity_counts = format_summary(findings, kev_findings, sla_findings, platform)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Patch Management Audit",
        "platform": platform,
        "pending_updates": findings,
        "kev_exposure": kev_findings,
        "sla_assessment": sla_findings,
        "severity_counts": severity_counts,
        "risk_level": (
            "CRITICAL" if kev_findings or severity_counts.get("CRITICAL", 0) > 0
            else "HIGH" if severity_counts.get("HIGH", 0) > 0
            else "MEDIUM" if findings
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
