#!/usr/bin/env python3
"""Container image hardening audit agent.

Audits Docker container images for security hardening best practices
using Trivy for vulnerability scanning, Dockle for CIS Docker Benchmark
compliance, and Dockerfile analysis for security anti-patterns.
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone


def find_binary(name):
    """Locate a binary on the system PATH."""
    for ext in ["", ".exe"]:
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            full_path = os.path.join(directory, name + ext)
            if os.path.isfile(full_path):
                return full_path
    return None


def run_trivy_image_scan(image, severity="CRITICAL,HIGH", ignore_unfixed=True):
    """Scan a container image with Trivy for vulnerabilities."""
    trivy_bin = find_binary("trivy")
    if not trivy_bin:
        print("[!] trivy not found. Install: https://github.com/aquasecurity/trivy",
              file=sys.stderr)
        return None

    cmd = [trivy_bin, "image", "--format", "json", "--severity", severity]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(image)

    print(f"[*] Running Trivy scan: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0 and not result.stdout:
        print(f"[!] Trivy error: {result.stderr[:300]}", file=sys.stderr)
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def run_dockle_scan(image):
    """Scan a container image with Dockle for CIS benchmark compliance."""
    dockle_bin = find_binary("dockle")
    if not dockle_bin:
        print("[*] dockle not found, skipping CIS benchmark check", file=sys.stderr)
        return None

    cmd = [dockle_bin, "--format", "json", image]
    print(f"[*] Running Dockle scan: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def analyze_dockerfile(dockerfile_path):
    """Analyze a Dockerfile for security anti-patterns."""
    findings = []
    if not os.path.isfile(dockerfile_path):
        return findings

    with open(dockerfile_path, "r") as f:
        lines = f.readlines()

    runs_as_root = True
    has_healthcheck = False
    uses_latest_tag = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        upper = stripped.upper()

        if upper.startswith("FROM") and ":latest" in stripped:
            uses_latest_tag = True
            findings.append({
                "check": "FROM uses :latest tag",
                "line": i,
                "severity": "HIGH",
                "description": "Pin image to a specific version for reproducibility and security",
                "content": stripped,
            })

        if upper.startswith("FROM") and "scratch" not in stripped.lower():
            base = stripped.split()[-1] if stripped.split() else ""
            if "alpine" not in base.lower() and "distroless" not in base.lower():
                findings.append({
                    "check": "Non-minimal base image",
                    "line": i,
                    "severity": "MEDIUM",
                    "description": "Consider using Alpine or distroless base for smaller attack surface",
                    "content": stripped,
                })

        if upper.startswith("USER") and stripped.split()[-1] not in ("root", "0"):
            runs_as_root = False

        if upper.startswith("HEALTHCHECK"):
            has_healthcheck = True

        if upper.startswith("RUN") and ("chmod 777" in stripped or "chmod -R 777" in stripped):
            findings.append({
                "check": "Overly permissive chmod 777",
                "line": i,
                "severity": "HIGH",
                "description": "chmod 777 grants world-writable permissions; use specific permissions",
                "content": stripped,
            })

        if upper.startswith("RUN") and "curl" in stripped and "| sh" in stripped:
            findings.append({
                "check": "Pipe to shell from curl",
                "line": i,
                "severity": "CRITICAL",
                "description": "Piping curl output to shell is risky; download, verify, then execute",
                "content": stripped,
            })

        if upper.startswith("ENV") and any(kw in upper for kw in ["PASSWORD", "SECRET", "TOKEN", "API_KEY"]):
            findings.append({
                "check": "Secrets in ENV instruction",
                "line": i,
                "severity": "CRITICAL",
                "description": "Never embed secrets in Dockerfile; use build args or secrets mount",
                "content": stripped,
            })

        if upper.startswith("ADD") and not stripped.endswith(".tar.gz"):
            findings.append({
                "check": "ADD instead of COPY",
                "line": i,
                "severity": "LOW",
                "description": "Use COPY unless you need ADD's auto-extraction; COPY is more explicit",
                "content": stripped,
            })

        if upper.startswith("EXPOSE") and any(p in stripped for p in ["22", "23", "3389"]):
            findings.append({
                "check": "Exposed management port",
                "line": i,
                "severity": "HIGH",
                "description": "SSH/Telnet/RDP ports should not be exposed in containers",
                "content": stripped,
            })

    if runs_as_root:
        findings.append({
            "check": "Container runs as root",
            "line": 0,
            "severity": "HIGH",
            "description": "Add a USER instruction to run as non-root for least privilege",
        })

    if not has_healthcheck:
        findings.append({
            "check": "Missing HEALTHCHECK",
            "line": 0,
            "severity": "LOW",
            "description": "Add HEALTHCHECK to enable container health monitoring",
        })

    return findings


def extract_trivy_findings(trivy_data):
    """Extract vulnerability findings from Trivy JSON output."""
    findings = []
    if not trivy_data:
        return findings
    results = trivy_data.get("Results", [])
    for result in results:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "source": "trivy",
                "target": target,
                "vulnerability_id": vuln.get("VulnerabilityID", ""),
                "pkg_name": vuln.get("PkgName", ""),
                "installed_version": vuln.get("InstalledVersion", ""),
                "fixed_version": vuln.get("FixedVersion", ""),
                "severity": vuln.get("Severity", "UNKNOWN"),
                "title": vuln.get("Title", ""),
                "description": vuln.get("Description", "")[:200],
            })
    return findings


def extract_dockle_findings(dockle_data):
    """Extract CIS benchmark findings from Dockle JSON output."""
    findings = []
    if not dockle_data:
        return findings
    for detail in dockle_data.get("details", []):
        severity_map = {"FATAL": "CRITICAL", "WARN": "HIGH", "INFO": "MEDIUM", "SKIP": "LOW"}
        findings.append({
            "source": "dockle",
            "code": detail.get("code", ""),
            "title": detail.get("title", ""),
            "level": detail.get("level", "INFO"),
            "severity": severity_map.get(detail.get("level", "INFO"), "MEDIUM"),
            "alerts": detail.get("alerts", []),
        })
    return findings


def format_summary(image, trivy_findings, dockle_findings, dockerfile_findings):
    """Print combined audit summary."""
    all_findings = trivy_findings + dockle_findings + dockerfile_findings
    print(f"\n{'='*60}")
    print("  Container Image Hardening Audit")
    print(f"{'='*60}")
    print(f"  Image          : {image}")
    print(f"  Vulnerabilities: {len(trivy_findings)} (Trivy)")
    print(f"  CIS Benchmark  : {len(dockle_findings)} (Dockle)")
    print(f"  Dockerfile     : {len(dockerfile_findings)}")
    print(f"  Total Findings : {len(all_findings)}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  By Severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            print(f"    {sev:10s}: {count}")

    if trivy_findings:
        print("\n  Top Vulnerabilities:")
        for f in trivy_findings[:10]:
            print(f"    {f['vulnerability_id']:16s} | {f['severity']:8s} | "
                  f"{f['pkg_name']}:{f['installed_version']} -> {f.get('fixed_version', 'N/A')}")

    if dockerfile_findings:
        print("\n  Dockerfile Issues:")
        for f in dockerfile_findings:
            print(f"    [{f['severity']:8s}] Line {f.get('line', 0):3d}: {f['check']}")

    return severity_counts


def main():
    parser = argparse.ArgumentParser(
        description="Container image hardening audit agent"
    )
    parser.add_argument("--image", required=True, help="Container image to scan (e.g., nginx:1.25)")
    parser.add_argument("--dockerfile", help="Path to Dockerfile for static analysis")
    parser.add_argument("--severity", default="CRITICAL,HIGH",
                        help="Trivy severity filter (default: CRITICAL,HIGH)")
    parser.add_argument("--skip-trivy", action="store_true", help="Skip Trivy scan")
    parser.add_argument("--skip-dockle", action="store_true", help="Skip Dockle scan")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    trivy_findings = []
    dockle_findings = []
    dockerfile_findings = []

    if not args.skip_trivy:
        trivy_data = run_trivy_image_scan(args.image, args.severity)
        trivy_findings = extract_trivy_findings(trivy_data)

    if not args.skip_dockle:
        dockle_data = run_dockle_scan(args.image)
        dockle_findings = extract_dockle_findings(dockle_data)

    if args.dockerfile:
        dockerfile_findings = analyze_dockerfile(args.dockerfile)

    severity_counts = format_summary(
        args.image, trivy_findings, dockle_findings, dockerfile_findings
    )

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "Container Hardening Audit",
        "image": args.image,
        "severity_counts": severity_counts,
        "trivy_findings": trivy_findings,
        "dockle_findings": dockle_findings,
        "dockerfile_findings": dockerfile_findings,
        "total_findings": len(trivy_findings) + len(dockle_findings) + len(dockerfile_findings),
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
