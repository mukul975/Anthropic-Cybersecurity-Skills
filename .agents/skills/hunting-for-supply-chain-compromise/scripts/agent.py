#!/usr/bin/env python3
"""Agent for hunting supply chain compromise indicators in software dependencies and builds."""

import json
import argparse
import hashlib
import re
import subprocess
from datetime import datetime
from pathlib import Path


KNOWN_COMPROMISED_PACKAGES = {
    "event-stream": "npm", "ua-parser-js": "npm", "coa": "npm",
    "colors": "npm", "faker": "npm", "node-ipc": "npm",
    "ctx": "pypi", "phpass": "pypi",
}


def scan_npm_lockfile(lockfile_path):
    """Scan package-lock.json for suspicious dependencies."""
    with open(lockfile_path) as f:
        data = json.load(f)
    findings = []
    packages = data.get("packages", data.get("dependencies", {}))
    for name, info in packages.items():
        pkg_name = name.split("node_modules/")[-1] if "node_modules/" in name else name
        if not pkg_name:
            continue
        if pkg_name in KNOWN_COMPROMISED_PACKAGES:
            findings.append({
                "package": pkg_name, "version": info.get("version", ""),
                "severity": "CRITICAL", "reason": "known_compromised",
            })
        resolved = info.get("resolved", "")
        if resolved and not resolved.startswith("https://registry.npmjs.org/"):
            findings.append({
                "package": pkg_name, "resolved": resolved,
                "severity": "HIGH", "reason": "non_standard_registry",
            })
        if info.get("hasInstallScript", False):
            findings.append({
                "package": pkg_name, "version": info.get("version", ""),
                "severity": "MEDIUM", "reason": "install_script",
            })
    return findings


def scan_pip_requirements(req_path):
    """Scan pip requirements.txt for suspicious packages."""
    findings = []
    with open(req_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
            if not match:
                continue
            pkg = match.group(1)
            if pkg.lower() in KNOWN_COMPROMISED_PACKAGES:
                findings.append({
                    "package": pkg, "line": line,
                    "severity": "CRITICAL", "reason": "known_compromised",
                })
            if "--index-url" in line or "--extra-index-url" in line:
                findings.append({
                    "package": pkg, "line": line,
                    "severity": "HIGH", "reason": "custom_index",
                })
            if re.search(r"git\+https?://", line):
                findings.append({
                    "package": pkg, "line": line,
                    "severity": "MEDIUM", "reason": "git_dependency",
                })
    return findings


def verify_binary_hashes(manifest_path):
    """Verify binary hashes against a known-good manifest."""
    with open(manifest_path) as f:
        manifest = json.load(f)
    results = []
    for entry in manifest:
        filepath = entry.get("path", "")
        expected_hash = entry.get("sha256", "")
        if not Path(filepath).exists():
            results.append({"path": filepath, "status": "MISSING", "severity": "HIGH"})
            continue
        sha = hashlib.sha256()
        with open(filepath, "rb") as bf:
            for chunk in iter(lambda: bf.read(8192), b""):
                sha.update(chunk)
        actual = sha.hexdigest()
        if actual != expected_hash:
            results.append({
                "path": filepath, "expected": expected_hash, "actual": actual,
                "status": "MISMATCH", "severity": "CRITICAL",
            })
    return results


def scan_build_logs(log_path):
    """Scan CI/CD build logs for supply chain indicators."""
    suspicious_patterns = [
        (r"curl\s+.*\|\s*(sh|bash)", "CRITICAL", "pipe_to_shell"),
        (r"wget\s+.*&&\s*chmod\s+\+x", "HIGH", "download_and_execute"),
        (r"npm\s+install\s+--registry\s+(?!https://registry\.npmjs\.org)", "HIGH", "custom_registry"),
        (r"pip\s+install\s+--index-url\s+(?!https://pypi\.org)", "HIGH", "custom_pypi"),
        (r"docker\s+pull\s+(?!docker\.io/|gcr\.io/|ghcr\.io/)", "MEDIUM", "untrusted_registry"),
    ]
    findings = []
    with open(log_path) as f:
        for i, line in enumerate(f, 1):
            for pattern, severity, category in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "line_number": i, "content": line.strip()[:300],
                        "pattern": category, "severity": severity,
                    })
    return findings


def check_dependency_confusion(internal_packages, public_registry="npm"):
    """Check if internal package names exist on public registries."""
    findings = []
    for pkg in internal_packages:
        try:
            if public_registry == "npm":
                result = subprocess.run(
                    ["npm", "view", pkg, "name"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(
                    ["pip", "index", "versions", pkg], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                findings.append({
                    "package": pkg, "registry": public_registry,
                    "severity": "CRITICAL", "reason": "dependency_confusion_risk",
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    return findings


def main():
    parser = argparse.ArgumentParser(description="Supply Chain Compromise Hunter")
    parser.add_argument("--npm-lock", help="Path to package-lock.json")
    parser.add_argument("--pip-req", help="Path to requirements.txt")
    parser.add_argument("--manifest", help="Path to hash manifest JSON")
    parser.add_argument("--build-log", help="Path to CI/CD build log")
    parser.add_argument("--output", default="supply_chain_hunt_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.npm_lock:
        f = scan_npm_lockfile(args.npm_lock)
        report["findings"]["npm_scan"] = f
        print(f"[+] NPM lock findings: {len(f)}")

    if args.pip_req:
        f = scan_pip_requirements(args.pip_req)
        report["findings"]["pip_scan"] = f
        print(f"[+] Pip requirements findings: {len(f)}")

    if args.manifest:
        f = verify_binary_hashes(args.manifest)
        report["findings"]["hash_verification"] = f
        print(f"[+] Binary hash mismatches: {len([x for x in f if x.get('status') == 'MISMATCH'])}")

    if args.build_log:
        f = scan_build_logs(args.build_log)
        report["findings"]["build_log_scan"] = f
        print(f"[+] Build log findings: {len(f)}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
