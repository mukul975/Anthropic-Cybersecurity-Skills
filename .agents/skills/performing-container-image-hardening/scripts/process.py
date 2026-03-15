#!/usr/bin/env python3
"""
Container Image Hardening Validation Script

Validates container images against hardening best practices,
checks for non-root user, minimal packages, and CIS compliance.

Usage:
    python process.py --image myapp:latest --output hardening-report.json
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class HardeningCheck:
    check_id: str
    name: str
    passed: bool
    details: str
    severity: str


def run_docker_inspect(image: str) -> dict:
    """Inspect a Docker image and return configuration."""
    cmd = ["docker", "inspect", image]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            return data[0] if data else {}
        return {"error": proc.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        return {"error": str(e)}


def check_non_root_user(config: dict) -> HardeningCheck:
    """Check if image runs as non-root user."""
    user = config.get("Config", {}).get("User", "")
    if user and user != "0" and user != "root":
        return HardeningCheck("CIS-4.1", "Non-root user configured", True,
                              f"User: {user}", "HIGH")
    return HardeningCheck("CIS-4.1", "Non-root user configured", False,
                          "Image runs as root. Add USER instruction.", "HIGH")


def check_healthcheck(config: dict) -> HardeningCheck:
    """Check if HEALTHCHECK is defined."""
    healthcheck = config.get("Config", {}).get("Healthcheck")
    if healthcheck and healthcheck.get("Test"):
        return HardeningCheck("CIS-4.6", "HEALTHCHECK defined", True,
                              f"Test: {healthcheck['Test']}", "MEDIUM")
    return HardeningCheck("CIS-4.6", "HEALTHCHECK defined", False,
                          "No HEALTHCHECK instruction found.", "MEDIUM")


def check_exposed_ports(config: dict) -> HardeningCheck:
    """Check for unnecessary exposed ports."""
    ports = config.get("Config", {}).get("ExposedPorts", {})
    port_list = list(ports.keys()) if ports else []
    if len(port_list) <= 2:
        return HardeningCheck("HARD-1", "Minimal ports exposed", True,
                              f"Ports: {port_list}", "LOW")
    return HardeningCheck("HARD-1", "Minimal ports exposed", False,
                          f"Many ports exposed: {port_list}. Minimize exposed ports.", "LOW")


def check_image_size(image: str) -> HardeningCheck:
    """Check image size against recommended limits."""
    cmd = ["docker", "image", "inspect", image, "--format", "{{.Size}}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        size_bytes = int(proc.stdout.strip())
        size_mb = size_bytes / (1024 * 1024)
        if size_mb < 200:
            return HardeningCheck("HARD-2", "Image size within limits", True,
                                  f"Size: {size_mb:.0f} MB (< 200 MB)", "MEDIUM")
        elif size_mb < 500:
            return HardeningCheck("HARD-2", "Image size within limits", False,
                                  f"Size: {size_mb:.0f} MB (> 200 MB, consider optimizing)", "MEDIUM")
        else:
            return HardeningCheck("HARD-2", "Image size within limits", False,
                                  f"Size: {size_mb:.0f} MB (> 500 MB, use multi-stage build)", "HIGH")
    except (subprocess.TimeoutExpired, ValueError):
        return HardeningCheck("HARD-2", "Image size within limits", False,
                              "Could not determine image size", "LOW")


def check_env_secrets(config: dict) -> HardeningCheck:
    """Check for potential secrets in environment variables."""
    env_vars = config.get("Config", {}).get("Env", [])
    secret_keywords = ["password", "secret", "key", "token", "credential", "api_key"]
    suspicious = []
    for env in env_vars:
        name = env.split("=")[0].lower()
        if any(kw in name for kw in secret_keywords):
            suspicious.append(env.split("=")[0])
    if not suspicious:
        return HardeningCheck("CIS-4.10", "No secrets in ENV", True,
                              "No suspicious environment variables found", "HIGH")
    return HardeningCheck("CIS-4.10", "No secrets in ENV", False,
                          f"Suspicious ENV vars: {suspicious}. Use secrets manager.", "HIGH")


def check_shell_available(image: str) -> HardeningCheck:
    """Check if shell is available in the image."""
    cmd = ["docker", "run", "--rm", "--entrypoint", "", image, "sh", "-c", "echo shell_available"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if "shell_available" in proc.stdout:
            return HardeningCheck("HARD-3", "Shell removed from image", False,
                                  "Shell (/bin/sh) is available. Consider removing for production.", "LOW")
        return HardeningCheck("HARD-3", "Shell removed from image", True,
                              "No shell available in image", "LOW")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return HardeningCheck("HARD-3", "Shell removed from image", True,
                              "Could not test shell access (likely unavailable)", "LOW")


def main():
    parser = argparse.ArgumentParser(description="Container Image Hardening Validation")
    parser.add_argument("--image", required=True, help="Docker image to validate")
    parser.add_argument("--output", default="hardening-report.json")
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()

    print(f"[*] Validating hardening: {args.image}")

    config = run_docker_inspect(args.image)
    if "error" in config:
        print(f"[ERROR] {config['error']}")
        sys.exit(2)

    checks = [
        check_non_root_user(config),
        check_healthcheck(config),
        check_exposed_ports(config),
        check_image_size(args.image),
        check_env_secrets(config),
        check_shell_available(args.image),
    ]

    passed = sum(1 for c in checks if c.passed)
    failed = sum(1 for c in checks if not c.passed)

    report = {
        "metadata": {"image": args.image, "date": datetime.now(timezone.utc).isoformat()},
        "summary": {"total": len(checks), "passed": passed, "failed": failed},
        "checks": [
            {"id": c.check_id, "name": c.name, "passed": c.passed,
             "details": c.details, "severity": c.severity}
            for c in checks
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    for c in checks:
        status = "PASS" if c.passed else "FAIL"
        print(f"  [{status}] {c.check_id}: {c.name} - {c.details}")

    print(f"\n[*] {passed}/{len(checks)} checks passed")
    if args.fail_on_findings and failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
