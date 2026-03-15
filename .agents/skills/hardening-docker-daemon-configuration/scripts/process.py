#!/usr/bin/env python3
"""
Docker Daemon Hardening Auditor - Check Docker daemon configuration
against CIS Docker Benchmark recommendations and generate remediation.
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path

HARDENING_CHECKS = {
    "icc_disabled": {
        "description": "Inter-container communication disabled (CIS 2.2)",
        "check_key": "icc",
        "expected": False,
        "severity": "HIGH",
    },
    "userns_remap": {
        "description": "User namespace remapping enabled (CIS 2.9)",
        "check_key": "userns-remap",
        "expected_not_empty": True,
        "severity": "HIGH",
    },
    "no_new_privileges": {
        "description": "No new privileges flag set (CIS 2.14)",
        "check_key": "no-new-privileges",
        "expected": True,
        "severity": "HIGH",
    },
    "live_restore": {
        "description": "Live restore enabled (CIS 2.15)",
        "check_key": "live-restore",
        "expected": True,
        "severity": "MEDIUM",
    },
    "userland_proxy_disabled": {
        "description": "Userland proxy disabled (CIS 2.16)",
        "check_key": "userland-proxy",
        "expected": False,
        "severity": "MEDIUM",
    },
    "log_driver": {
        "description": "Logging driver configured (CIS 2.13)",
        "check_key": "log-driver",
        "expected_not_empty": True,
        "severity": "MEDIUM",
    },
    "storage_driver": {
        "description": "Storage driver set to overlay2 (CIS 2.6)",
        "check_key": "storage-driver",
        "expected_value": "overlay2",
        "severity": "LOW",
    },
    "experimental_disabled": {
        "description": "Experimental features disabled",
        "check_key": "experimental",
        "expected": False,
        "severity": "LOW",
    },
}

RECOMMENDED_CONFIG = {
    "icc": False,
    "userns-remap": "default",
    "no-new-privileges": True,
    "log-driver": "json-file",
    "log-opts": {"max-size": "10m", "max-file": "5"},
    "storage-driver": "overlay2",
    "live-restore": True,
    "userland-proxy": False,
    "default-ulimits": {
        "nofile": {"Name": "nofile", "Hard": 65536, "Soft": 32768},
        "nproc": {"Name": "nproc", "Hard": 4096, "Soft": 2048},
    },
    "experimental": False,
    "metrics-addr": "127.0.0.1:9323",
}


def load_daemon_config(config_path: str = "/etc/docker/daemon.json") -> dict:
    """Load Docker daemon.json configuration."""
    path = Path(config_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error parsing {config_path}: {e}", file=sys.stderr)
        return {}


def get_docker_info() -> dict:
    """Get Docker system info."""
    result = subprocess.run(["docker", "info", "--format", "{{json .}}"],
                          capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running docker info: {result.stderr}", file=sys.stderr)
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def audit_config(config: dict) -> list:
    """Audit daemon.json against hardening checks."""
    results = []
    for check_id, check in HARDENING_CHECKS.items():
        key = check["check_key"]
        value = config.get(key)
        passed = False
        actual = value

        if "expected" in check:
            passed = value == check["expected"]
        elif "expected_not_empty" in check:
            passed = value is not None and value != ""
        elif "expected_value" in check:
            passed = value == check["expected_value"]

        results.append({
            "id": check_id,
            "description": check["description"],
            "severity": check["severity"],
            "passed": passed,
            "expected": check.get("expected", check.get("expected_value", "non-empty")),
            "actual": actual,
        })
    return results


def check_tls_config(config: dict) -> dict:
    """Check TLS configuration."""
    tls_enabled = config.get("tls", False)
    tls_verify = config.get("tlsverify", False)
    has_ca = bool(config.get("tlscacert"))
    has_cert = bool(config.get("tlscert"))
    has_key = bool(config.get("tlskey"))

    return {
        "tls_enabled": tls_enabled,
        "tls_verify": tls_verify,
        "has_ca_cert": has_ca,
        "has_server_cert": has_cert,
        "has_server_key": has_key,
        "fully_configured": all([tls_enabled, tls_verify, has_ca, has_cert, has_key]),
    }


def check_socket_permissions() -> dict:
    """Check Docker socket file permissions."""
    import os
    import stat
    socket_path = "/var/run/docker.sock"
    if not os.path.exists(socket_path):
        return {"exists": False}

    st = os.stat(socket_path)
    mode = stat.filemode(st.st_mode)
    owner_uid = st.st_uid
    group_gid = st.st_gid

    world_readable = bool(st.st_mode & stat.S_IROTH)
    world_writable = bool(st.st_mode & stat.S_IWOTH)

    return {
        "exists": True,
        "permissions": mode,
        "owner_uid": owner_uid,
        "group_gid": group_gid,
        "world_readable": world_readable,
        "world_writable": world_writable,
        "secure": not world_readable and not world_writable,
    }


def generate_report(audit_results: list, tls_info: dict, config_path: str) -> str:
    """Generate markdown audit report."""
    passed = sum(1 for r in audit_results if r["passed"])
    total = len(audit_results)
    score = (passed / total * 100) if total > 0 else 0

    report = f"""# Docker Daemon Hardening Audit Report

**Config File:** `{config_path}`
**Score:** {passed}/{total} checks passed ({score:.0f}%)

## Audit Results

| Status | Severity | Check | Expected | Actual |
|--------|----------|-------|----------|--------|
"""
    for r in sorted(audit_results, key=lambda x: (0 if not x["passed"] else 1, x["severity"])):
        status = "PASS" if r["passed"] else "FAIL"
        report += f"| {status} | {r['severity']} | {r['description']} | {r['expected']} | {r['actual']} |\n"

    report += f"""
## TLS Configuration

| Setting | Value |
|---------|-------|
| TLS Enabled | {tls_info.get('tls_enabled', False)} |
| TLS Verify | {tls_info.get('tls_verify', False)} |
| CA Certificate | {tls_info.get('has_ca_cert', False)} |
| Server Certificate | {tls_info.get('has_server_cert', False)} |
| Server Key | {tls_info.get('has_server_key', False)} |
| Fully Configured | {tls_info.get('fully_configured', False)} |

## Remediation

Failed checks require updating `/etc/docker/daemon.json` and restarting the Docker daemon:
```bash
sudo systemctl restart docker
```
"""
    return report


def generate_hardened_config(existing: dict) -> dict:
    """Merge recommended settings with existing config."""
    merged = existing.copy()
    merged.update(RECOMMENDED_CONFIG)
    return merged


def main():
    parser = argparse.ArgumentParser(description="Docker Daemon Hardening Auditor")
    parser.add_argument("--config", default="/etc/docker/daemon.json",
                       help="Path to daemon.json")
    parser.add_argument("--audit", action="store_true", help="Run hardening audit")
    parser.add_argument("--generate", action="store_true",
                       help="Generate hardened daemon.json")
    parser.add_argument("--report", help="Save audit report to file")
    parser.add_argument("--output", help="Output path for generated config")

    args = parser.parse_args()

    if args.generate:
        existing = load_daemon_config(args.config)
        hardened = generate_hardened_config(existing)
        output = json.dumps(hardened, indent=2)
        if args.output:
            Path(args.output).write_text(output)
            print(f"Hardened config written to {args.output}")
        else:
            print(output)
        return

    if args.audit:
        config = load_daemon_config(args.config)
        if not config:
            print(f"Warning: No config found at {args.config}, auditing empty config")

        audit_results = audit_config(config)
        tls_info = check_tls_config(config)
        report = generate_report(audit_results, tls_info, args.config)

        if args.report:
            Path(args.report).write_text(report)
            print(f"Report written to {args.report}")
        else:
            print(report)

        failed = sum(1 for r in audit_results if not r["passed"])
        sys.exit(1 if failed > 0 else 0)

    parser.print_help()


if __name__ == "__main__":
    main()
