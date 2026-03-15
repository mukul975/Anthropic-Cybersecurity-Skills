#!/usr/bin/env python3
"""
Docker Container Hardening Assessment Tool

Audits Docker daemon configuration, running containers, and images
against CIS Docker Benchmark v1.8.0 hardening requirements.
"""

import subprocess
import json
import sys
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status: str    # PASS, FAIL, WARN, INFO
    details: str
    remediation: str


@dataclass
class HardeningReport:
    findings: list = field(default_factory=list)
    total_pass: int = 0
    total_fail: int = 0
    total_warn: int = 0

    def add(self, finding: Finding):
        self.findings.append(finding)
        if finding.status == "PASS":
            self.total_pass += 1
        elif finding.status == "FAIL":
            self.total_fail += 1
        elif finding.status == "WARN":
            self.total_warn += 1


def run_command(cmd: list, timeout: int = 30) -> tuple:
    """Execute a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def check_docker_available() -> bool:
    """Verify Docker is installed and accessible."""
    rc, out, _ = run_command(["docker", "version", "--format", "{{.Server.Version}}"])
    if rc == 0:
        print(f"[*] Docker version: {out}")
        return True
    print("[!] Docker is not available or not running")
    return False


def check_daemon_config(report: HardeningReport):
    """Check Docker daemon.json configuration against CIS benchmarks."""
    daemon_config_path = "/etc/docker/daemon.json"

    if not os.path.exists(daemon_config_path):
        report.add(Finding(
            check_id="2.0",
            title="Docker daemon configuration file exists",
            severity="HIGH",
            status="FAIL",
            details="daemon.json not found at /etc/docker/daemon.json",
            remediation="Create /etc/docker/daemon.json with security-hardened settings"
        ))
        return

    with open(daemon_config_path, "r") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError:
            report.add(Finding(
                check_id="2.0",
                title="Docker daemon configuration is valid JSON",
                severity="HIGH",
                status="FAIL",
                details="daemon.json contains invalid JSON",
                remediation="Fix JSON syntax in /etc/docker/daemon.json"
            ))
            return

    # Check 2.2: Inter-container communication
    icc = config.get("icc", True)
    report.add(Finding(
        check_id="2.2",
        title="Network traffic restricted between containers",
        severity="HIGH",
        status="PASS" if icc is False else "FAIL",
        details=f"icc is set to {icc}",
        remediation='Set "icc": false in daemon.json to restrict inter-container communication'
    ))

    # Check 2.7: TLS authentication
    tls_verify = config.get("tlsverify", False)
    report.add(Finding(
        check_id="2.7",
        title="TLS authentication for Docker daemon",
        severity="CRITICAL",
        status="PASS" if tls_verify else "FAIL",
        details=f"tlsverify is {tls_verify}",
        remediation='Enable TLS: set "tls": true, "tlsverify": true with cert paths in daemon.json'
    ))

    # Check 2.13: Live restore
    live_restore = config.get("live-restore", False)
    report.add(Finding(
        check_id="2.13",
        title="Live restore is enabled",
        severity="MEDIUM",
        status="PASS" if live_restore else "WARN",
        details=f"live-restore is {live_restore}",
        remediation='Set "live-restore": true in daemon.json'
    ))

    # Check 2.14: Userland proxy disabled
    userland_proxy = config.get("userland-proxy", True)
    report.add(Finding(
        check_id="2.14",
        title="Userland Proxy is disabled",
        severity="MEDIUM",
        status="PASS" if userland_proxy is False else "WARN",
        details=f"userland-proxy is {userland_proxy}",
        remediation='Set "userland-proxy": false in daemon.json'
    ))

    # Check 2.17: No new privileges
    no_new_privs = config.get("no-new-privileges", False)
    report.add(Finding(
        check_id="2.17",
        title="Containers restricted from acquiring new privileges",
        severity="HIGH",
        status="PASS" if no_new_privs else "FAIL",
        details=f"no-new-privileges is {no_new_privs}",
        remediation='Set "no-new-privileges": true in daemon.json'
    ))

    # Check logging configuration
    log_driver = config.get("log-driver", "json-file")
    log_opts = config.get("log-opts", {})
    has_log_limits = "max-size" in log_opts and "max-file" in log_opts
    report.add(Finding(
        check_id="2.12",
        title="Logging is properly configured with rotation",
        severity="MEDIUM",
        status="PASS" if has_log_limits else "WARN",
        details=f"log-driver={log_driver}, max-size={log_opts.get('max-size', 'not set')}, max-file={log_opts.get('max-file', 'not set')}",
        remediation='Configure log-opts with max-size and max-file in daemon.json'
    ))


def check_running_containers(report: HardeningReport):
    """Audit running containers against CIS runtime checks."""
    rc, out, _ = run_command([
        "docker", "ps", "-q"
    ])
    if rc != 0 or not out:
        report.add(Finding(
            check_id="5.0",
            title="Running containers found",
            severity="INFO",
            status="INFO",
            details="No running containers found to audit",
            remediation="N/A"
        ))
        return

    container_ids = out.split("\n")
    print(f"[*] Auditing {len(container_ids)} running containers")

    for cid in container_ids:
        rc, inspect_out, _ = run_command([
            "docker", "inspect", cid
        ])
        if rc != 0:
            continue

        try:
            container = json.loads(inspect_out)[0]
        except (json.JSONDecodeError, IndexError):
            continue

        name = container.get("Name", cid).lstrip("/")
        host_config = container.get("HostConfig", {})
        config = container.get("Config", {})

        # Check 5.4: Privileged mode
        privileged = host_config.get("Privileged", False)
        report.add(Finding(
            check_id="5.4",
            title=f"[{name}] Not running in privileged mode",
            severity="CRITICAL",
            status="PASS" if not privileged else "FAIL",
            details=f"Privileged={privileged}",
            remediation="Remove --privileged flag. Use specific --cap-add instead."
        ))

        # Check 5.3: Capabilities
        cap_add = host_config.get("CapAdd") or []
        cap_drop = host_config.get("CapDrop") or []
        all_dropped = "ALL" in [c.upper() for c in cap_drop] if cap_drop else False
        report.add(Finding(
            check_id="5.3",
            title=f"[{name}] Linux capabilities are restricted",
            severity="HIGH",
            status="PASS" if all_dropped else "FAIL",
            details=f"CapDrop={cap_drop}, CapAdd={cap_add}",
            remediation="Use --cap-drop ALL and only --cap-add specific required capabilities"
        ))

        # Check 5.12: Read-only root filesystem
        read_only = host_config.get("ReadonlyRootfs", False)
        report.add(Finding(
            check_id="5.12",
            title=f"[{name}] Root filesystem is read-only",
            severity="HIGH",
            status="PASS" if read_only else "FAIL",
            details=f"ReadonlyRootfs={read_only}",
            remediation="Run with --read-only and use --tmpfs for writable directories"
        ))

        # Check 4.1: Non-root user
        user = config.get("User", "")
        report.add(Finding(
            check_id="4.1",
            title=f"[{name}] Running as non-root user",
            severity="HIGH",
            status="PASS" if user and user != "0" and user != "root" else "FAIL",
            details=f"User={user if user else 'root (default)'}",
            remediation="Set USER in Dockerfile or use --user flag at runtime"
        ))

        # Check 5.10: Memory limit
        memory = host_config.get("Memory", 0)
        report.add(Finding(
            check_id="5.10",
            title=f"[{name}] Memory usage is limited",
            severity="MEDIUM",
            status="PASS" if memory > 0 else "FAIL",
            details=f"Memory limit={memory} bytes" if memory > 0 else "No memory limit set",
            remediation="Set --memory flag to limit container memory usage"
        ))

        # Check 5.25: No new privileges
        security_opts = host_config.get("SecurityOpt") or []
        no_new_privs = any("no-new-privileges" in opt for opt in security_opts)
        report.add(Finding(
            check_id="5.25",
            title=f"[{name}] No new privileges restriction",
            severity="HIGH",
            status="PASS" if no_new_privs else "FAIL",
            details=f"SecurityOpt={security_opts}",
            remediation="Use --security-opt no-new-privileges:true"
        ))

        # Check 5.28: PID limits
        pids_limit = host_config.get("PidsLimit", 0)
        report.add(Finding(
            check_id="5.28",
            title=f"[{name}] PIDs limit is set",
            severity="MEDIUM",
            status="PASS" if pids_limit and pids_limit > 0 else "WARN",
            details=f"PidsLimit={pids_limit}",
            remediation="Set --pids-limit to prevent fork bomb attacks"
        ))

        # Check health check
        healthcheck = config.get("Healthcheck", {})
        has_healthcheck = bool(healthcheck and healthcheck.get("Test"))
        report.add(Finding(
            check_id="4.6",
            title=f"[{name}] Health check is configured",
            severity="LOW",
            status="PASS" if has_healthcheck else "WARN",
            details=f"Healthcheck configured: {has_healthcheck}",
            remediation="Add HEALTHCHECK instruction in Dockerfile"
        ))


def check_docker_socket(report: HardeningReport):
    """Check if Docker socket is exposed to any container."""
    rc, out, _ = run_command([
        "docker", "ps", "-q"
    ])
    if rc != 0 or not out:
        return

    for cid in out.split("\n"):
        rc, inspect_out, _ = run_command(["docker", "inspect", cid])
        if rc != 0:
            continue

        try:
            container = json.loads(inspect_out)[0]
        except (json.JSONDecodeError, IndexError):
            continue

        name = container.get("Name", cid).lstrip("/")
        mounts = container.get("Mounts", [])

        for mount in mounts:
            source = mount.get("Source", "")
            if "docker.sock" in source:
                report.add(Finding(
                    check_id="5.31",
                    title=f"[{name}] Docker socket mounted",
                    severity="CRITICAL",
                    status="FAIL",
                    details=f"Docker socket mounted from {source}",
                    remediation="Remove Docker socket mount. Use Docker API proxy with restricted access."
                ))
                break


def check_content_trust(report: HardeningReport):
    """Check if Docker Content Trust is enabled."""
    dct = os.environ.get("DOCKER_CONTENT_TRUST", "0")
    report.add(Finding(
        check_id="4.5",
        title="Docker Content Trust is enabled",
        severity="HIGH",
        status="PASS" if dct == "1" else "FAIL",
        details=f"DOCKER_CONTENT_TRUST={dct}",
        remediation="Set DOCKER_CONTENT_TRUST=1 environment variable"
    ))


def generate_report(report: HardeningReport) -> dict:
    """Generate JSON report from findings."""
    score = (report.total_pass / max(len(report.findings), 1)) * 100

    output = {
        "tool": "Docker Hardening Assessment",
        "framework": "CIS Docker Benchmark v1.8.0",
        "summary": {
            "total_checks": len(report.findings),
            "passed": report.total_pass,
            "failed": report.total_fail,
            "warnings": report.total_warn,
            "score_percent": round(score, 1)
        },
        "findings": []
    }

    for f in report.findings:
        output["findings"].append({
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "details": f.details,
            "remediation": f.remediation
        })

    return output


def print_summary(report_data: dict):
    """Print human-readable summary."""
    summary = report_data["summary"]
    print("\n" + "=" * 70)
    print("DOCKER HARDENING ASSESSMENT REPORT")
    print(f"Framework: {report_data['framework']}")
    print("=" * 70)
    print(f"Total Checks:  {summary['total_checks']}")
    print(f"Passed:        {summary['passed']}")
    print(f"Failed:        {summary['failed']}")
    print(f"Warnings:      {summary['warnings']}")
    print(f"Score:         {summary['score_percent']}%")
    print("=" * 70)

    # Print failures
    failures = [f for f in report_data["findings"] if f["status"] == "FAIL"]
    if failures:
        print("\nFAILED CHECKS:")
        print("-" * 70)
        for f in sorted(failures, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 4)):
            print(f"  [{f['severity']}] {f['check_id']}: {f['title']}")
            print(f"    Details: {f['details']}")
            print(f"    Fix: {f['remediation']}")
            print()


def main():
    print("[*] Docker Container Hardening Assessment Tool")
    print("[*] Based on CIS Docker Benchmark v1.8.0\n")

    if not check_docker_available():
        sys.exit(1)

    report = HardeningReport()

    print("[*] Checking daemon configuration...")
    check_daemon_config(report)

    print("[*] Checking Docker Content Trust...")
    check_content_trust(report)

    print("[*] Auditing running containers...")
    check_running_containers(report)

    print("[*] Checking Docker socket exposure...")
    check_docker_socket(report)

    report_data = generate_report(report)
    print_summary(report_data)

    # Save JSON report
    output_file = "docker_hardening_report.json"
    with open(output_file, "w") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[*] Full report saved to {output_file}")

    # Exit with failure if critical/high findings
    critical_high_failures = [
        f for f in report_data["findings"]
        if f["status"] == "FAIL" and f["severity"] in ("CRITICAL", "HIGH")
    ]
    if critical_high_failures:
        print(f"\n[!] {len(critical_high_failures)} CRITICAL/HIGH failures found")
        sys.exit(1)

    print("\n[+] Assessment complete")


if __name__ == "__main__":
    main()
