#!/usr/bin/env python3
"""Docker container forensics agent for investigating compromised containers."""

import subprocess
import json
import os
import sys
import hashlib
import datetime


def run_cmd(cmd):
    """Execute a shell command and return output."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def list_containers(all_containers=True):
    """List Docker containers with detailed information."""
    flags = "-a" if all_containers else ""
    cmd = f"docker ps {flags} --no-trunc --format '{{{{json .}}}}'"
    stdout, _, rc = run_cmd(cmd)
    containers = []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return containers


def inspect_container(container_id):
    """Get detailed container inspection data."""
    stdout, _, rc = run_cmd(f"docker inspect {container_id}")
    if rc == 0 and stdout:
        return json.loads(stdout)
    return None


def analyze_security_config(inspect_data):
    """Analyze container security configuration for misconfigurations."""
    if isinstance(inspect_data, list):
        inspect_data = inspect_data[0]
    findings = []
    host_config = inspect_data.get("HostConfig", {})
    config = inspect_data.get("Config", {})

    if host_config.get("Privileged"):
        findings.append({"severity": "CRITICAL", "finding": "Container running in PRIVILEGED mode"})

    cap_add = host_config.get("CapAdd") or []
    dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
                      "DAC_OVERRIDE", "NET_RAW"]
    for cap in cap_add:
        if cap in dangerous_caps:
            findings.append({"severity": "HIGH", "finding": f"Dangerous capability added: {cap}"})

    if host_config.get("PidMode") == "host":
        findings.append({"severity": "HIGH", "finding": "Shares host PID namespace"})

    if host_config.get("NetworkMode") == "host":
        findings.append({"severity": "HIGH", "finding": "Shares host network namespace"})

    mounts = inspect_data.get("Mounts", [])
    sensitive_paths = ["/", "/etc", "/var", "/root", "/home", "/var/run/docker.sock"]
    for mount in mounts:
        src = mount.get("Source", "")
        rw = mount.get("RW", False)
        if src in sensitive_paths and rw:
            findings.append({
                "severity": "CRITICAL",
                "finding": f"Sensitive host path mounted RW: {src} -> {mount.get('Destination')}"
            })
        if "docker.sock" in src:
            findings.append({
                "severity": "CRITICAL",
                "finding": "Docker socket mounted (container can control Docker daemon)"
            })

    user = config.get("User", "")
    if not user or user == "root":
        findings.append({"severity": "MEDIUM", "finding": "Running as root user"})

    env_vars = config.get("Env", [])
    secret_keywords = ["PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL", "API_KEY"]
    for env in env_vars:
        key = env.split("=")[0]
        if any(s in key.upper() for s in secret_keywords):
            findings.append({"severity": "HIGH", "finding": f"Sensitive env var exposed: {key}"})

    return findings


def get_filesystem_changes(container_id):
    """Get filesystem changes between container and its image."""
    stdout, _, rc = run_cmd(f"docker diff {container_id}")
    changes = {"added": [], "changed": [], "deleted": []}
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("A "):
                changes["added"].append(line[2:])
            elif line.startswith("C "):
                changes["changed"].append(line[2:])
            elif line.startswith("D "):
                changes["deleted"].append(line[2:])
    return changes


def detect_suspicious_files(changes):
    """Analyze filesystem changes for indicators of compromise."""
    suspicious_patterns = [
        "/tmp/", "/dev/shm/", "/root/", ".sh", ".py", ".elf",
        "reverse", "shell", "backdoor", "miner", "xmr", "nc ",
        ".php", "webshell", "c2", "beacon",
    ]
    suspicious_changes = ["/etc/passwd", "/etc/shadow", "/etc/crontab",
                          "/etc/ssh", ".bashrc", "/etc/sudoers", "authorized_keys"]

    findings = []
    for f in changes["added"]:
        for pattern in suspicious_patterns:
            if pattern in f.lower():
                findings.append({"type": "ADDED", "path": f, "reason": f"Matches pattern: {pattern}"})
                break
    for f in changes["changed"]:
        for pattern in suspicious_changes:
            if pattern in f.lower():
                findings.append({"type": "CHANGED", "path": f, "reason": f"Critical file modified"})
                break
    return findings


def export_container(container_id, output_path):
    """Export container filesystem as a tarball for offline analysis."""
    cmd = f"docker export {container_id} > {output_path}"
    _, _, rc = run_cmd(cmd)
    if rc == 0 and os.path.exists(output_path):
        sha256 = hashlib.sha256()
        with open(output_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return True, sha256.hexdigest()
    return False, None


def get_container_logs(container_id, tail=500):
    """Retrieve container logs with timestamps."""
    stdout, stderr, rc = run_cmd(f"docker logs --timestamps --tail {tail} {container_id}")
    return stdout + "\n" + stderr if rc == 0 else None


def scan_image_vulnerabilities(image_name):
    """Run Trivy vulnerability scan on a container image."""
    cmd = f"trivy image --format json {image_name}"
    stdout, _, rc = run_cmd(cmd)
    if rc == 0 and stdout:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
    return None


def generate_report(container_id, inspect_data, security_findings,
                    fs_changes, suspicious_files):
    """Generate a forensic analysis report."""
    container_name = "unknown"
    image = "unknown"
    if inspect_data:
        data = inspect_data[0] if isinstance(inspect_data, list) else inspect_data
        container_name = data.get("Name", "").lstrip("/")
        image = data.get("Config", {}).get("Image", "unknown")

    report = {
        "report_type": "Docker Container Forensics",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "container_id": container_id,
        "container_name": container_name,
        "image": image,
        "security_findings": security_findings,
        "filesystem_changes": {
            "added": len(fs_changes["added"]),
            "changed": len(fs_changes["changed"]),
            "deleted": len(fs_changes["deleted"]),
        },
        "suspicious_files": suspicious_files,
    }
    return report


if __name__ == "__main__":
    print("=" * 60)
    print("Docker Container Forensics Agent")
    print("Security analysis, filesystem diffing, evidence collection")
    print("=" * 60)

    container_id = sys.argv[1] if len(sys.argv) > 1 else None

    if container_id:
        print(f"\n[*] Analyzing container: {container_id}")

        inspect_data = inspect_container(container_id)
        if not inspect_data:
            print("[ERROR] Failed to inspect container. Is Docker running?")
            sys.exit(1)

        print("\n--- Security Configuration Analysis ---")
        findings = analyze_security_config(inspect_data)
        for f in findings:
            print(f"[{f['severity']}] {f['finding']}")

        print("\n--- Filesystem Changes ---")
        changes = get_filesystem_changes(container_id)
        print(f"  Added: {len(changes['added'])}, Changed: {len(changes['changed'])}, "
              f"Deleted: {len(changes['deleted'])}")

        print("\n--- Suspicious Files ---")
        suspicious = detect_suspicious_files(changes)
        for s in suspicious:
            print(f"[!] {s['type']}: {s['path']} ({s['reason']})")

        report = generate_report(container_id, inspect_data, findings, changes, suspicious)
        print(f"\n[*] Report:\n{json.dumps(report, indent=2)}")
    else:
        print("\n[*] Listing all containers...")
        containers = list_containers()
        for c in containers:
            print(f"  {c.get('ID', '?')[:12]}  {c.get('Names', '?')}  {c.get('Status', '?')}")
        print(f"\n[DEMO] Usage: python agent.py <container_id>")
