#!/usr/bin/env python3
"""Container drift detection agent using Docker SDK.

Compares running container filesystem against the original image to detect
binary drift, file modifications, and package installations.
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime

try:
    import docker
except ImportError:
    print("Install docker SDK: pip install docker")
    sys.exit(1)

PACKAGE_MANAGERS = {"apt", "apt-get", "yum", "dnf", "apk", "pip", "pip3", "npm", "gem"}
SHELLS = {"bash", "sh", "dash", "zsh", "csh", "ash"}
SUSPICIOUS_BINARIES = {"curl", "wget", "nc", "ncat", "netcat", "socat", "python",
                       "perl", "gcc", "cc", "make", "nmap", "tcpdump"}


def get_container_diff(client, container_id):
    container = client.containers.get(container_id)
    try:
        diff = container.diff()
    except docker.errors.APIError:
        diff = []
    changes = {"added": [], "modified": [], "deleted": []}
    for entry in diff or []:
        path = entry.get("Path", "")
        kind = entry.get("Kind", 0)
        if kind == 0:
            changes["modified"].append(path)
        elif kind == 1:
            changes["added"].append(path)
        elif kind == 2:
            changes["deleted"].append(path)
    return changes


def get_running_processes(container_id):
    try:
        result = subprocess.run(
            ["docker", "top", container_id, "-eo", "pid,user,comm,args"],
            capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []
        lines = result.stdout.strip().split("\n")[1:]
        processes = []
        for line in lines:
            parts = line.split(None, 3)
            if len(parts) >= 3:
                processes.append({
                    "pid": parts[0], "user": parts[1],
                    "command": parts[2], "args": parts[3] if len(parts) > 3 else ""
                })
        return processes
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def detect_drift_indicators(changes, processes):
    findings = []
    for path in changes.get("added", []):
        basename = path.rsplit("/", 1)[-1]
        if basename in SUSPICIOUS_BINARIES:
            findings.append({"type": "suspicious_binary_added", "path": path,
                             "severity": "HIGH"})
        if path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            findings.append({"type": "binary_added_to_system_path", "path": path,
                             "severity": "HIGH"})
    for path in changes.get("modified", []):
        if path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
            findings.append({"type": "sensitive_file_modified", "path": path,
                             "severity": "CRITICAL"})
        if path.startswith("/etc/cron"):
            findings.append({"type": "cron_modified", "path": path, "severity": "HIGH"})

    for proc in processes:
        cmd = proc.get("command", "")
        if cmd in PACKAGE_MANAGERS:
            findings.append({"type": "package_manager_running", "process": cmd,
                             "severity": "HIGH"})
        if cmd in SHELLS and proc.get("user") == "root":
            findings.append({"type": "root_shell_active", "process": cmd,
                             "severity": "MEDIUM"})
    return findings


def check_image_digest(client, container_id):
    container = client.containers.get(container_id)
    image_id = container.image.id
    image_tags = container.image.tags
    attrs = container.attrs
    config_image = attrs.get("Config", {}).get("Image", "")
    uses_digest = "@sha256:" in config_image
    return {
        "image_id": image_id[:19],
        "image_tags": image_tags,
        "config_image": config_image,
        "uses_immutable_digest": uses_digest,
        "privileged": attrs.get("HostConfig", {}).get("Privileged", False),
        "read_only_rootfs": attrs.get("HostConfig", {}).get("ReadonlyRootfs", False),
    }


def audit_container(client, container_id):
    changes = get_container_diff(client, container_id)
    processes = get_running_processes(container_id)
    findings = detect_drift_indicators(changes, processes)
    image_info = check_image_digest(client, container_id)

    if not image_info.get("read_only_rootfs"):
        findings.append({"type": "mutable_rootfs", "severity": "MEDIUM",
                         "detail": "readOnlyRootFilesystem not enabled"})
    if image_info.get("privileged"):
        findings.append({"type": "privileged_container", "severity": "CRITICAL",
                         "detail": "Container running in privileged mode"})

    total_changes = sum(len(v) for v in changes.values())
    risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else \
           "HIGH" if total_changes > 20 or any(f["severity"] == "HIGH" for f in findings) else \
           "MEDIUM" if total_changes > 5 else "LOW"

    return {
        "container_id": container_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "filesystem_changes": changes,
        "total_changes": total_changes,
        "running_processes": processes,
        "image_info": image_info,
        "findings": findings,
        "risk_level": risk,
    }


def main():
    parser = argparse.ArgumentParser(description="Container Drift Detector")
    parser.add_argument("--container", required=True, help="Container ID or name")
    parser.add_argument("--all", action="store_true", help="Audit all running containers")
    args = parser.parse_args()

    client = docker.from_env()
    results = []
    if args.all:
        for c in client.containers.list():
            results.append(audit_container(client, c.id))
    else:
        results.append(audit_container(client, args.container))

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
