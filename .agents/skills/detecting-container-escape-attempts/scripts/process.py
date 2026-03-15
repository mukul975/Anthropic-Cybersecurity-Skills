#!/usr/bin/env python3
"""
Container Escape Detection Scanner

Analyzes running containers for escape risk factors including
privileged mode, dangerous capabilities, sensitive mounts,
and Docker socket exposure.
"""

import subprocess
import json
import sys
from dataclasses import dataclass, field


DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN": 10,
    "SYS_PTRACE": 9,
    "SYS_MODULE": 10,
    "SYS_RAWIO": 8,
    "NET_ADMIN": 7,
    "DAC_OVERRIDE": 6,
    "DAC_READ_SEARCH": 5,
    "MKNOD": 4,
    "NET_RAW": 4,
    "SYS_CHROOT": 3,
}

SENSITIVE_MOUNT_PATHS = [
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/proc/sysrq-trigger",
    "/proc/kcore",
    "/proc/kmsg",
    "/proc/kallsyms",
    "/sys/kernel",
    "/sys/fs/cgroup",
    "/dev",
    "/etc/shadow",
    "/etc/passwd",
    "/root",
]


@dataclass
class EscapeRisk:
    container_name: str
    container_id: str
    image: str
    risk_score: int = 0
    risk_factors: list = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.risk_score >= 8:
            return "CRITICAL"
        elif self.risk_score >= 5:
            return "HIGH"
        elif self.risk_score >= 3:
            return "MEDIUM"
        return "LOW"


def run_command(cmd: list, timeout: int = 30) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return -1, "", str(e)


def get_running_containers() -> list:
    """Get list of running container IDs."""
    rc, out, _ = run_command(["docker", "ps", "-q"])
    if rc != 0 or not out:
        return []
    return out.split("\n")


def inspect_container(container_id: str) -> dict:
    """Get container inspection data."""
    rc, out, _ = run_command(["docker", "inspect", container_id])
    if rc != 0:
        return {}
    try:
        return json.loads(out)[0]
    except (json.JSONDecodeError, IndexError):
        return {}


def assess_escape_risk(container_data: dict) -> EscapeRisk:
    """Assess container escape risk based on configuration."""
    name = container_data.get("Name", "unknown").lstrip("/")
    cid = container_data.get("Id", "")[:12]
    image = container_data.get("Config", {}).get("Image", "unknown")

    risk = EscapeRisk(container_name=name, container_id=cid, image=image)
    host_config = container_data.get("HostConfig", {})
    config = container_data.get("Config", {})
    mounts = container_data.get("Mounts", [])

    # Check privileged mode
    if host_config.get("Privileged", False):
        risk.risk_score += 10
        risk.risk_factors.append({
            "factor": "Privileged mode enabled",
            "severity": "CRITICAL",
            "score": 10,
            "description": "Container has full host access, trivial escape",
            "remediation": "Remove --privileged flag, use specific --cap-add"
        })

    # Check capabilities
    cap_add = host_config.get("CapAdd") or []
    cap_drop = host_config.get("CapDrop") or []
    all_dropped = "ALL" in [c.upper() for c in cap_drop]

    for cap in cap_add:
        cap_upper = cap.upper()
        if cap_upper in DANGEROUS_CAPABILITIES:
            score = DANGEROUS_CAPABILITIES[cap_upper]
            risk.risk_score += score
            risk.risk_factors.append({
                "factor": f"Dangerous capability: {cap_upper}",
                "severity": "CRITICAL" if score >= 8 else "HIGH",
                "score": score,
                "description": f"CAP_{cap_upper} can be used for container escape",
                "remediation": f"Remove CAP_{cap_upper} unless absolutely required"
            })

    if not all_dropped and not host_config.get("Privileged", False):
        risk.risk_score += 2
        risk.risk_factors.append({
            "factor": "Default capabilities not dropped",
            "severity": "MEDIUM",
            "score": 2,
            "description": "Container retains default Linux capabilities",
            "remediation": "Use --cap-drop ALL and add only required capabilities"
        })

    # Check host namespaces
    for ns in ["NetworkMode", "PidMode", "IpcMode"]:
        value = host_config.get(ns, "")
        if value == "host":
            risk.risk_score += 7
            risk.risk_factors.append({
                "factor": f"Host namespace: {ns}={value}",
                "severity": "CRITICAL",
                "score": 7,
                "description": f"Container shares host {ns}, enabling escape",
                "remediation": f"Remove host {ns} configuration"
            })

    # Check sensitive mounts
    for mount in mounts:
        source = mount.get("Source", "")
        for sensitive_path in SENSITIVE_MOUNT_PATHS:
            if source == sensitive_path or source.startswith(sensitive_path):
                score = 9 if "docker.sock" in source else 6
                risk.risk_score += score
                risk.risk_factors.append({
                    "factor": f"Sensitive mount: {source}",
                    "severity": "CRITICAL" if score >= 8 else "HIGH",
                    "score": score,
                    "description": f"Container has access to {source}",
                    "remediation": f"Remove mount of {source}, use alternative access method"
                })
                break

    # Check user
    user = config.get("User", "")
    if not user or user == "0" or user == "root":
        risk.risk_score += 3
        risk.risk_factors.append({
            "factor": "Running as root",
            "severity": "HIGH",
            "score": 3,
            "description": "Container process runs as root (UID 0)",
            "remediation": "Set USER in Dockerfile or use --user flag"
        })

    # Check security options
    security_opts = host_config.get("SecurityOpt") or []
    has_seccomp = any("seccomp" in opt for opt in security_opts)
    has_apparmor = any("apparmor" in opt for opt in security_opts)
    no_new_privs = any("no-new-privileges" in opt for opt in security_opts)

    if not has_seccomp:
        risk.risk_score += 2
        risk.risk_factors.append({
            "factor": "No custom seccomp profile",
            "severity": "MEDIUM",
            "score": 2,
            "description": "Container uses default seccomp profile or none",
            "remediation": "Apply restrictive custom seccomp profile"
        })

    if not no_new_privs:
        risk.risk_score += 2
        risk.risk_factors.append({
            "factor": "No new-privileges restriction missing",
            "severity": "MEDIUM",
            "score": 2,
            "description": "Container can acquire new privileges via setuid binaries",
            "remediation": "Add --security-opt no-new-privileges:true"
        })

    # Check read-only filesystem
    if not host_config.get("ReadonlyRootfs", False):
        risk.risk_score += 1
        risk.risk_factors.append({
            "factor": "Writable root filesystem",
            "severity": "LOW",
            "score": 1,
            "description": "Container filesystem is writable, allowing tool download",
            "remediation": "Use --read-only with --tmpfs for writable directories"
        })

    # Cap score at 10
    risk.risk_score = min(risk.risk_score, 10)
    return risk


def scan_kubernetes_pods() -> list:
    """Scan Kubernetes pods for escape risks."""
    rc, out, _ = run_command(["kubectl", "get", "pods", "-A", "-o", "json"])
    if rc != 0:
        return []

    risks = []
    try:
        pods = json.loads(out)
    except json.JSONDecodeError:
        return []

    for pod in pods.get("items", []):
        pod_name = pod["metadata"]["name"]
        namespace = pod["metadata"]["namespace"]
        spec = pod.get("spec", {})

        risk = EscapeRisk(
            container_name=f"{namespace}/{pod_name}",
            container_id="k8s",
            image=spec.get("containers", [{}])[0].get("image", "unknown")
        )

        # Check host namespaces
        if spec.get("hostNetwork", False):
            risk.risk_score += 7
            risk.risk_factors.append({
                "factor": "hostNetwork enabled",
                "severity": "CRITICAL",
                "score": 7,
                "description": "Pod shares host network namespace",
                "remediation": "Set hostNetwork: false"
            })

        if spec.get("hostPID", False):
            risk.risk_score += 7
            risk.risk_factors.append({
                "factor": "hostPID enabled",
                "severity": "CRITICAL",
                "score": 7,
                "description": "Pod shares host PID namespace",
                "remediation": "Set hostPID: false"
            })

        # Check containers
        for container in spec.get("containers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged", False):
                risk.risk_score += 10
                risk.risk_factors.append({
                    "factor": f"Privileged container: {container.get('name')}",
                    "severity": "CRITICAL",
                    "score": 10,
                    "description": "Container runs in privileged mode",
                    "remediation": "Set privileged: false"
                })

        # Check volumes
        for vol in spec.get("volumes", []):
            if "hostPath" in vol:
                path = vol["hostPath"].get("path", "")
                if any(path.startswith(p) for p in SENSITIVE_MOUNT_PATHS):
                    risk.risk_score += 8
                    risk.risk_factors.append({
                        "factor": f"Sensitive hostPath: {path}",
                        "severity": "CRITICAL",
                        "score": 8,
                        "description": f"Pod mounts sensitive host path: {path}",
                        "remediation": "Remove hostPath volume"
                    })

        risk.risk_score = min(risk.risk_score, 10)
        if risk.risk_factors:
            risks.append(risk)

    return risks


def main():
    print("[*] Container Escape Risk Scanner")
    print("=" * 70)

    risks = []

    # Scan Docker containers
    containers = get_running_containers()
    if containers:
        print(f"[*] Scanning {len(containers)} Docker containers...")
        for cid in containers:
            data = inspect_container(cid)
            if data:
                risk = assess_escape_risk(data)
                risks.append(risk)
    else:
        print("[*] No Docker containers found, checking Kubernetes...")
        k8s_risks = scan_kubernetes_pods()
        risks.extend(k8s_risks)

    if not risks:
        print("[+] No containers found to scan")
        sys.exit(0)

    # Sort by risk score
    risks.sort(key=lambda r: r.risk_score, reverse=True)

    # Print results
    print(f"\n{'=' * 70}")
    print("CONTAINER ESCAPE RISK ASSESSMENT")
    print(f"{'=' * 70}")

    for risk in risks:
        print(f"\n[{risk.risk_level}] {risk.container_name} (score: {risk.risk_score}/10)")
        print(f"  Image: {risk.image}")
        for factor in risk.risk_factors:
            print(f"  - [{factor['severity']}] {factor['factor']}")
            print(f"    Fix: {factor['remediation']}")

    # Summary
    critical = sum(1 for r in risks if r.risk_level == "CRITICAL")
    high = sum(1 for r in risks if r.risk_level == "HIGH")
    medium = sum(1 for r in risks if r.risk_level == "MEDIUM")
    low = sum(1 for r in risks if r.risk_level == "LOW")

    print(f"\n{'=' * 70}")
    print(f"SUMMARY: {len(risks)} containers scanned")
    print(f"  CRITICAL: {critical}  HIGH: {high}  MEDIUM: {medium}  LOW: {low}")

    # Save report
    report = {
        "scan_type": "container_escape_risk",
        "containers_scanned": len(risks),
        "results": [
            {
                "container": r.container_name,
                "image": r.image,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "factors": r.risk_factors
            }
            for r in risks
        ]
    }

    with open("escape_risk_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Report saved to escape_risk_report.json")

    if critical > 0:
        print(f"\n[!] {critical} containers with CRITICAL escape risk!")
        sys.exit(1)


if __name__ == "__main__":
    main()
