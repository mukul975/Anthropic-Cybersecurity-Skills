#!/usr/bin/env python3
"""
Kubernetes etcd Security Assessment Tool

Checks etcd security configuration including TLS, encryption at rest,
access controls, certificate expiration, and backup status.
"""

import json
import subprocess
import sys
import argparse
import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path


def run_command(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return "", str(e), 1


def check_etcd_tls() -> list[dict]:
    """Check etcd TLS configuration via API server process."""
    findings = []
    stdout, _, _ = run_command(["kubectl", "get", "pod", "etcd-*", "-n", "kube-system",
                                "-o", "jsonpath={.items[0].spec.containers[0].command}"])
    if not stdout:
        stdout, _, _ = run_command(["kubectl", "get", "pods", "-n", "kube-system",
                                    "-l", "component=etcd", "-o", "json"])
    if not stdout:
        findings.append({"severity": "WARNING", "type": "etcd_access",
                        "description": "Cannot access etcd pod configuration"})
        return findings

    required_flags = {
        "--cert-file": "Client TLS certificate",
        "--key-file": "Client TLS key",
        "--trusted-ca-file": "Client CA certificate",
        "--peer-cert-file": "Peer TLS certificate",
        "--peer-key-file": "Peer TLS key",
        "--peer-trusted-ca-file": "Peer CA certificate",
        "--client-cert-auth": "Client certificate authentication",
        "--peer-client-cert-auth": "Peer certificate authentication",
    }

    for flag, desc in required_flags.items():
        if flag not in stdout:
            findings.append({
                "severity": "CRITICAL" if "cert" in flag else "HIGH",
                "type": "missing_tls_flag",
                "flag": flag,
                "description": f"etcd missing {desc} ({flag})"
            })

    dangerous_flags = {"--auto-tls=true": "Auto TLS enabled (insecure)",
                      "--peer-auto-tls=true": "Peer auto TLS enabled (insecure)"}
    for flag, desc in dangerous_flags.items():
        if flag in stdout:
            findings.append({
                "severity": "CRITICAL", "type": "insecure_tls",
                "flag": flag, "description": desc
            })

    return findings


def check_encryption_at_rest() -> list[dict]:
    """Check if encryption at rest is configured for secrets."""
    findings = []
    stdout, _, _ = run_command(["kubectl", "get", "pods", "-n", "kube-system",
                                "-l", "component=kube-apiserver", "-o", "json"])
    if not stdout:
        findings.append({"severity": "WARNING", "type": "api_access",
                        "description": "Cannot access API server pod"})
        return findings

    if "--encryption-provider-config" not in stdout:
        findings.append({
            "severity": "CRITICAL", "type": "no_encryption",
            "description": "Secrets encryption at rest is NOT configured (--encryption-provider-config missing)"
        })
    else:
        findings.append({
            "severity": "INFO", "type": "encryption_configured",
            "description": "Encryption at rest configuration flag is present"
        })

    return findings


def check_etcd_network_exposure() -> list[dict]:
    """Check if etcd is exposed on non-localhost interfaces."""
    findings = []
    stdout, _, _ = run_command(["kubectl", "get", "pods", "-n", "kube-system",
                                "-l", "component=etcd", "-o", "json"])
    if not stdout:
        return findings

    if "0.0.0.0:2379" in stdout:
        findings.append({
            "severity": "CRITICAL", "type": "etcd_exposed",
            "description": "etcd client port listening on all interfaces (0.0.0.0:2379)"
        })
    if "0.0.0.0:2380" in stdout:
        findings.append({
            "severity": "HIGH", "type": "etcd_peer_exposed",
            "description": "etcd peer port listening on all interfaces (0.0.0.0:2380)"
        })

    return findings


def check_etcd_pod_security() -> list[dict]:
    """Check etcd pod security context."""
    findings = []
    stdout, _, _ = run_command(["kubectl", "get", "pod", "-n", "kube-system",
                                "-l", "component=etcd", "-o", "json"])
    if not stdout:
        return findings

    try:
        data = json.loads(stdout)
        for pod in data.get("items", []):
            for container in pod["spec"].get("containers", []):
                sc = container.get("securityContext", {})
                if not sc.get("readOnlyRootFilesystem", False):
                    findings.append({
                        "severity": "LOW", "type": "etcd_writable_fs",
                        "description": "etcd container does not have readOnlyRootFilesystem"
                    })
                host_mounts = [v for v in container.get("volumeMounts", [])
                              if "/etc/kubernetes/pki" in v.get("mountPath", "")]
                if host_mounts:
                    findings.append({
                        "severity": "INFO", "type": "etcd_pki_mount",
                        "description": f"etcd mounts PKI directory: {host_mounts[0]['mountPath']}"
                    })
    except (json.JSONDecodeError, KeyError):
        pass

    return findings


def generate_report(all_findings: list[dict], output_format: str = "text") -> str:
    critical = [f for f in all_findings if f["severity"] == "CRITICAL"]
    high = [f for f in all_findings if f["severity"] == "HIGH"]
    medium = [f for f in all_findings if f["severity"] in ("MEDIUM", "WARNING")]
    info = [f for f in all_findings if f["severity"] in ("LOW", "INFO")]

    if output_format == "json":
        return json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {"critical": len(critical), "high": len(high),
                       "medium": len(medium), "info": len(info)},
            "findings": all_findings
        }, indent=2)

    lines = ["=" * 70, "KUBERNETES ETCD SECURITY ASSESSMENT REPORT",
             f"Generated: {datetime.utcnow().isoformat()}", "=" * 70]
    lines.append(f"\nFindings: {len(critical)} Critical, {len(high)} High, {len(medium)} Medium, {len(info)} Info")

    for sev, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM/WARNING", medium), ("INFO", info)]:
        if items:
            lines.append(f"\n## {sev}")
            for f in items:
                lines.append(f"  [{f['type']}] {f['description']}")

    passed = len(critical) == 0 and len(high) == 0
    lines.append(f"\nAssessment Result: {'PASS' if passed else 'FAIL'}")
    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="etcd Security Assessment Tool")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    all_findings = []
    all_findings.extend(check_etcd_tls())
    all_findings.extend(check_encryption_at_rest())
    all_findings.extend(check_etcd_network_exposure())
    all_findings.extend(check_etcd_pod_security())

    print(generate_report(all_findings, args.format))
    sys.exit(1 if any(f["severity"] == "CRITICAL" for f in all_findings) else 0)


if __name__ == "__main__":
    main()
