#!/usr/bin/env python3
"""Agent for auditing Cilium Tetragon runtime security configuration."""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone

try:
    from kubernetes import client, config as k8s_config
except ImportError:
    client = None


def check_tetragon_deployment(namespace="kube-system"):
    """Check if Tetragon is deployed in the cluster."""
    findings = []
    if not client:
        return [{"error": "kubernetes library required"}]
    try:
        k8s_config.load_kube_config()
        v1 = client.AppsV1Api()
        daemonsets = v1.list_namespaced_daemon_set(namespace)
        tetragon_found = False
        for ds in daemonsets.items:
            if "tetragon" in ds.metadata.name.lower():
                tetragon_found = True
                desired = ds.status.desired_number_scheduled or 0
                ready = ds.status.number_ready or 0
                if ready < desired:
                    findings.append({"check": "Tetragon Readiness",
                                     "desired": desired, "ready": ready,
                                     "severity": "HIGH"})
        if not tetragon_found:
            findings.append({"check": "Tetragon Deployment", "status": "NOT_FOUND",
                             "severity": "CRITICAL"})
    except Exception as e:
        findings.append({"error": str(e)})
    return findings


def check_tracing_policies():
    """Check TracingPolicy custom resources."""
    findings = []
    try:
        result = subprocess.check_output(
            ["kubectl", "get", "tracingpolicies", "-o", "json"],
            text=True, timeout=10,
        )
        data = json.loads(result)
        items = data.get("items", [])
        if not items:
            findings.append({"check": "TracingPolicies", "count": 0,
                             "severity": "MEDIUM",
                             "recommendation": "Deploy TracingPolicy for runtime enforcement"})
        for item in items:
            name = item.get("metadata", {}).get("name", "unknown")
            spec = item.get("spec", {})
            if not spec.get("kprobes") and not spec.get("tracepoints"):
                findings.append({"check": f"Policy: {name}", "severity": "LOW",
                                 "recommendation": "Add kprobes or tracepoints"})
    except (subprocess.SubprocessError, json.JSONDecodeError):
        findings.append({"check": "TracingPolicies", "status": "query_failed",
                         "severity": "MEDIUM"})
    return findings


def check_tetragon_cli():
    """Check tetra CLI availability and events."""
    findings = []
    try:
        result = subprocess.check_output(
            ["tetra", "status"], text=True, timeout=5,
        )
        if "running" not in result.lower():
            findings.append({"check": "Tetragon Status", "severity": "HIGH"})
    except (subprocess.SubprocessError, FileNotFoundError):
        findings.append({"check": "Tetra CLI", "status": "not_available",
                         "severity": "LOW"})
    return findings


def main():
    parser = argparse.ArgumentParser(description="Tetragon runtime security audit agent")
    parser.add_argument("--namespace", default="kube-system")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    print("[*] Tetragon Runtime Security Audit Agent")
    report = {"timestamp": datetime.now(timezone.utc).isoformat(), "findings": []}
    report["findings"].extend(check_tetragon_deployment(args.namespace))
    report["findings"].extend(check_tracing_policies())
    report["findings"].extend(check_tetragon_cli())
    crit = sum(1 for f in report["findings"] if f.get("severity") == "CRITICAL")
    report["risk_level"] = "CRITICAL" if crit > 0 else "HIGH" if report["findings"] else "LOW"
    print(f"[*] {len(report['findings'])} findings, risk: {report['risk_level']}")
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
