#!/usr/bin/env python3
"""Agent for analyzing Kubernetes audit logs for security threats."""

import os
import json
import argparse
from collections import defaultdict
from datetime import datetime


def parse_audit_log(log_path):
    """Parse Kubernetes audit log file (JSON lines format)."""
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def detect_pod_exec(events):
    """Detect kubectl exec and attach events (shell access to pods)."""
    findings = []
    for event in events:
        obj_ref = event.get("objectRef", {})
        subresource = obj_ref.get("subresource", "")
        if subresource in ("exec", "attach"):
            findings.append({
                "timestamp": event.get("requestReceivedTimestamp", ""),
                "user": event.get("user", {}).get("username", ""),
                "groups": event.get("user", {}).get("groups", []),
                "verb": event.get("verb", ""),
                "namespace": obj_ref.get("namespace", ""),
                "pod": obj_ref.get("name", ""),
                "subresource": subresource,
                "source_ip": event.get("sourceIPs", [""])[0],
                "severity": "HIGH",
            })
    return findings


def detect_secret_access(events):
    """Detect access to Kubernetes secrets."""
    findings = []
    for event in events:
        obj_ref = event.get("objectRef", {})
        if obj_ref.get("resource") != "secrets":
            continue
        verb = event.get("verb", "")
        if verb not in ("get", "list", "watch", "create", "update", "delete"):
            continue
        findings.append({
            "timestamp": event.get("requestReceivedTimestamp", ""),
            "user": event.get("user", {}).get("username", ""),
            "verb": verb,
            "namespace": obj_ref.get("namespace", ""),
            "secret_name": obj_ref.get("name", ""),
            "source_ip": event.get("sourceIPs", [""])[0],
            "severity": "HIGH" if verb in ("list", "delete") else "MEDIUM",
        })
    return findings


def detect_rbac_changes(events):
    """Detect RBAC role and binding modifications."""
    rbac_resources = {"clusterroles", "clusterrolebindings", "roles", "rolebindings"}
    findings = []
    for event in events:
        obj_ref = event.get("objectRef", {})
        resource = obj_ref.get("resource", "")
        verb = event.get("verb", "")
        if resource in rbac_resources and verb in ("create", "update", "patch", "delete"):
            findings.append({
                "timestamp": event.get("requestReceivedTimestamp", ""),
                "user": event.get("user", {}).get("username", ""),
                "verb": verb,
                "resource": resource,
                "name": obj_ref.get("name", ""),
                "namespace": obj_ref.get("namespace", ""),
                "source_ip": event.get("sourceIPs", [""])[0],
                "severity": "CRITICAL" if "cluster" in resource else "HIGH",
            })
    return findings


def detect_privileged_pods(events):
    """Detect creation of privileged pods."""
    findings = []
    for event in events:
        if event.get("verb") != "create":
            continue
        obj_ref = event.get("objectRef", {})
        if obj_ref.get("resource") != "pods":
            continue
        request_obj = event.get("requestObject", {})
        spec = request_obj.get("spec", {})
        containers = spec.get("containers", [])
        for container in containers:
            sc = container.get("securityContext", {})
            if sc.get("privileged"):
                findings.append({
                    "timestamp": event.get("requestReceivedTimestamp", ""),
                    "user": event.get("user", {}).get("username", ""),
                    "namespace": obj_ref.get("namespace", ""),
                    "pod": obj_ref.get("name", ""),
                    "container": container.get("name", ""),
                    "severity": "CRITICAL",
                })
    return findings


def detect_anonymous_access(events):
    """Detect API access by anonymous or unauthenticated users."""
    findings = []
    anon_users = {"system:anonymous", "system:unauthenticated"}
    for event in events:
        user = event.get("user", {}).get("username", "")
        groups = event.get("user", {}).get("groups", [])
        if user in anon_users or "system:unauthenticated" in groups:
            status_code = event.get("responseStatus", {}).get("code", 0)
            if status_code < 400:
                findings.append({
                    "timestamp": event.get("requestReceivedTimestamp", ""),
                    "user": user,
                    "verb": event.get("verb", ""),
                    "resource": event.get("objectRef", {}).get("resource", ""),
                    "source_ip": event.get("sourceIPs", [""])[0],
                    "status_code": status_code,
                    "severity": "CRITICAL",
                })
    return findings


def detect_forbidden_surge(events, threshold=20):
    """Detect 403 surges indicating enumeration or brute force."""
    user_forbidden = defaultdict(int)
    for event in events:
        if event.get("responseStatus", {}).get("code") == 403:
            user = event.get("user", {}).get("username", "")
            user_forbidden[user] += 1
    surges = []
    for user, count in user_forbidden.items():
        if count >= threshold:
            surges.append({"user": user, "forbidden_count": count, "severity": "MEDIUM"})
    return sorted(surges, key=lambda x: x["forbidden_count"], reverse=True)


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Audit Log Analyzer")
    parser.add_argument("--audit-log", required=True, help="Path to audit log file")
    parser.add_argument("--output", default="k8s_audit_report.json")
    parser.add_argument("--action", choices=[
        "exec", "secrets", "rbac", "privileged", "anonymous", "full_analysis"
    ], default="full_analysis")
    args = parser.parse_args()

    events = parse_audit_log(args.audit_log)
    report = {"log_file": args.audit_log, "total_events": len(events),
              "generated_at": datetime.utcnow().isoformat(), "findings": {}}
    print(f"[+] Parsed {len(events)} audit events")

    if args.action in ("exec", "full_analysis"):
        findings = detect_pod_exec(events)
        report["findings"]["pod_exec"] = findings
        print(f"[+] Pod exec/attach events: {len(findings)}")

    if args.action in ("secrets", "full_analysis"):
        findings = detect_secret_access(events)
        report["findings"]["secret_access"] = findings
        print(f"[+] Secret access events: {len(findings)}")

    if args.action in ("rbac", "full_analysis"):
        findings = detect_rbac_changes(events)
        report["findings"]["rbac_changes"] = findings
        print(f"[+] RBAC changes: {len(findings)}")

    if args.action in ("privileged", "full_analysis"):
        findings = detect_privileged_pods(events)
        report["findings"]["privileged_pods"] = findings
        print(f"[+] Privileged pod creation: {len(findings)}")

    if args.action in ("anonymous", "full_analysis"):
        findings = detect_anonymous_access(events)
        report["findings"]["anonymous_access"] = findings
        print(f"[+] Anonymous access events: {len(findings)}")

    forbidden = detect_forbidden_surge(events)
    report["findings"]["forbidden_surges"] = forbidden
    print(f"[+] 403 surges: {len(forbidden)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
