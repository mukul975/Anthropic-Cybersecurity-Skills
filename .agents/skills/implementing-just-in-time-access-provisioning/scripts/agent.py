#!/usr/bin/env python3
"""Agent for implementing and auditing Just-In-Time access provisioning."""

import json
import argparse
from datetime import datetime, timedelta
from collections import Counter


def audit_jit_requests(requests_path):
    """Audit JIT access requests for compliance and anomalies."""
    with open(requests_path) as f:
        data = json.load(f)
    requests_list = data if isinstance(data, list) else data.get("requests", [])
    findings = []
    by_status = Counter()
    by_resource = Counter()

    for req in requests_list:
        status = req.get("status", "unknown").lower()
        by_status[status] += 1
        by_resource[req.get("resource", "unknown")] += 1

        duration_hours = req.get("duration_hours", req.get("duration", 0))
        if duration_hours > 8:
            findings.append({
                "request_id": req.get("id", ""),
                "issue": f"Long access duration: {duration_hours}h",
                "severity": "MEDIUM",
                "user": req.get("requestor", req.get("user", "")),
            })
        if duration_hours > 24:
            findings[-1]["severity"] = "HIGH"

        if status == "approved" and not req.get("approver"):
            findings.append({
                "request_id": req.get("id", ""),
                "issue": "Auto-approved without approver record",
                "severity": "HIGH",
            })

        granted = req.get("granted_at", "")
        expired = req.get("expired_at", req.get("revoked_at", ""))
        if granted and not expired and status == "active":
            granted_dt = datetime.fromisoformat(granted.replace("Z", ""))
            if (datetime.utcnow() - granted_dt).total_seconds() > duration_hours * 3600:
                findings.append({
                    "request_id": req.get("id", ""),
                    "issue": "Access not revoked after expiration",
                    "severity": "CRITICAL",
                    "user": req.get("requestor", ""),
                })

    return {
        "total_requests": len(requests_list),
        "by_status": dict(by_status),
        "by_resource": dict(by_resource.most_common(10)),
        "findings": findings,
        "anomaly_count": len(findings),
    }


def audit_standing_privileges(privileges_path):
    """Identify standing privileges that should be converted to JIT."""
    with open(privileges_path) as f:
        data = json.load(f)
    privs = data if isinstance(data, list) else data.get("privileges", [])
    candidates = []

    for priv in privs:
        role = priv.get("role", priv.get("permission", "")).lower()
        usage = priv.get("last_used", priv.get("last_access", ""))
        is_privileged = any(k in role for k in [
            "admin", "root", "owner", "superuser", "dba", "operator"])

        days_unused = 0
        if usage:
            try:
                usage_dt = datetime.fromisoformat(usage.replace("Z", ""))
                days_unused = (datetime.utcnow() - usage_dt).days
            except ValueError:
                pass

        if is_privileged and days_unused > 30:
            candidates.append({
                "user": priv.get("user", priv.get("identity", "")),
                "role": priv.get("role", ""),
                "resource": priv.get("resource", priv.get("target", "")),
                "days_unused": days_unused,
                "severity": "CRITICAL" if days_unused > 90 else "HIGH",
                "recommendation": "Convert to JIT access",
            })
        elif is_privileged:
            candidates.append({
                "user": priv.get("user", ""),
                "role": priv.get("role", ""),
                "days_unused": days_unused,
                "severity": "MEDIUM",
                "recommendation": "Evaluate for JIT conversion",
            })

    return {
        "total_privileges": len(privs),
        "jit_candidates": len(candidates),
        "critical_standing": sum(1 for c in candidates if c["severity"] == "CRITICAL"),
        "details": candidates[:30],
    }


def calculate_jit_metrics(requests_path):
    """Calculate JIT program operational metrics."""
    with open(requests_path) as f:
        data = json.load(f)
    requests_list = data if isinstance(data, list) else data.get("requests", [])

    approval_times = []
    durations = []
    auto_approved = 0
    total = len(requests_list)

    for req in requests_list:
        if req.get("auto_approved", False):
            auto_approved += 1

        requested = req.get("requested_at", "")
        approved = req.get("approved_at", "")
        if requested and approved:
            try:
                r_dt = datetime.fromisoformat(requested.replace("Z", ""))
                a_dt = datetime.fromisoformat(approved.replace("Z", ""))
                approval_times.append((a_dt - r_dt).total_seconds() / 60)
            except ValueError:
                pass

        duration = req.get("duration_hours", 0)
        if duration:
            durations.append(duration)

    return {
        "total_requests": total,
        "auto_approved_rate": round(auto_approved / total * 100, 1) if total else 0,
        "avg_approval_time_min": round(sum(approval_times) / len(approval_times), 1) if approval_times else 0,
        "avg_duration_hours": round(sum(durations) / len(durations), 1) if durations else 0,
        "max_duration_hours": max(durations) if durations else 0,
        "p95_approval_time_min": sorted(approval_times)[int(len(approval_times) * 0.95)] if approval_times else 0,
    }


def generate_jit_policy():
    """Generate JIT access provisioning policy."""
    return {
        "risk_levels": {
            "low": {
                "approval": "auto-approve",
                "max_duration": "4h",
                "examples": ["Read-only database access", "Log viewer"],
            },
            "medium": {
                "approval": "manager-approve",
                "max_duration": "8h",
                "examples": ["Application admin", "Deploy permissions"],
            },
            "high": {
                "approval": "manager + security team",
                "max_duration": "4h",
                "examples": ["Production database write", "IAM admin"],
            },
            "critical": {
                "approval": "CISO + manager + security team",
                "max_duration": "2h",
                "examples": ["Domain admin", "Root access", "Key management"],
            },
        },
        "controls": {
            "session_recording": True,
            "break_glass_procedure": True,
            "automatic_revocation": True,
            "audit_logging": True,
            "notification_on_grant": True,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="JIT Access Provisioning Agent")
    parser.add_argument("--requests", help="JIT requests log JSON")
    parser.add_argument("--privileges", help="Standing privileges JSON")
    parser.add_argument("--action", choices=["audit", "standing", "metrics", "policy", "full"],
                        default="full")
    parser.add_argument("--output", default="jit_access_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action in ("audit", "full") and args.requests:
        result = audit_jit_requests(args.requests)
        report["results"]["audit"] = result
        print(f"[+] JIT audit: {result['total_requests']} requests, {result['anomaly_count']} issues")

    if args.action in ("standing", "full") and args.privileges:
        result = audit_standing_privileges(args.privileges)
        report["results"]["standing"] = result
        print(f"[+] Standing privs: {result['jit_candidates']} JIT candidates")

    if args.action in ("metrics", "full") and args.requests:
        metrics = calculate_jit_metrics(args.requests)
        report["results"]["metrics"] = metrics
        print(f"[+] Avg approval: {metrics['avg_approval_time_min']}min")

    if args.action in ("policy", "full"):
        policy = generate_jit_policy()
        report["results"]["policy"] = policy
        print("[+] JIT policy generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
