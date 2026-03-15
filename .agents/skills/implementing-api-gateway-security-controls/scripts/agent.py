#!/usr/bin/env python3
"""Agent for auditing API gateway security controls (Kong, AWS API Gateway)."""

import json
import argparse
from datetime import datetime

try:
    import boto3
except ImportError:
    boto3 = None

try:
    import requests
except ImportError:
    requests = None


def audit_aws_api_gateway(region="us-east-1"):
    """Audit AWS API Gateway configurations for security issues."""
    if boto3 is None:
        return {"error": "boto3 not installed"}
    client = boto3.client("apigateway", region_name=region)
    findings = []
    apis = client.get_rest_apis()["items"]
    for api in apis:
        api_id = api["id"]
        api_name = api["name"]
        resources = client.get_resources(restApiId=api_id)["items"]
        for resource in resources:
            for method_key in resource.get("resourceMethods", {}):
                method = client.get_method(restApiId=api_id,
                                           resourceId=resource["id"], httpMethod=method_key)
                auth_type = method.get("authorizationType", "NONE")
                api_key_req = method.get("apiKeyRequired", False)
                if auth_type == "NONE" and not api_key_req:
                    findings.append({
                        "api": api_name, "resource": resource["path"],
                        "method": method_key, "issue": "no_authentication",
                        "severity": "CRITICAL",
                    })
                if not method.get("requestValidatorId"):
                    findings.append({
                        "api": api_name, "resource": resource["path"],
                        "method": method_key, "issue": "no_request_validation",
                        "severity": "MEDIUM",
                    })
        stages = client.get_stages(restApiId=api_id)["item"]
        for stage in stages:
            if not stage.get("accessLogSettings"):
                findings.append({
                    "api": api_name, "stage": stage["stageName"],
                    "issue": "no_access_logging", "severity": "HIGH",
                })
            throttle = stage.get("methodSettings", {}).get("*/*", {})
            if not throttle.get("throttlingRateLimit"):
                findings.append({
                    "api": api_name, "stage": stage["stageName"],
                    "issue": "no_rate_limiting", "severity": "HIGH",
                })
    return findings


def audit_kong_gateway(admin_url="http://localhost:8001"):
    """Audit Kong API Gateway plugin configurations."""
    findings = []
    services = requests.get(f"{admin_url}/services").json().get("data", [])
    for svc in services:
        svc_id = svc["id"]
        svc_name = svc.get("name", svc_id)
        plugins = requests.get(f"{admin_url}/services/{svc_id}/plugins").json().get("data", [])
        plugin_names = {p["name"] for p in plugins}
        if "key-auth" not in plugin_names and "jwt" not in plugin_names and "oauth2" not in plugin_names:
            findings.append({
                "service": svc_name, "issue": "no_auth_plugin",
                "severity": "CRITICAL",
            })
        if "rate-limiting" not in plugin_names and "rate-limiting-advanced" not in plugin_names:
            findings.append({
                "service": svc_name, "issue": "no_rate_limiting",
                "severity": "HIGH",
            })
        if "cors" not in plugin_names:
            findings.append({
                "service": svc_name, "issue": "no_cors_plugin",
                "severity": "MEDIUM",
            })
        if "ip-restriction" not in plugin_names:
            findings.append({
                "service": svc_name, "issue": "no_ip_restriction",
                "severity": "LOW",
            })
    return findings


def analyze_gateway_logs(log_path):
    """Analyze API gateway access logs for security issues."""
    findings = []
    status_counts = {}
    ip_counts = {}
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            status = int(entry.get("status", entry.get("status_code", 0)))
            ip = entry.get("client_ip", entry.get("ip", ""))
            status_counts[status] = status_counts.get(status, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    total = sum(status_counts.values())
    error_rate = sum(v for k, v in status_counts.items() if k >= 400) / max(total, 1)
    if error_rate > 0.1:
        findings.append({
            "issue": "high_error_rate", "error_rate": round(error_rate, 3),
            "severity": "HIGH",
        })
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
        if count > total * 0.3:
            findings.append({
                "issue": "traffic_concentration", "ip": ip,
                "request_pct": round(count / total * 100, 1), "severity": "MEDIUM",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="API Gateway Security Audit Agent")
    parser.add_argument("--action", choices=["aws", "kong", "logs", "full"], default="full")
    parser.add_argument("--kong-url", default="http://localhost:8001")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--log", help="Gateway access log (JSON lines)")
    parser.add_argument("--output", default="api_gateway_audit_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.action in ("aws", "full"):
        findings = audit_aws_api_gateway(args.region)
        report["findings"]["aws_api_gateway"] = findings
        print(f"[+] AWS API Gateway findings: {len(findings)}")

    if args.action in ("kong", "full"):
        findings = audit_kong_gateway(args.kong_url)
        report["findings"]["kong_gateway"] = findings
        print(f"[+] Kong Gateway findings: {len(findings)}")

    if args.action in ("logs", "full") and args.log:
        findings = analyze_gateway_logs(args.log)
        report["findings"]["log_analysis"] = findings
        print(f"[+] Log analysis findings: {len(findings)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
