#!/usr/bin/env python3
"""Agent for API Security Posture Management - discovery, classification, and risk scoring."""

import json
import argparse
import re
from datetime import datetime
from collections import Counter, defaultdict
from pathlib import Path


def discover_apis_from_traffic(log_path):
    """Discover APIs from network traffic logs."""
    apis = defaultdict(lambda: {"methods": set(), "consumers": set(), "count": 0,
                                "status_codes": Counter()})
    with open(log_path) as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            path = entry.get("path", entry.get("endpoint", ""))
            method = entry.get("method", entry.get("http_method", ""))
            ip = entry.get("client_ip", "")
            status = entry.get("status_code", entry.get("status", 200))
            normalized = re.sub(r"/[0-9a-f-]{8,}", "/{id}", path)
            normalized = re.sub(r"/\d+", "/{id}", normalized)
            apis[normalized]["methods"].add(method)
            apis[normalized]["consumers"].add(ip)
            apis[normalized]["count"] += 1
            apis[normalized]["status_codes"][int(status)] += 1
    result = []
    for path, info in sorted(apis.items(), key=lambda x: -x[1]["count"]):
        result.append({
            "path": path,
            "methods": sorted(info["methods"]),
            "unique_consumers": len(info["consumers"]),
            "total_requests": info["count"],
            "error_rate": round(
                sum(v for k, v in info["status_codes"].items() if k >= 400) / info["count"], 3),
        })
    return result


def classify_api_sensitivity(apis):
    """Classify APIs by data sensitivity level."""
    sensitive_patterns = {
        "PII": [r"/users?(/|$)", r"/customers?(/|$)", r"/profile", r"/account"],
        "Financial": [r"/payments?", r"/billing", r"/invoices?", r"/transactions?"],
        "Auth": [r"/auth", r"/login", r"/token", r"/oauth", r"/password"],
        "Admin": [r"/admin", r"/management", r"/config", r"/settings"],
        "Health": [r"/health", r"/status", r"/metrics", r"/ping"],
    }
    classified = []
    for api in apis:
        path = api["path"]
        categories = []
        for category, patterns in sensitive_patterns.items():
            if any(re.search(p, path, re.IGNORECASE) for p in patterns):
                categories.append(category)
        sensitivity = "HIGH" if any(c in categories for c in ["PII", "Financial", "Auth", "Admin"]) \
            else "LOW" if "Health" in categories else "MEDIUM"
        classified.append({**api, "categories": categories, "sensitivity": sensitivity})
    return classified


def score_api_risk(apis):
    """Calculate risk score for each API endpoint."""
    scored = []
    for api in apis:
        risk_score = 0
        factors = []
        if api.get("sensitivity") == "HIGH":
            risk_score += 30
            factors.append("high_sensitivity_data")
        if api.get("error_rate", 0) > 0.1:
            risk_score += 20
            factors.append("high_error_rate")
        if api.get("unique_consumers", 0) > 100:
            risk_score += 10
            factors.append("high_consumer_count")
        if "Auth" in api.get("categories", []):
            risk_score += 15
            factors.append("authentication_endpoint")
        methods = api.get("methods", [])
        if any(m in methods for m in ["DELETE", "PUT", "PATCH"]):
            risk_score += 10
            factors.append("state_changing_methods")
        severity = "CRITICAL" if risk_score >= 50 else "HIGH" if risk_score >= 30 else "MEDIUM"
        scored.append({**api, "risk_score": risk_score, "risk_factors": factors,
                       "risk_level": severity})
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def check_api_security_controls(apis, spec_path=None):
    """Check security controls for discovered APIs."""
    findings = []
    spec_paths = set()
    if spec_path:
        try:
            import yaml
            with open(spec_path) as f:
                spec = yaml.safe_load(f) if spec_path.endswith((".yaml", ".yml")) else json.load(f)
            spec_paths = set(spec.get("paths", {}).keys())
        except Exception:
            pass
    for api in apis:
        if spec_paths and api["path"] not in spec_paths:
            findings.append({
                "path": api["path"], "issue": "undocumented_api",
                "severity": "HIGH", "recommendation": "Add to OpenAPI spec or deprecate",
            })
        if api.get("sensitivity") == "HIGH" and api.get("error_rate", 0) > 0.05:
            findings.append({
                "path": api["path"], "issue": "sensitive_endpoint_high_errors",
                "severity": "HIGH",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description="API Security Posture Management Agent")
    parser.add_argument("--log", help="API traffic log (JSON lines)")
    parser.add_argument("--spec", help="OpenAPI spec for comparison")
    parser.add_argument("--output", default="api_posture_report.json")
    parser.add_argument("--action", choices=["discover", "classify", "score", "audit", "full"],
                        default="full")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "findings": {}}

    if args.log:
        apis = discover_apis_from_traffic(args.log)
        report["findings"]["discovered_apis"] = len(apis)
        print(f"[+] Discovered {len(apis)} API endpoints")

        if args.action in ("classify", "full"):
            apis = classify_api_sensitivity(apis)
        if args.action in ("score", "full"):
            apis = score_api_risk(apis)
        report["findings"]["api_inventory"] = apis[:200]

        if args.action in ("audit", "full"):
            f = check_api_security_controls(apis, args.spec)
            report["findings"]["security_gaps"] = f
            print(f"[+] Security gaps: {len(f)}")

    with open(args.output, "w") as fout:
        json.dump(report, fout, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
