#!/usr/bin/env python3
"""Agent for discovering undocumented (shadow) API endpoints via traffic analysis."""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse


def parse_access_log(log_path, api_prefix="/api"):
    """Parse web server access logs to extract API endpoint calls."""
    endpoints = defaultdict(lambda: {"count": 0, "methods": set(), "status_codes": set()})
    # Combined log format: IP - - [date] "METHOD path HTTP/ver" status size
    pattern = re.compile(
        r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    )
    try:
        with open(log_path, "r") as f:
            for line in f:
                m = pattern.match(line)
                if not m:
                    continue
                method, path, status = m.group(3), m.group(4), m.group(5)
                parsed = urlparse(path)
                clean_path = re.sub(r'/\d+', '/{id}', parsed.path)
                clean_path = re.sub(r'/[0-9a-f]{24,}', '/{id}', clean_path)
                clean_path = re.sub(
                    r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                    '/{uuid}', clean_path
                )
                if api_prefix and not clean_path.startswith(api_prefix):
                    continue
                key = f"{method} {clean_path}"
                endpoints[key]["count"] += 1
                endpoints[key]["methods"].add(method)
                endpoints[key]["status_codes"].add(status)
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
    return endpoints


def load_openapi_spec(spec_path):
    """Load documented endpoints from OpenAPI/Swagger spec."""
    documented = set()
    try:
        with open(spec_path, "r") as f:
            spec = json.load(f)
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            normalized = re.sub(r'\{[^}]+\}', '{id}', path)
            for method in methods:
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    documented.add(f"{method.upper()} {normalized}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading spec: {e}")
    return documented


def find_shadow_endpoints(observed, documented):
    """Identify endpoints in traffic that are not in the API spec."""
    shadow = []
    for endpoint, data in observed.items():
        if endpoint not in documented:
            shadow.append({
                "endpoint": endpoint,
                "call_count": data["count"],
                "status_codes": sorted(data["status_codes"]),
                "risk": "HIGH" if any(s.startswith("2") for s in data["status_codes"]) else "MEDIUM",
            })
    return sorted(shadow, key=lambda x: x["call_count"], reverse=True)


def classify_risk(shadow_endpoints):
    """Classify shadow endpoints by risk category."""
    categories = {
        "debug": [], "admin": [], "internal": [],
        "deprecated": [], "unknown": [],
    }
    for ep in shadow_endpoints:
        path = ep["endpoint"].lower()
        if any(k in path for k in ["debug", "test", "dev", "health"]):
            categories["debug"].append(ep)
        elif any(k in path for k in ["admin", "manage", "console", "dashboard"]):
            categories["admin"].append(ep)
        elif any(k in path for k in ["internal", "private", "system"]):
            categories["internal"].append(ep)
        elif any(k in path for k in ["v1", "v0", "old", "legacy"]):
            categories["deprecated"].append(ep)
        else:
            categories["unknown"].append(ep)
    return categories


def main():
    parser = argparse.ArgumentParser(
        description="Discover undocumented shadow API endpoints"
    )
    parser.add_argument("--access-log", required=True, help="Path to web access log")
    parser.add_argument("--openapi-spec", help="Path to OpenAPI/Swagger JSON spec")
    parser.add_argument("--api-prefix", default="/api", help="API path prefix filter")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--min-calls", type=int, default=1, help="Minimum call count threshold")
    args = parser.parse_args()

    print("[*] Shadow API Endpoint Detection Agent")
    observed = parse_access_log(args.access_log, args.api_prefix)
    print(f"[*] Observed {len(observed)} unique API endpoints in traffic")

    documented = set()
    if args.openapi_spec:
        documented = load_openapi_spec(args.openapi_spec)
        print(f"[*] Loaded {len(documented)} documented endpoints from spec")

    shadow = find_shadow_endpoints(observed, documented)
    shadow = [s for s in shadow if s["call_count"] >= args.min_calls]
    categories = classify_risk(shadow)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_observed": len(observed),
        "documented": len(documented),
        "shadow_count": len(shadow),
        "categories": {k: len(v) for k, v in categories.items()},
        "shadow_endpoints": shadow[:50],
    }

    high_risk = sum(1 for s in shadow if s["risk"] == "HIGH")
    report["risk_level"] = "CRITICAL" if high_risk >= 5 else "HIGH" if high_risk >= 2 else "MEDIUM" if shadow else "LOW"

    print(f"[*] Shadow endpoints: {len(shadow)} (HIGH risk: {high_risk})")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
