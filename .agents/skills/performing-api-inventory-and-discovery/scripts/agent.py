#!/usr/bin/env python3
# For authorized testing only
"""API inventory and discovery agent for attack surface mapping."""

import json
import sys
import argparse
import re
import subprocess
from datetime import datetime
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/api-docs", "/docs",
    "/health", "/healthz", "/status", "/metrics",
    "/admin/api", "/internal/api", "/.well-known/openid-configuration",
    "/v1", "/v2", "/rest", "/ws", "/rpc",
]


def discover_api_endpoints(base_url, paths=None, timeout=5):
    """Probe common API paths to discover active endpoints."""
    if paths is None:
        paths = COMMON_API_PATHS
    discovered = []
    for path in paths:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False,
                                verify=True, headers={"User-Agent": "API-Inventory-Agent/1.0"})
            if resp.status_code < 500:
                entry = {
                    "url": url,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                }
                if "json" in entry["content_type"]:
                    entry["type"] = "REST/JSON"
                elif "xml" in entry["content_type"]:
                    entry["type"] = "SOAP/XML"
                elif "html" in entry["content_type"] and "swagger" in path.lower():
                    entry["type"] = "API Documentation"
                else:
                    entry["type"] = "unknown"
                if resp.status_code == 200:
                    entry["finding"] = "Active API endpoint"
                    entry["severity"] = "INFO"
                discovered.append(entry)
        except requests.exceptions.RequestException:
            pass
    return discovered


def parse_swagger_spec(spec_url):
    """Fetch and parse OpenAPI/Swagger spec to inventory endpoints."""
    try:
        resp = requests.get(spec_url, timeout=15)
        resp.raise_for_status()
        spec = resp.json()
    except Exception as e:
        return {"error": str(e)}

    version = spec.get("openapi", spec.get("swagger", "unknown"))
    info = spec.get("info", {})
    paths = spec.get("paths", {})
    endpoints = []
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                op = methods[method]
                endpoints.append({
                    "method": method.upper(),
                    "path": path,
                    "summary": op.get("summary", ""),
                    "deprecated": op.get("deprecated", False),
                    "auth_required": bool(op.get("security", spec.get("security", []))),
                })
    deprecated = [e for e in endpoints if e["deprecated"]]
    return {
        "spec_version": version,
        "api_title": info.get("title", ""),
        "api_version": info.get("version", ""),
        "total_endpoints": len(endpoints),
        "deprecated_endpoints": len(deprecated),
        "endpoints": endpoints,
    }


def scan_javascript_for_apis(js_url):
    """Fetch JavaScript file and extract API endpoint references."""
    try:
        resp = requests.get(js_url, timeout=15)
        content = resp.text
    except Exception as e:
        return {"error": str(e)}

    api_patterns = [
        re.compile(r'["\'](/api/[^"\']+)["\']'),
        re.compile(r'["\'](/v\d+/[^"\']+)["\']'),
        re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
        re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']'),
        re.compile(r'\.get\s*\(\s*["\']([^"\']+/api[^"\']*)["\']'),
        re.compile(r'\.post\s*\(\s*["\']([^"\']+/api[^"\']*)["\']'),
    ]
    found_apis = set()
    for pattern in api_patterns:
        for match in pattern.findall(content):
            if len(match) > 3 and not match.endswith((".js", ".css", ".png", ".jpg")):
                found_apis.add(match)

    return {"source": js_url, "discovered_apis": sorted(found_apis), "count": len(found_apis)}


def enumerate_subdomains_for_apis(domain):
    """Use DNS enumeration to find API subdomains."""
    api_prefixes = [
        "api", "api-v1", "api-v2", "api-gateway", "api-internal",
        "gateway", "graphql", "rest", "ws", "webhook",
        "staging-api", "dev-api", "sandbox-api", "beta-api",
        "admin-api", "partner-api", "public-api", "mobile-api",
    ]
    found = []
    for prefix in api_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            result = subprocess.run(
                ["nslookup", subdomain], capture_output=True, text=True, timeout=5
            )
            if "Non-authoritative answer" in result.stdout or "Address:" in result.stdout:
                found.append({
                    "subdomain": subdomain,
                    "status": "resolved",
                    "severity": "MEDIUM" if "internal" in prefix or "staging" in prefix else "INFO",
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return found


def classify_api_risk(endpoints):
    """Classify discovered APIs by risk level."""
    findings = []
    for ep in endpoints:
        url = ep.get("url", ep.get("path", ""))
        risk = "LOW"
        reason = "Standard endpoint"
        if any(p in url.lower() for p in ["/admin", "/internal", "/debug", "/metrics"]):
            risk = "HIGH"
            reason = "Administrative/internal endpoint exposed"
        elif any(p in url.lower() for p in ["/graphql", "/graphiql", "/playground"]):
            risk = "HIGH"
            reason = "GraphQL endpoint — check introspection"
        elif "swagger" in url.lower() or "api-docs" in url.lower():
            risk = "MEDIUM"
            reason = "API documentation publicly accessible"
        elif ep.get("deprecated", False):
            risk = "HIGH"
            reason = "Deprecated/zombie API still accessible"
        findings.append({**ep, "risk": risk, "reason": reason})
    return findings


def run_audit(args):
    """Execute API inventory and discovery audit."""
    print(f"\n{'='*60}")
    print(f"  API INVENTORY AND DISCOVERY AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.target_url:
        discovered = discover_api_endpoints(args.target_url)
        classified = classify_api_risk(discovered)
        report["discovered_endpoints"] = classified
        print(f"--- ENDPOINT DISCOVERY ({len(classified)} found) ---")
        for ep in classified:
            print(f"  [{ep['risk']}] {ep['url']} ({ep.get('status','')}): {ep['reason']}")

    if args.swagger_url:
        spec = parse_swagger_spec(args.swagger_url)
        report["swagger_spec"] = spec
        print(f"\n--- SWAGGER SPEC ANALYSIS ---")
        print(f"  API: {spec.get('api_title','')} v{spec.get('api_version','')}")
        print(f"  Endpoints: {spec.get('total_endpoints',0)}")
        print(f"  Deprecated: {spec.get('deprecated_endpoints',0)}")

    if args.js_url:
        js_apis = scan_javascript_for_apis(args.js_url)
        report["js_api_discovery"] = js_apis
        print(f"\n--- JAVASCRIPT API EXTRACTION ({js_apis.get('count',0)}) ---")
        for api in js_apis.get("discovered_apis", [])[:15]:
            print(f"  {api}")

    if args.domain:
        subs = enumerate_subdomains_for_apis(args.domain)
        report["api_subdomains"] = subs
        print(f"\n--- API SUBDOMAIN ENUMERATION ({len(subs)} found) ---")
        for s in subs:
            print(f"  [{s['severity']}] {s['subdomain']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="API Inventory Discovery Agent")
    parser.add_argument("--target-url", help="Base URL to probe for API endpoints")
    parser.add_argument("--swagger-url", help="Swagger/OpenAPI spec URL to parse")
    parser.add_argument("--js-url", help="JavaScript file URL to extract API paths")
    parser.add_argument("--domain", help="Domain for API subdomain enumeration")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
