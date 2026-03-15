#!/usr/bin/env python3
"""Web cache poisoning assessment agent using requests and subprocess."""

import sys
import json
import hashlib
import time
import random
import string

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def generate_cache_buster():
    """Generate a unique cache buster parameter."""
    return "cb" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def identify_cache_layer(target_url):
    """Identify caching infrastructure from response headers."""
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
    except RequestException as e:
        return {"error": str(e)}
    headers = dict(resp.headers)
    cache_info = {
        "url": target_url,
        "cache_control": headers.get("Cache-Control", ""),
        "x_cache": headers.get("X-Cache", ""),
        "cf_cache_status": headers.get("CF-Cache-Status", ""),
        "age": headers.get("Age", ""),
        "vary": headers.get("Vary", ""),
        "x_varnish": headers.get("X-Varnish", ""),
        "via": headers.get("Via", ""),
        "x_served_by": headers.get("X-Served-By", ""),
        "cdn_detected": None,
    }
    header_text = json.dumps(headers).lower()
    if "cloudflare" in header_text or cache_info["cf_cache_status"]:
        cache_info["cdn_detected"] = "Cloudflare"
    elif "varnish" in header_text:
        cache_info["cdn_detected"] = "Varnish"
    elif "akamai" in header_text:
        cache_info["cdn_detected"] = "Akamai"
    elif "fastly" in header_text:
        cache_info["cdn_detected"] = "Fastly"
    elif "x-amz" in header_text:
        cache_info["cdn_detected"] = "AWS CloudFront"
    return cache_info


def test_cache_hit_miss(target_url):
    """Determine if responses are being cached by comparing repeated requests."""
    cb = generate_cache_buster()
    test_url = f"{target_url}?{cb}=1"
    results = []
    for i in range(3):
        try:
            resp = requests.get(test_url, timeout=10, verify=False)
            results.append({
                "request": i + 1,
                "x_cache": resp.headers.get("X-Cache", ""),
                "cf_cache": resp.headers.get("CF-Cache-Status", ""),
                "age": resp.headers.get("Age", ""),
                "status": resp.status_code,
            })
        except RequestException:
            pass
        time.sleep(1)
    return {"test_url": test_url, "results": results}


def test_unkeyed_headers(target_url):
    """Test for unkeyed headers that are reflected in cached responses."""
    cb = generate_cache_buster()
    base_url = f"{target_url}?{cb}=1"
    unkeyed_headers = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Scheme", "http"),
        ("X-Forwarded-Proto", "http"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
        ("X-Host", "evil.com"),
        ("X-Forwarded-Server", "evil.com"),
        ("X-Forwarded-Port", "1337"),
        ("X-Original-Host", "evil.com"),
        ("Transfer-Encoding", "chunked"),
    ]
    findings = []
    for header_name, header_value in unkeyed_headers:
        cb = generate_cache_buster()
        test_url = f"{target_url}?{cb}=1"
        try:
            resp = requests.get(
                test_url, headers={header_name: header_value},
                timeout=10, verify=False
            )
            if header_value in resp.text:
                poisoned_resp = requests.get(test_url, timeout=10, verify=False)
                cached_poison = header_value in poisoned_resp.text
                findings.append({
                    "header": header_name,
                    "value": header_value,
                    "reflected": True,
                    "cached_poison": cached_poison,
                    "risk": "CRITICAL" if cached_poison else "HIGH",
                })
        except RequestException:
            pass
    return findings


def test_cache_key_normalization(target_url):
    """Test cache key normalization issues."""
    cb = generate_cache_buster()
    tests = []
    variations = [
        (f"{target_url}?{cb}=1", "Original"),
        (f"{target_url}?{cb}=1&utm_source=test", "Extra parameter"),
        (f"{target_url}?{cb}=1#fragment", "Fragment"),
        (f"{target_url}/?{cb}=1", "Trailing slash"),
    ]
    for url, desc in variations:
        try:
            resp = requests.get(url, timeout=10, verify=False)
            tests.append({
                "variation": desc, "url": url,
                "status": resp.status_code,
                "x_cache": resp.headers.get("X-Cache", ""),
                "content_length": len(resp.content),
            })
        except RequestException:
            pass
    return tests


def test_cache_deception(target_url):
    """Test for web cache deception vulnerabilities."""
    cb = generate_cache_buster()
    deception_paths = [
        "/account/profile.css",
        "/api/user.js",
        "/settings.png",
        "/dashboard/nonexistent.css",
    ]
    findings = []
    for path in deception_paths:
        test_url = f"{target_url.rstrip('/')}{path}?{cb}=1"
        try:
            resp = requests.get(test_url, timeout=10, verify=False)
            cache_status = resp.headers.get("X-Cache", resp.headers.get("CF-Cache-Status", ""))
            if "HIT" in cache_status.upper() or resp.headers.get("Age"):
                findings.append({
                    "path": path,
                    "cached": True,
                    "status": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "risk": "HIGH",
                })
        except RequestException:
            pass
    return findings


def run_assessment(target_url):
    """Full web cache poisoning assessment."""
    report = {
        "target": target_url,
        "cache_layer": identify_cache_layer(target_url),
        "cache_behavior": test_cache_hit_miss(target_url),
        "unkeyed_headers": test_unkeyed_headers(target_url),
        "key_normalization": test_cache_key_normalization(target_url),
        "cache_deception": test_cache_deception(target_url),
    }
    critical_count = sum(
        1 for f in report["unkeyed_headers"] if f.get("risk") == "CRITICAL"
    )
    high_count = sum(
        1 for f in report["unkeyed_headers"] if f.get("risk") == "HIGH"
    ) + len(report["cache_deception"])
    report["summary"] = {
        "cdn": report["cache_layer"].get("cdn_detected", "Unknown"),
        "critical_findings": critical_count,
        "high_findings": high_count,
        "poisonable_headers": [f["header"] for f in report["unkeyed_headers"] if f.get("cached_poison")],
    }
    return report


def print_report(report):
    print("Web Cache Poisoning Assessment")
    print("=" * 50)
    print(f"Target: {report['target']}")
    print(f"CDN: {report['summary']['cdn']}")
    print(f"Critical: {report['summary']['critical_findings']}")
    print(f"High: {report['summary']['high_findings']}")
    if report["summary"]["poisonable_headers"]:
        print(f"\nPoisonable Headers:")
        for h in report["summary"]["poisonable_headers"]:
            print(f"  - {h}")
    print(f"\nUnkeyed Header Tests:")
    for f in report["unkeyed_headers"]:
        status = "POISON" if f.get("cached_poison") else ("REFLECTED" if f.get("reflected") else "SAFE")
        print(f"  {f['header']}: {status} [{f.get('risk', 'N/A')}]")
    if report["cache_deception"]:
        print(f"\nCache Deception:")
        for f in report["cache_deception"]:
            print(f"  {f['path']}: CACHED ({f['content_type']})")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = run_assessment(target)
    print_report(result)
