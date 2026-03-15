#!/usr/bin/env python3
"""SSL stripping assessment agent using subprocess wrappers for bettercap and curl."""

import subprocess
import re
import json
import sys
import shutil


def check_hsts_header(target_url):
    """Check HSTS header on a target URL using curl."""
    result = subprocess.run(
        ["curl", "-sI", "--max-time", "10", target_url],
        capture_output=True, text=True, timeout=15
    )
    headers = result.stdout
    hsts_match = re.search(
        r"strict-transport-security:\s*(.+)", headers, re.IGNORECASE
    )
    findings = {"url": target_url, "hsts_present": False, "details": {}}
    if hsts_match:
        hsts_value = hsts_match.group(1).strip()
        findings["hsts_present"] = True
        findings["details"]["raw"] = hsts_value
        max_age = re.search(r"max-age=(\d+)", hsts_value)
        if max_age:
            findings["details"]["max_age"] = int(max_age.group(1))
        findings["details"]["include_subdomains"] = "includesubdomains" in hsts_value.lower()
        findings["details"]["preload"] = "preload" in hsts_value.lower()
    return findings


def check_hsts_preload(domain):
    """Check if domain is in HSTS preload list via the hstspreload.org API."""
    try:
        result = subprocess.run(
            ["curl", "-s", f"https://hstspreload.org/api/v2/status?domain={domain}"],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        return {
            "domain": domain,
            "status": data.get("status", "unknown"),
            "preloaded": data.get("status") == "preloaded",
        }
    except (json.JSONDecodeError, subprocess.TimeoutExpired):
        return {"domain": domain, "status": "error", "preloaded": False}


def check_redirect_chain(url):
    """Follow HTTP redirects and check for HTTPS upgrade."""
    result = subprocess.run(
        ["curl", "-sIL", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{redirect_url}\\n%{url_effective}\\n%{scheme}", url],
        capture_output=True, text=True, timeout=15
    )
    lines = result.stdout.strip().split("\n")
    return {
        "initial_url": url,
        "redirect_url": lines[0] if len(lines) > 0 else "",
        "final_url": lines[1] if len(lines) > 1 else "",
        "final_scheme": lines[2] if len(lines) > 2 else "",
        "upgrades_to_https": lines[2] == "HTTPS" if len(lines) > 2 else False,
    }


def check_mixed_content(url):
    """Fetch page and check for HTTP resources on an HTTPS page."""
    result = subprocess.run(
        ["curl", "-s", "--max-time", "10", url],
        capture_output=True, text=True, timeout=15
    )
    body = result.stdout
    http_refs = re.findall(r'(src|href|action)=["\']http://', body, re.IGNORECASE)
    return {
        "url": url,
        "mixed_content_found": len(http_refs) > 0,
        "http_reference_count": len(http_refs),
    }


def check_security_headers(url):
    """Check for key security headers that complement HSTS."""
    result = subprocess.run(
        ["curl", "-sI", "--max-time", "10", url],
        capture_output=True, text=True, timeout=15
    )
    headers_text = result.stdout.lower()
    checks = {
        "content-security-policy": "content-security-policy:" in headers_text,
        "x-content-type-options": "x-content-type-options:" in headers_text,
        "x-frame-options": "x-frame-options:" in headers_text,
        "upgrade-insecure-requests": "upgrade-insecure-requests" in headers_text,
    }
    return checks


def run_assessment(targets):
    """Run full SSL stripping assessment against a list of target domains."""
    results = []
    for target in targets:
        https_url = f"https://{target}"
        http_url = f"http://{target}"
        entry = {"target": target}
        entry["hsts"] = check_hsts_header(https_url)
        entry["preload"] = check_hsts_preload(target)
        entry["redirect"] = check_redirect_chain(http_url)
        entry["mixed_content"] = check_mixed_content(https_url)
        entry["security_headers"] = check_security_headers(https_url)
        vulnerable = (
            not entry["hsts"]["hsts_present"]
            or not entry["preload"]["preloaded"]
            or entry["mixed_content"]["mixed_content_found"]
        )
        entry["ssl_strip_risk"] = "HIGH" if not entry["hsts"]["hsts_present"] else (
            "MEDIUM" if not entry["preload"]["preloaded"] else "LOW"
        )
        results.append(entry)
    return results


def print_report(results):
    print("SSL Stripping Assessment Report")
    print("=" * 50)
    for r in results:
        print(f"\nTarget: {r['target']}")
        print(f"  HSTS Present:     {r['hsts']['hsts_present']}")
        if r["hsts"]["hsts_present"]:
            d = r["hsts"]["details"]
            print(f"    max-age:        {d.get('max_age', 'N/A')}")
            print(f"    subdomains:     {d.get('include_subdomains', False)}")
            print(f"    preload dir:    {d.get('preload', False)}")
        print(f"  Preload List:     {r['preload']['status']}")
        print(f"  HTTP->HTTPS:      {r['redirect']['upgrades_to_https']}")
        print(f"  Mixed Content:    {r['mixed_content']['http_reference_count']} refs")
        print(f"  SSL Strip Risk:   {r['ssl_strip_risk']}")
        sh = r["security_headers"]
        missing = [h for h, v in sh.items() if not v]
        if missing:
            print(f"  Missing Headers:  {', '.join(missing)}")


if __name__ == "__main__":
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["example.com"]
    results = run_assessment(targets)
    print_report(results)
