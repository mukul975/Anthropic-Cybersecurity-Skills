#!/usr/bin/env python3
"""Agent for testing sensitive data exposure vulnerabilities during authorized assessments."""

import requests
import re
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token": r"ghp_[a-zA-Z0-9]{36}",
    "Slack Token": r"xox[bpsa]-[0-9a-zA-Z\-]{10,}",
    "Private Key": r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Generic Secret": r"(?i)(password|secret|api_key|apikey|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
}

SENSITIVE_FIELDS = [
    "password", "password_hash", "salt", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "secret_key", "api_key",
    "private_key", "token", "access_token", "refresh_token",
]


def scan_javascript_files(base_url):
    """Download and scan JavaScript files for hardcoded secrets."""
    print("\n[*] Scanning JavaScript files for secrets...")
    findings = []
    try:
        resp = requests.get(base_url, timeout=15, verify=False)
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
        for js_path in js_urls[:20]:
            if js_path.startswith("//"):
                js_url = "https:" + js_path
            elif js_path.startswith("/"):
                js_url = urljoin(base_url, js_path)
            elif js_path.startswith("http"):
                js_url = js_path
            else:
                js_url = urljoin(base_url, js_path)
            try:
                js_resp = requests.get(js_url, timeout=15, verify=False)
                for name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, js_resp.text)
                    if matches:
                        findings.append({
                            "type": "SECRET_IN_JS", "file": js_url,
                            "pattern": name, "count": len(matches), "severity": "HIGH",
                        })
                        print(f"  [!] {name} found in {js_path} ({len(matches)} matches)")
            except requests.RequestException:
                continue
    except requests.RequestException as e:
        print(f"  [-] Error: {e}")
    return findings


def check_config_files(base_url):
    """Check for exposed configuration files."""
    print("\n[*] Checking for exposed configuration files...")
    findings = []
    config_files = [
        ".env", ".env.local", ".env.production", "config.json", "settings.json",
        ".aws/credentials", ".docker/config.json", "wp-config.php",
        ".git/config", ".git/HEAD", "composer.json", "package.json",
        ".htaccess", "web.config", "phpinfo.php",
    ]
    for cf in config_files:
        url = urljoin(base_url, cf)
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.text) > 10:
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type or cf.endswith((".json", ".php")):
                    findings.append({
                        "type": "EXPOSED_CONFIG", "file": cf, "url": url,
                        "size": len(resp.text), "severity": "CRITICAL",
                    })
                    print(f"  [!] FOUND: {cf} ({len(resp.text)} bytes)")
        except requests.RequestException:
            continue
    return findings


def check_api_data_exposure(base_url, token, endpoints):
    """Check API responses for excessive sensitive data."""
    print("\n[*] Checking API responses for sensitive data exposure...")
    findings = []
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if resp.status_code == 200:
                data_str = resp.text.lower()
                exposed = [f for f in SENSITIVE_FIELDS if f in data_str]
                if exposed:
                    findings.append({
                        "type": "API_DATA_EXPOSURE", "endpoint": endpoint,
                        "exposed_fields": exposed, "severity": "HIGH",
                    })
                    print(f"  [!] {endpoint}: Exposes {exposed}")
        except requests.RequestException:
            continue
    return findings


def check_security_headers(base_url, sensitive_endpoints):
    """Check Cache-Control and security headers on sensitive pages."""
    print("\n[*] Checking cache headers on sensitive endpoints...")
    findings = []
    for endpoint in sensitive_endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            cache_control = resp.headers.get("Cache-Control", "")
            if "no-store" not in cache_control and resp.status_code == 200:
                findings.append({
                    "type": "MISSING_NO_STORE", "endpoint": endpoint,
                    "cache_control": cache_control, "severity": "MEDIUM",
                })
                print(f"  [!] {endpoint}: Missing no-store (Cache-Control: {cache_control})")
        except requests.RequestException:
            continue
    return findings


def check_tls_config(host):
    """Basic TLS configuration check."""
    print(f"\n[*] Checking TLS on {host}...")
    findings = []
    try:
        resp = requests.get(f"http://{host}/", timeout=5, allow_redirects=False, verify=False)
        if resp.status_code not in (301, 302, 307, 308):
            findings.append({
                "type": "NO_HTTPS_REDIRECT", "host": host,
                "status": resp.status_code, "severity": "HIGH",
            })
            print(f"  [!] HTTP does not redirect to HTTPS (status {resp.status_code})")
        else:
            location = resp.headers.get("Location", "")
            if location.startswith("https://"):
                print(f"  [+] HTTP redirects to HTTPS")
    except requests.RequestException:
        print(f"  [+] HTTP not accessible (HTTPS only)")

    try:
        resp = requests.get(f"https://{host}/", timeout=5, verify=False)
        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            findings.append({"type": "MISSING_HSTS", "host": host, "severity": "MEDIUM"})
            print(f"  [!] Missing HSTS header")
        else:
            print(f"  [+] HSTS: {hsts}")
    except requests.RequestException:
        pass
    return findings


def check_error_verbosity(base_url):
    """Test if error responses leak sensitive information."""
    print("\n[*] Testing error response verbosity...")
    findings = []
    test_requests = [
        {"method": "POST", "url": "/api/users", "data": '{"invalid": data'},
        {"method": "GET", "url": "/api/nonexistent/path"},
        {"method": "GET", "url": "/api/users/999999999"},
    ]
    verbose_patterns = ["traceback", "stack trace", "exception", "sql", "at line",
                        "file \"", "internal server", "debug"]
    for tr in test_requests:
        url = urljoin(base_url, tr["url"])
        try:
            resp = requests.request(tr["method"], url, data=tr.get("data"),
                                    timeout=10, verify=False)
            text_lower = resp.text.lower()
            matches = [p for p in verbose_patterns if p in text_lower]
            if matches:
                findings.append({
                    "type": "VERBOSE_ERROR", "url": tr["url"],
                    "patterns": matches, "severity": "MEDIUM",
                })
                print(f"  [!] {tr['url']}: Verbose error ({matches})")
        except requests.RequestException:
            continue
    return findings


def generate_report(findings, output_path):
    """Generate sensitive data exposure report."""
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
    print(f"\n[*] Report: {output_path} | Total: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="Sensitive Data Exposure Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--token", help="Bearer token for authenticated testing")
    parser.add_argument("--endpoints", nargs="+",
                        default=["/api/users/me", "/api/users", "/api/account"])
    parser.add_argument("-o", "--output", default="data_exposure_report.json")
    args = parser.parse_args()

    print(f"[*] Sensitive Data Exposure Assessment: {args.base_url}")
    findings = []
    findings.extend(scan_javascript_files(args.base_url))
    findings.extend(check_config_files(args.base_url))
    findings.extend(check_error_verbosity(args.base_url))
    from urllib.parse import urlparse
    host = urlparse(args.base_url).netloc
    findings.extend(check_tls_config(host))
    if args.token:
        findings.extend(check_api_data_exposure(args.base_url, args.token, args.endpoints))
        findings.extend(check_security_headers(args.base_url, args.endpoints))
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
