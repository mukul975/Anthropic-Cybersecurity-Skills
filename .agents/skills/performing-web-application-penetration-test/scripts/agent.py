#!/usr/bin/env python3
"""Web application penetration test agent using requests and subprocess."""

import subprocess
import sys
import re
import json
import os
from urllib.parse import urlparse, urljoin

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def fingerprint_technology(target_url):
    """Identify technology stack from response headers and cookies."""
    try:
        resp = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
    except RequestException as e:
        return {"error": str(e)}
    headers = dict(resp.headers)
    tech = {"server": headers.get("Server", "Unknown"), "technologies": []}
    if "X-Powered-By" in headers:
        tech["technologies"].append(headers["X-Powered-By"])
    cookies = resp.cookies.get_dict()
    cookie_tech = {
        "JSESSIONID": "Java", "PHPSESSID": "PHP",
        "ASP.NET_SessionId": "ASP.NET", "csrftoken": "Django",
        "laravel_session": "Laravel", "_rails_session": "Ruby on Rails",
    }
    for cookie_name, framework in cookie_tech.items():
        if cookie_name in cookies:
            tech["technologies"].append(framework)
    return tech


def check_security_headers(target_url):
    """Check for presence of security headers."""
    try:
        resp = requests.get(target_url, timeout=10, verify=False)
    except RequestException as e:
        return {"error": str(e)}
    required_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "Clickjacking protection",
        "X-XSS-Protection": "XSS filter",
        "Referrer-Policy": "Referrer control",
        "Permissions-Policy": "Feature policy",
    }
    results = {}
    for header, desc in required_headers.items():
        value = resp.headers.get(header)
        results[header] = {
            "present": value is not None,
            "value": value,
            "description": desc,
        }
    return results


def test_http_methods(target_url):
    """Test for dangerous HTTP methods."""
    dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
    results = []
    for method in dangerous:
        try:
            resp = requests.request(method, target_url, timeout=5, verify=False)
            if resp.status_code not in (405, 501):
                results.append({
                    "method": method, "status": resp.status_code,
                    "risk": "HIGH" if method in ("PUT", "DELETE") else "MEDIUM",
                })
        except RequestException:
            pass
    try:
        resp = requests.options(target_url, timeout=5, verify=False)
        allow = resp.headers.get("Allow", "")
        results.append({"method": "OPTIONS", "allow_header": allow})
    except RequestException:
        pass
    return results


def test_cors_config(target_url):
    """Test CORS configuration for misconfigurations."""
    tests = []
    origins = [
        "https://evil.com",
        "null",
        urlparse(target_url).scheme + "://" + urlparse(target_url).hostname + ".evil.com",
    ]
    for origin in origins:
        try:
            resp = requests.get(
                target_url, headers={"Origin": origin},
                timeout=5, verify=False
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or acao == "*":
                tests.append({
                    "origin": origin, "reflected": True,
                    "allow_credentials": acac.lower() == "true",
                    "risk": "HIGH" if acac.lower() == "true" else "MEDIUM",
                })
        except RequestException:
            pass
    return tests


def run_directory_bruteforce(target_url, wordlist=None):
    """Run directory enumeration using ffuf if available."""
    if wordlist is None:
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    if not os.path.exists(wordlist):
        return {"error": f"Wordlist not found: {wordlist}"}
    try:
        result = subprocess.run(
            ["ffuf", "-w", wordlist, "-u", f"{target_url}/FUZZ",
             "-mc", "200,301,302,403", "-t", "20", "-o", "/tmp/ffuf_output.json",
             "-of", "json", "-s"],
            capture_output=True, text=True, timeout=120
        )
        if os.path.exists("/tmp/ffuf_output.json"):
            with open("/tmp/ffuf_output.json") as f:
                return json.load(f)
        return {"stdout": result.stdout[:1000]}
    except FileNotFoundError:
        return {"error": "ffuf not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "ffuf timeout"}


def test_sql_injection_basic(target_url, params):
    """Test for basic SQL injection indicators."""
    payloads = ["'", "' OR '1'='1", "1 OR 1=1--", "'; DROP TABLE--"]
    sql_errors = [
        "sql syntax", "mysql", "sqlite", "postgresql", "ora-",
        "microsoft ole db", "unclosed quotation", "syntax error",
    ]
    findings = []
    for param_name in params:
        for payload in payloads:
            test_params = {param_name: payload}
            try:
                resp = requests.get(target_url, params=test_params, timeout=10, verify=False)
                body_lower = resp.text.lower()
                for err in sql_errors:
                    if err in body_lower:
                        findings.append({
                            "parameter": param_name, "payload": payload,
                            "error_pattern": err, "status": resp.status_code,
                            "risk": "CRITICAL",
                        })
                        break
            except RequestException:
                pass
    return findings


def test_xss_basic(target_url, params):
    """Test for basic reflected XSS."""
    payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
    ]
    findings = []
    for param_name in params:
        for payload in payloads:
            try:
                resp = requests.get(
                    target_url, params={param_name: payload},
                    timeout=10, verify=False
                )
                if payload in resp.text:
                    findings.append({
                        "parameter": param_name, "payload": payload,
                        "reflected": True, "risk": "HIGH",
                    })
            except RequestException:
                pass
    return findings


def run_assessment(target_url, test_params=None):
    """Run web application security assessment."""
    if test_params is None:
        test_params = ["id", "q", "search", "page", "user"]
    report = {
        "target": target_url,
        "technology": fingerprint_technology(target_url),
        "security_headers": check_security_headers(target_url),
        "http_methods": test_http_methods(target_url),
        "cors": test_cors_config(target_url),
        "sqli_findings": test_sql_injection_basic(target_url, test_params),
        "xss_findings": test_xss_basic(target_url, test_params),
    }
    missing_headers = [
        h for h, v in report["security_headers"].items()
        if isinstance(v, dict) and not v.get("present", True)
    ]
    report["summary"] = {
        "missing_security_headers": len(missing_headers),
        "dangerous_methods": len(report["http_methods"]),
        "cors_issues": len(report["cors"]),
        "sqli_findings": len(report["sqli_findings"]),
        "xss_findings": len(report["xss_findings"]),
    }
    return report


def print_report(report):
    print("Web Application Penetration Test Report")
    print("=" * 50)
    print(f"Target: {report['target']}")
    tech = report["technology"]
    print(f"Server: {tech.get('server', 'Unknown')}")
    if tech.get("technologies"):
        print(f"Stack: {', '.join(tech['technologies'])}")
    print("\nSecurity Headers:")
    for h, v in report["security_headers"].items():
        if isinstance(v, dict):
            status = "PRESENT" if v.get("present") else "MISSING"
            print(f"  {h}: {status}")
    if report["sqli_findings"]:
        print(f"\nSQL Injection: {len(report['sqli_findings'])} finding(s)")
        for f in report["sqli_findings"]:
            print(f"  [{f['risk']}] {f['parameter']}: {f['error_pattern']}")
    if report["xss_findings"]:
        print(f"\nXSS: {len(report['xss_findings'])} finding(s)")
        for f in report["xss_findings"]:
            print(f"  [{f['risk']}] {f['parameter']}: reflected")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    result = run_assessment(target)
    print_report(result)
