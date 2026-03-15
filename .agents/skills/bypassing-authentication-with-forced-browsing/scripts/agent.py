#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Forced Browsing Authentication Bypass Agent - Tests for unprotected endpoints."""

import json
import logging
import argparse
from urllib.parse import urljoin

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_ADMIN_PATHS = [
    "/admin", "/administrator", "/admin-panel", "/wp-admin", "/cpanel",
    "/phpmyadmin", "/adminer", "/manager", "/console", "/debug",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/swagger-ui", "/swagger-ui.html", "/api-docs", "/graphql", "/graphiql",
    "/.env", "/server-status", "/server-info", "/.git/HEAD", "/.git/config",
    "/web.config", "/phpinfo.php", "/robots.txt", "/sitemap.xml",
]

SENSITIVE_EXTENSIONS = [
    ".bak", ".old", ".orig", ".save", ".swp", ".tmp", ".config",
    ".sql", ".gz", ".tar", ".zip", ".env",
]


def load_wordlist(wordlist_path):
    """Load directory/file wordlist from file."""
    with open(wordlist_path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def test_endpoint(base_url, path, session_cookie=None, timeout=10):
    """Test a single endpoint with and without authentication."""
    url = urljoin(base_url, path)
    unauth_resp = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)

    auth_resp = None
    if session_cookie:
        auth_resp = requests.get(
            url, cookies={"session": session_cookie},
            timeout=timeout, allow_redirects=False, verify=False,
        )

    result = {
        "path": path,
        "url": url,
        "unauth_status": unauth_resp.status_code,
        "unauth_size": len(unauth_resp.content),
    }
    if auth_resp:
        result["auth_status"] = auth_resp.status_code
        result["auth_size"] = len(auth_resp.content)
        result["auth_bypass"] = (
            unauth_resp.status_code == 200 and auth_resp.status_code == 200
            and abs(result["unauth_size"] - result["auth_size"]) < 100
        )
    return result


def enumerate_directories(base_url, wordlist, session_cookie=None):
    """Enumerate directories and test authentication enforcement."""
    findings = []
    for word in wordlist:
        path = f"/{word}" if not word.startswith("/") else word
        try:
            result = test_endpoint(base_url, path, session_cookie)
            if result["unauth_status"] in (200, 301, 302, 403):
                findings.append(result)
                logger.info(
                    "Found: %s (status: %d, size: %d)",
                    path, result["unauth_status"], result["unauth_size"],
                )
        except requests.RequestException:
            continue
    return findings


def test_http_method_bypass(base_url, path):
    """Test HTTP method-based authentication bypass."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    results = {}
    for method in methods:
        try:
            resp = requests.request(method, urljoin(base_url, path), timeout=10, verify=False)
            results[method] = resp.status_code
        except requests.RequestException:
            results[method] = None
    logger.info("Method bypass test for %s: %s", path, results)
    return results


def test_path_traversal_bypass(base_url, path):
    """Test path normalization bypass techniques."""
    variants = [
        path,
        path.upper(),
        path.replace("/", "/./"),
        f"/public/..{path}",
        path.replace("/", "%2f"),
        f"/;{path}",
        f"/.;{path}",
        f"{path}/",
        f"{path}.json",
    ]
    results = []
    for variant in variants:
        try:
            resp = requests.get(urljoin(base_url, variant), timeout=10, verify=False)
            results.append({"path": variant, "status": resp.status_code, "size": len(resp.content)})
        except requests.RequestException:
            continue
    return results


def check_sensitive_files(base_url):
    """Check for exposed backup and configuration files."""
    sensitive_paths = [
        ".env", ".git/HEAD", ".git/config", "web.config", "wp-config.php.bak",
        "config.php.old", ".htpasswd", "database.yml", "phpinfo.php",
    ]
    exposed = []
    for path in sensitive_paths:
        try:
            resp = requests.get(urljoin(base_url, path), timeout=10, verify=False)
            if resp.status_code == 200 and len(resp.content) > 0:
                exposed.append({"path": path, "status": resp.status_code, "size": len(resp.content)})
                logger.warning("EXPOSED: %s (size: %d bytes)", path, len(resp.content))
        except requests.RequestException:
            continue
    return exposed


def generate_report(findings, method_results, sensitive_files):
    """Generate pentest finding report for forced browsing results."""
    report = {
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "total_endpoints_found": len(findings),
        "auth_bypass_candidates": [f for f in findings if f.get("auth_bypass")],
        "accessible_without_auth": [f for f in findings if f["unauth_status"] == 200],
        "http_method_bypass": method_results,
        "sensitive_files_exposed": sensitive_files,
    }
    bypasses = len(report["auth_bypass_candidates"])
    logger.info("Report: %d endpoints, %d auth bypasses, %d sensitive files",
                len(findings), bypasses, len(sensitive_files))
    return report


def main():
    parser = argparse.ArgumentParser(description="Forced Browsing Authentication Bypass Agent")
    parser.add_argument("--target", required=True, help="Target base URL")
    parser.add_argument("--wordlist", help="Path to wordlist file")
    parser.add_argument("--session-cookie", help="Valid session cookie for auth comparison")
    parser.add_argument("--admin-paths", action="store_true", help="Test common admin paths")
    parser.add_argument("--output", default="forced_browsing_report.json")
    args = parser.parse_args()

    wordlist = DEFAULT_ADMIN_PATHS if args.admin_paths else []
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)

    findings = enumerate_directories(args.target, wordlist, args.session_cookie)
    method_results = {}
    for f in findings:
        if f["unauth_status"] in (401, 403):
            method_results[f["path"]] = test_http_method_bypass(args.target, f["path"])

    sensitive = check_sensitive_files(args.target)
    report = generate_report(findings, method_results, sensitive)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
