#!/usr/bin/env python3
"""Agent for testing web cache deception vulnerabilities.

Appends static file extensions to authenticated URLs to test
whether CDN/proxy caches serve personalized content to other users.
"""

import requests
import json
import sys
from datetime import datetime


CACHE_EXTENSIONS = [".css", ".js", ".png", ".jpg", ".gif", ".ico",
                    ".svg", ".woff", ".woff2", ".pdf", ".txt"]

CACHE_HEADERS = ["X-Cache", "X-Cache-Status", "CF-Cache-Status",
                 "Age", "X-Varnish", "X-Proxy-Cache", "X-CDN-Cache"]


class WebCacheDeceptionAgent:
    """Tests for web cache deception vulnerabilities."""

    def __init__(self, target_url, auth_cookie=None, auth_header=None):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        if auth_cookie:
            self.session.cookies.set(*auth_cookie.split("=", 1))
        if auth_header:
            self.session.headers["Authorization"] = auth_header
        self.findings = []

    def check_cache_headers(self, response):
        """Extract cache-related headers from response."""
        cache_info = {}
        for header in CACHE_HEADERS:
            val = response.headers.get(header)
            if val:
                cache_info[header] = val
        cache_info["Cache-Control"] = response.headers.get("Cache-Control", "")
        return cache_info

    def test_path_confusion(self, authenticated_path="/account"):
        """Test cache deception via path confusion with static extensions."""
        url = f"{self.target_url}{authenticated_path}"
        results = []

        baseline = self.session.get(url, timeout=10, allow_redirects=False)
        baseline_len = len(baseline.text)
        baseline_has_pii = self._check_pii(baseline.text)

        for ext in CACHE_EXTENSIONS:
            test_url = f"{url}/nonexistent{ext}"
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                cache_info = self.check_cache_headers(resp)
                cached = any(v.lower() in ("hit", "true", "1")
                             for v in cache_info.values() if isinstance(v, str))
                content_match = abs(len(resp.text) - baseline_len) < 100

                if content_match and resp.status_code == 200:
                    unauth = requests.get(test_url, timeout=10)
                    served_to_unauth = abs(len(unauth.text) - baseline_len) < 100

                    if served_to_unauth:
                        self.findings.append({
                            "type": "Web Cache Deception",
                            "severity": "Critical",
                            "url": test_url,
                            "extension": ext,
                            "cached_pii": baseline_has_pii,
                        })

                results.append({
                    "extension": ext, "url": test_url,
                    "status": resp.status_code,
                    "content_match": content_match,
                    "cache_headers": cache_info,
                    "cached": cached,
                })
            except requests.RequestException:
                continue
        return results

    def test_delimiter_confusion(self, authenticated_path="/account"):
        """Test path delimiter confusion (semicolon, hash, question mark)."""
        delimiters = [";", "%23", "%3f", "%3b", "\r\n"]
        results = []
        for delim in delimiters:
            for ext in [".css", ".js", ".png"]:
                test_url = f"{self.target_url}{authenticated_path}{delim}test{ext}"
                try:
                    resp = self.session.get(test_url, timeout=10)
                    cache_info = self.check_cache_headers(resp)
                    results.append({
                        "delimiter": delim, "extension": ext,
                        "status": resp.status_code,
                        "cache_headers": cache_info,
                    })
                except requests.RequestException:
                    continue
        return results

    def _check_pii(self, text):
        """Check if response contains PII indicators."""
        pii_indicators = ["email", "username", "name", "address", "phone",
                          "ssn", "credit", "account", "@"]
        return any(indicator in text.lower() for indicator in pii_indicators)

    def generate_report(self):
        report = {
            "target": self.target_url,
            "report_date": datetime.utcnow().isoformat(),
            "vulnerable": len(self.findings) > 0,
            "findings_count": len(self.findings),
            "findings": self.findings,
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    path = sys.argv[2] if len(sys.argv) > 2 else "/account"
    cookie = sys.argv[3] if len(sys.argv) > 3 else None
    agent = WebCacheDeceptionAgent(url, auth_cookie=cookie)
    agent.test_path_confusion(path)
    agent.test_delimiter_confusion(path)
    agent.generate_report()


if __name__ == "__main__":
    main()
