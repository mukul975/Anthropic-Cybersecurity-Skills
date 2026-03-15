#!/usr/bin/env python3
"""
Mobile Traffic Analysis Pipeline for Burp Suite Exports

Parses Burp Suite XML export files to identify security findings in mobile API traffic.
Analyzes authentication patterns, sensitive data exposure, and security header compliance.

Usage:
    python process.py --burp-xml export.xml [--output report.json]
"""

import argparse
import json
import sys
import base64
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs


class BurpTrafficAnalyzer:
    """Analyzes Burp Suite XML exports for mobile security findings."""

    SENSITIVE_PATTERNS = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "api_key": r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})",
        "bearer_token": r"Bearer\s+[a-zA-Z0-9_.-]+",
    }

    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Cache-Control",
    ]

    def __init__(self, xml_path: str):
        self.xml_path = xml_path
        self.requests = []
        self.findings = []

    def parse_burp_xml(self) -> int:
        """Parse Burp Suite XML export file."""
        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        for item in root.findall(".//item"):
            request_data = {
                "url": item.findtext("url", ""),
                "host": item.findtext("host", ""),
                "port": item.findtext("port", ""),
                "protocol": item.findtext("protocol", ""),
                "method": item.findtext("method", ""),
                "path": item.findtext("path", ""),
                "status": item.findtext("status", ""),
                "mime_type": item.findtext("mimetype", ""),
            }

            # Decode request
            req_elem = item.find("request")
            if req_elem is not None and req_elem.text:
                is_base64 = req_elem.get("base64", "false") == "true"
                request_data["request_body"] = (
                    base64.b64decode(req_elem.text).decode("utf-8", errors="replace")
                    if is_base64 else req_elem.text
                )
            else:
                request_data["request_body"] = ""

            # Decode response
            resp_elem = item.find("response")
            if resp_elem is not None and resp_elem.text:
                is_base64 = resp_elem.get("base64", "false") == "true"
                request_data["response_body"] = (
                    base64.b64decode(resp_elem.text).decode("utf-8", errors="replace")
                    if is_base64 else resp_elem.text
                )
            else:
                request_data["response_body"] = ""

            self.requests.append(request_data)

        return len(self.requests)

    def analyze_cleartext_traffic(self) -> list:
        """Identify HTTP (non-HTTPS) traffic."""
        cleartext = [
            r for r in self.requests
            if r["protocol"].lower() == "http"
        ]

        if cleartext:
            self.findings.append({
                "type": "cleartext_traffic",
                "severity": "HIGH",
                "owasp_mobile": "M5",
                "count": len(cleartext),
                "urls": list(set(r["url"] for r in cleartext))[:10],
                "description": f"{len(cleartext)} requests sent over unencrypted HTTP",
            })
        return cleartext

    def analyze_sensitive_data(self) -> list:
        """Scan traffic for sensitive data patterns."""
        sensitive_findings = []

        for req in self.requests:
            combined_text = req.get("response_body", "") + req.get("request_body", "")
            for pattern_name, pattern_regex in self.SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern_regex, combined_text)
                if matches:
                    sensitive_findings.append({
                        "url": req["url"],
                        "pattern": pattern_name,
                        "match_count": len(matches),
                        "sample": matches[0][:20] + "..." if matches else "",
                    })

        if sensitive_findings:
            self.findings.append({
                "type": "sensitive_data_exposure",
                "severity": "HIGH",
                "owasp_mobile": "M9",
                "count": len(sensitive_findings),
                "details": sensitive_findings[:20],
                "description": f"Sensitive data patterns found in {len(sensitive_findings)} request/response pairs",
            })
        return sensitive_findings

    def analyze_security_headers(self) -> dict:
        """Check for missing security headers in responses."""
        header_coverage = {h: 0 for h in self.SECURITY_HEADERS}
        total_responses = 0

        for req in self.requests:
            resp = req.get("response_body", "")
            if resp:
                total_responses += 1
                for header in self.SECURITY_HEADERS:
                    if header.lower() in resp.lower():
                        header_coverage[header] += 1

        missing = [h for h, count in header_coverage.items() if count == 0]

        if missing:
            self.findings.append({
                "type": "missing_security_headers",
                "severity": "MEDIUM",
                "owasp_mobile": "M8",
                "missing_headers": missing,
                "total_responses": total_responses,
                "description": f"Missing security headers: {', '.join(missing)}",
            })
        return header_coverage

    def analyze_authentication(self) -> list:
        """Analyze authentication patterns in traffic."""
        auth_findings = []

        for req in self.requests:
            body = req.get("request_body", "")

            # Check for credentials in URL parameters
            parsed = urlparse(req["url"])
            params = parse_qs(parsed.query)
            sensitive_params = [
                k for k in params
                if any(s in k.lower() for s in ["password", "token", "key", "secret", "auth"])
            ]
            if sensitive_params:
                auth_findings.append({
                    "url": req["url"],
                    "issue": "credentials_in_url",
                    "parameters": sensitive_params,
                })

            # Check for basic auth
            if "Authorization: Basic" in body:
                auth_findings.append({
                    "url": req["url"],
                    "issue": "basic_auth_used",
                })

        if auth_findings:
            self.findings.append({
                "type": "authentication_issues",
                "severity": "HIGH",
                "owasp_mobile": "M1",
                "count": len(auth_findings),
                "details": auth_findings[:10],
                "description": f"{len(auth_findings)} authentication-related issues found",
            })
        return auth_findings

    def analyze_api_surface(self) -> dict:
        """Map the API surface area from captured traffic."""
        endpoints = Counter()
        methods = Counter()
        hosts = Counter()

        for req in self.requests:
            parsed = urlparse(req["url"])
            path = re.sub(r"\d+", "{id}", parsed.path)
            endpoints[f"{req['method']} {path}"] += 1
            methods[req["method"]] += 1
            hosts[req["host"]] += 1

        return {
            "unique_endpoints": len(endpoints),
            "top_endpoints": endpoints.most_common(20),
            "methods": dict(methods),
            "hosts": dict(hosts),
        }

    def generate_report(self) -> dict:
        """Generate comprehensive traffic analysis report."""
        api_surface = self.analyze_api_surface()

        return {
            "analysis": {
                "source_file": self.xml_path,
                "date": datetime.now().isoformat(),
                "total_requests": len(self.requests),
                "tool": "Burp Suite Traffic Analyzer",
            },
            "api_surface": api_surface,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": Counter(f["severity"] for f in self.findings),
            },
        }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Burp Suite XML exports for mobile security findings"
    )
    parser.add_argument("--burp-xml", required=True, help="Path to Burp Suite XML export")
    parser.add_argument("--output", default="traffic_analysis.json", help="Output report path")
    args = parser.parse_args()

    if not Path(args.burp_xml).exists():
        print(f"[-] File not found: {args.burp_xml}")
        sys.exit(1)

    analyzer = BurpTrafficAnalyzer(args.burp_xml)

    # Parse
    count = analyzer.parse_burp_xml()
    print(f"[+] Parsed {count} requests from Burp export")

    # Run analyses
    analyzer.analyze_cleartext_traffic()
    analyzer.analyze_sensitive_data()
    analyzer.analyze_security_headers()
    analyzer.analyze_authentication()

    # Generate report
    report = analyzer.generate_report()

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report saved: {args.output}")
    print(f"[*] Total findings: {report['summary']['total_findings']}")


if __name__ == "__main__":
    main()
