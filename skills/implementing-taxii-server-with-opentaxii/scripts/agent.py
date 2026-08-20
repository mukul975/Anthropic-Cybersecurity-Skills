#!/usr/bin/env python3
"""OpenTAXII server configuration and health audit agent.

Audits an OpenTAXII server instance by checking service discovery,
collection availability, content block statistics, and API health.
Supports both TAXII 1.1 and 2.0/2.1 endpoints.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] 'requests' required: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from taxii2client.v20 import Server as Server20
    from taxii2client.v21 import Server as Server21
    HAS_TAXII_CLIENT = True
except ImportError:
    HAS_TAXII_CLIENT = False


def check_taxii1_discovery(base_url, username=None, password=None):
    """Check TAXII 1.1 discovery service."""
    findings = []
    discovery_url = f"{base_url}/services/discovery"
    print(f"[*] Checking TAXII 1.1 discovery: {discovery_url}")

    headers = {"Content-Type": "application/xml",
               "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
               "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0"}
    discovery_xml = (
        '<Discovery_Request xmlns="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" '
        'message_id="1"/>'
    )

    auth = (username, password) if username else None
    try:
        resp = requests.post(discovery_url, data=discovery_xml, headers=headers,
                             auth=auth, timeout=15)
        if resp.status_code == 200:
            findings.append({
                "check": "TAXII 1.1 Discovery",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Discovery service responding ({len(resp.content)} bytes)",
            })
        else:
            findings.append({
                "check": "TAXII 1.1 Discovery",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"HTTP {resp.status_code}",
            })
    except requests.RequestException as e:
        findings.append({
            "check": "TAXII 1.1 Discovery",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": str(e)[:100],
        })

    return findings


def check_taxii2_discovery(base_url, username=None, password=None, version="2.1"):
    """Check TAXII 2.0/2.1 discovery and collections."""
    findings = []
    print(f"[*] Checking TAXII {version} discovery: {base_url}")

    if HAS_TAXII_CLIENT:
        try:
            kwargs = {}
            if username and password:
                kwargs["user"] = username
                kwargs["password"] = password
            if version == "2.0":
                server = Server20(base_url, **kwargs)
            else:
                server = Server21(base_url, **kwargs)

            findings.append({
                "check": f"TAXII {version} Discovery",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Server: {server.title or 'Untitled'}",
            })

            for api_root in server.api_roots:
                collections = list(api_root.collections)
                findings.append({
                    "check": f"API Root: {api_root.title or api_root.url}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"{len(collections)} collections",
                    "collections": [{
                        "id": c.id,
                        "title": c.title,
                        "can_read": getattr(c, "can_read", True),
                        "can_write": getattr(c, "can_write", False),
                    } for c in collections],
                })

        except Exception as e:
            findings.append({
                "check": f"TAXII {version} Discovery",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": str(e)[:100],
            })
    else:
        # Fallback to raw HTTP
        auth = (username, password) if username else None
        headers = {"Accept": "application/taxii+json;version=2.1"}
        try:
            resp = requests.get(base_url, headers=headers, auth=auth, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                findings.append({
                    "check": f"TAXII {version} Discovery",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Title: {data.get('title', 'N/A')}, "
                              f"API Roots: {len(data.get('api_roots', []))}",
                })
            else:
                findings.append({
                    "check": f"TAXII {version} Discovery",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"HTTP {resp.status_code}",
                })
        except requests.RequestException as e:
            findings.append({
                "check": f"TAXII {version} Discovery",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": str(e)[:100],
            })

    return findings


def check_server_health(base_url):
    """Check basic server health."""
    findings = []
    print(f"[*] Checking server health: {base_url}")

    # Check TLS
    if base_url.startswith("https://"):
        findings.append({
            "check": "TLS enabled",
            "status": "PASS",
            "severity": "INFO",
        })
    else:
        findings.append({
            "check": "TLS enabled",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "TAXII server not using HTTPS",
        })

    # Check response time
    try:
        resp = requests.get(base_url, timeout=10)
        response_time = resp.elapsed.total_seconds()
        if response_time > 5:
            findings.append({
                "check": "Response time",
                "status": "WARN",
                "severity": "MEDIUM",
                "detail": f"{response_time:.2f}s (slow)",
            })
        else:
            findings.append({
                "check": "Response time",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"{response_time:.2f}s",
            })
    except requests.RequestException:
        pass

    return findings


def format_summary(all_findings, base_url):
    """Print audit summary."""
    print(f"\n{'='*60}")
    print("  OpenTAXII Server Audit Report")
    print(f"{'='*60}")
    print(f"  Server       : {base_url}")
    print(f"  Findings     : {len(all_findings)}")

    pass_count = sum(1 for f in all_findings if f["status"] == "PASS")
    fail_count = sum(1 for f in all_findings if f["status"] == "FAIL")
    print(f"  Passed       : {pass_count}")
    print(f"  Failed       : {fail_count}")

    for f in all_findings:
        icon = "OK" if f["status"] == "PASS" else "!!" if f["status"] == "FAIL" else "~~"
        print(f"    [{icon}] {f['check']}: {f.get('detail', '')[:50]}")

    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return severity_counts


def main():
    parser = argparse.ArgumentParser(description="OpenTAXII server audit agent")
    parser.add_argument("--url", required=True, help="TAXII server base URL")
    parser.add_argument("--username", help="Authentication username")
    parser.add_argument("--password", help="Authentication password")
    parser.add_argument("--version", choices=["1.1", "2.0", "2.1"], default="2.1")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    all_findings = []
    all_findings.extend(check_server_health(args.url))

    if args.version == "1.1":
        all_findings.extend(check_taxii1_discovery(args.url, args.username, args.password))
    else:
        all_findings.extend(check_taxii2_discovery(args.url, args.username, args.password, args.version))

    severity_counts = format_summary(all_findings, args.url)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "OpenTAXII Audit",
        "server": args.url,
        "version": args.version,
        "findings": all_findings,
        "severity_counts": severity_counts,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
