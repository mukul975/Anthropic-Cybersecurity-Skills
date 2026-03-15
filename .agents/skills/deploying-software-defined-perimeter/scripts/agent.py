#!/usr/bin/env python3
"""Software-Defined Perimeter (SDP) deployment audit agent."""

import json
import sys
import argparse
import socket
import ssl
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


def check_spa_port(host, port, timeout=5):
    """Check if a port responds to standard TCP connect (should be dark in SDP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return {"host": host, "port": port, "open": result == 0}
    except socket.error as e:
        return {"host": host, "port": port, "open": False, "error": str(e)}


def audit_dark_ports(host, ports):
    """Verify SDP ports are invisible to unauthorized scanners."""
    results = []
    for port in ports:
        scan = check_spa_port(host, port)
        if scan.get("open"):
            scan["finding"] = "Port visible without SPA — SDP not enforced"
            scan["severity"] = "HIGH"
        else:
            scan["finding"] = "Port dark — SDP enforced"
            scan["severity"] = "INFO"
        results.append(scan)
    return results


def check_tls_mutual_auth(host, port, client_cert=None, client_key=None):
    """Verify mutual TLS authentication on SDP controller."""
    result = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        if client_cert and client_key:
            ctx.load_cert_chain(client_cert, client_key)
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()
            result["tls_version"] = s.version()
            result["cipher"] = s.cipher()[0]
            result["server_cn"] = dict(x[0] for x in cert.get("subject", ()))
            result["mtls_enforced"] = client_cert is not None
    except ssl.SSLError as e:
        result["error"] = str(e)
        if "CERTIFICATE_REQUIRED" in str(e):
            result["mtls_enforced"] = True
            result["finding"] = "Server requires client certificate — mTLS enforced"
    except Exception as e:
        result["error"] = str(e)
    return result


class SDPControllerClient:
    """Client for SDP controller REST API (e.g., Appgate SDP)."""

    def __init__(self, controller_url, username, password):
        self.base_url = controller_url.rstrip("/")
        self.session = requests.Session()
        self._authenticate(username, password)

    def _authenticate(self, username, password):
        resp = self.session.post(f"{self.base_url}/admin/login", json={
            "providerName": "local",
            "username": username,
            "password": password,
        }, timeout=15, verify=True)
        resp.raise_for_status()
        token = resp.json().get("token", "")
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def list_sites(self):
        resp = self.session.get(f"{self.base_url}/admin/sites", timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def list_policies(self):
        resp = self.session.get(f"{self.base_url}/admin/policies", timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def list_entitlements(self):
        resp = self.session.get(f"{self.base_url}/admin/entitlements", timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", [])

    def list_appliances(self):
        resp = self.session.get(f"{self.base_url}/admin/appliances", timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", [])


def run_audit(args):
    """Execute SDP deployment audit."""
    print(f"\n{'='*60}")
    print(f"  SOFTWARE-DEFINED PERIMETER AUDIT")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.scan_host:
        ports = [int(p) for p in args.ports.split(",")] if args.ports else [22, 443, 8443, 3389]
        dark_results = audit_dark_ports(args.scan_host, ports)
        report["dark_port_scan"] = dark_results
        print(f"--- DARK PORT SCAN ({args.scan_host}) ---")
        for r in dark_results:
            status = "OPEN" if r["open"] else "DARK"
            print(f"  Port {r['port']}: {status} — {r['finding']}")

    if args.mtls_host:
        mtls = check_tls_mutual_auth(args.mtls_host, args.mtls_port or 443,
                                      args.client_cert, args.client_key)
        report["mtls_check"] = mtls
        print(f"\n--- MUTUAL TLS CHECK ---")
        print(f"  Host: {mtls['host']}:{mtls['port']}")
        print(f"  mTLS Enforced: {mtls.get('mtls_enforced', 'unknown')}")
        if mtls.get("tls_version"):
            print(f"  TLS Version: {mtls['tls_version']}")

    if args.controller_url and args.username and args.password:
        client = SDPControllerClient(args.controller_url, args.username, args.password)
        appliances = client.list_appliances()
        report["appliances"] = len(appliances)
        print(f"\n--- SDP APPLIANCES ({len(appliances)}) ---")
        for a in appliances[:10]:
            print(f"  {a.get('name', '')}: {a.get('function', '')} ({a.get('state', '')})")

        entitlements = client.list_entitlements()
        report["entitlements"] = len(entitlements)
        print(f"\n--- ENTITLEMENTS ({len(entitlements)}) ---")
        for e in entitlements[:10]:
            print(f"  {e.get('name', '')}: {e.get('site', '')} -> {e.get('actions', [])}")

    return report


def main():
    parser = argparse.ArgumentParser(description="SDP Deployment Audit")
    parser.add_argument("--scan-host", help="Host to scan for dark ports")
    parser.add_argument("--ports", help="Comma-separated ports to scan (default: 22,443,8443,3389)")
    parser.add_argument("--mtls-host", help="Host to check mutual TLS")
    parser.add_argument("--mtls-port", type=int, default=443, help="mTLS port")
    parser.add_argument("--client-cert", help="Client certificate for mTLS test")
    parser.add_argument("--client-key", help="Client key for mTLS test")
    parser.add_argument("--controller-url", help="SDP controller URL (Appgate)")
    parser.add_argument("--username", help="Controller admin username")
    parser.add_argument("--password", help="Controller admin password")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
