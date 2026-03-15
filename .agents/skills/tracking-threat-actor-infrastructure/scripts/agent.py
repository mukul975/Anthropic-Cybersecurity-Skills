#!/usr/bin/env python3
"""Agent for tracking threat actor infrastructure.

Uses passive DNS, certificate transparency, Shodan, WHOIS, and
network fingerprinting to discover, pivot across, and map
adversary-controlled infrastructure.
"""

import json
import sys
import socket
import ssl
import hashlib
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None


class ThreatInfraTracker:
    """Tracks and pivots across threat actor infrastructure."""

    def __init__(self, shodan_key=None, vt_key=None, output_dir="./threat_infra"):
        self.shodan_key = shodan_key
        self.vt_key = vt_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []
        self.infrastructure = {}

    def _get(self, url, params=None, headers=None, timeout=10):
        if not requests:
            return None
        try:
            return requests.get(url, params=params, headers=headers, timeout=timeout)
        except requests.RequestException:
            return None

    def query_shodan(self, ip):
        """Query Shodan for host information and services."""
        if not self.shodan_key:
            return {"error": "No Shodan API key"}
        resp = self._get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": self.shodan_key})
        if resp and resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": ip, "org": data.get("org"), "asn": data.get("asn"),
                "os": data.get("os"), "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "vulns": data.get("vulns", []),
                "country": data.get("country_code"),
            }
            self.infrastructure[ip] = result
            return result
        return None

    def query_virustotal(self, indicator, indicator_type="ip"):
        """Query VirusTotal for IP/domain reputation."""
        if not self.vt_key:
            return {"error": "No VT API key"}
        type_map = {"ip": "ip-addresses", "domain": "domains", "hash": "files"}
        endpoint = type_map.get(indicator_type, "ip-addresses")
        resp = self._get(f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
                         headers={"x-apikey": self.vt_key})
        if resp and resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            result = {
                "indicator": indicator, "type": indicator_type,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "reputation": data.get("reputation", 0),
            }
            if stats.get("malicious", 0) > 3:
                self.findings.append({"severity": "high", "type": "Malicious Infrastructure",
                                      "detail": f"{indicator} flagged by {stats['malicious']} engines"})
            return result
        return None

    def passive_dns_lookup(self, indicator):
        """Query passive DNS via SecurityTrails-style API."""
        resp = self._get(f"https://api.securitytrails.com/v1/domain/{indicator}/subdomains",
                         headers={"APIKEY": "demo"})
        if resp and resp.status_code == 200:
            return resp.json().get("subdomains", [])
        try:
            ips = socket.getaddrinfo(indicator, None)
            return list({addr[4][0] for addr in ips})
        except socket.gaierror:
            return []

    def get_ssl_certificate(self, host, port=443):
        """Retrieve SSL certificate details for fingerprinting."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(5)
                s.connect((host, port))
                cert = s.getpeercert(binary_form=True)
                cert_hash = hashlib.sha256(cert).hexdigest()
                der_info = s.getpeercert()
                return {
                    "host": host, "sha256": cert_hash,
                    "subject": dict(x[0] for x in der_info.get("subject", [])) if der_info else {},
                    "issuer": dict(x[0] for x in der_info.get("issuer", [])) if der_info else {},
                    "serial": der_info.get("serialNumber") if der_info else None,
                    "not_after": der_info.get("notAfter") if der_info else None,
                }
        except Exception:
            return None

    def check_whois(self, domain):
        """Retrieve WHOIS data via RDAP for pivoting."""
        resp = self._get(f"https://rdap.org/domain/{domain}")
        if resp and resp.status_code == 200:
            data = resp.json()
            registrar = None
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    registrar = entity.get("handle")
            return {
                "domain": domain, "status": data.get("status", []),
                "registrar": registrar,
                "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
            }
        return None

    def fingerprint_http(self, ip, port=80):
        """Fingerprint HTTP server for infrastructure correlation."""
        resp = self._get(f"http://{ip}:{port}/", timeout=5)
        if not resp:
            return None
        headers = dict(resp.headers)
        body_hash = hashlib.sha256(resp.content).hexdigest()
        return {
            "ip": ip, "port": port, "status": resp.status_code,
            "server": headers.get("Server"), "content_type": headers.get("Content-Type"),
            "body_hash": body_hash, "body_length": len(resp.content),
            "headers_of_interest": {k: v for k, v in headers.items()
                                    if k.lower() not in ("date", "content-length", "connection")},
        }

    def pivot_from_ip(self, ip):
        """Perform infrastructure pivoting from a known IP."""
        result = {"ip": ip, "shodan": None, "vt": None, "ssl": None, "http": None}
        result["shodan"] = self.query_shodan(ip)
        result["vt"] = self.query_virustotal(ip, "ip")
        result["ssl"] = self.get_ssl_certificate(ip)
        result["http"] = self.fingerprint_http(ip)
        return result

    def generate_report(self, indicators=None):
        results = {}
        if indicators:
            for ind in indicators:
                results[ind] = self.pivot_from_ip(ind)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "indicators_analyzed": len(indicators or []),
            "pivot_results": results,
            "infrastructure_map": self.infrastructure,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "threat_infra_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <ip_or_domain> [--shodan-key KEY] [--vt-key KEY]")
        sys.exit(1)
    indicators = [sys.argv[1]]
    shodan_key = vt_key = None
    if "--shodan-key" in sys.argv:
        shodan_key = sys.argv[sys.argv.index("--shodan-key") + 1]
    if "--vt-key" in sys.argv:
        vt_key = sys.argv[sys.argv.index("--vt-key") + 1]
    agent = ThreatInfraTracker(shodan_key, vt_key)
    agent.generate_report(indicators)


if __name__ == "__main__":
    main()
