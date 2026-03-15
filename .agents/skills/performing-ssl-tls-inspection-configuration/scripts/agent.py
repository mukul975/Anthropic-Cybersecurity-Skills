#!/usr/bin/env python3
"""Agent for SSL/TLS inspection configuration validation.

Verifies TLS inspection is working by comparing certificate issuers,
validates CA deployment on endpoints, checks TLS version enforcement,
audits decryption exemption lists, and monitors inspection health.
"""

import ssl
import socket
import json
import sys
import subprocess
from datetime import datetime


class TLSInspectionAgent:
    """Validates SSL/TLS inspection configuration and health."""

    def __init__(self, internal_ca_cn=None):
        self.internal_ca_cn = internal_ca_cn or "SSL Inspection CA"
        self.results = []

    def check_inspection_active(self, hostname, port=443):
        """Connect to external host and check if cert is signed by internal CA."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(),
                                 server_hostname=hostname) as s:
                s.settimeout(10)
                s.connect((hostname, port))
                cert = s.getpeercert(binary_form=False)
                if not cert:
                    der = s.getpeercert(binary_form=True)
                    return {"hostname": hostname, "inspection": "unknown",
                            "note": "Could not parse certificate"}

            issuer = dict(x[0] for x in cert.get("issuer", ()))
            issuer_cn = issuer.get("commonName", "")
            issuer_org = issuer.get("organizationName", "")
            subject = dict(x[0] for x in cert.get("subject", ()))

            is_inspected = self.internal_ca_cn.lower() in issuer_cn.lower()

            result = {
                "hostname": hostname, "port": port,
                "subject_cn": subject.get("commonName", ""),
                "issuer_cn": issuer_cn,
                "issuer_org": issuer_org,
                "inspection_active": is_inspected,
                "tls_version": s.version() if hasattr(s, "version") else "unknown",
            }
            self.results.append(result)
            return result

        except (socket.error, ssl.SSLError, OSError) as exc:
            result = {"hostname": hostname, "error": str(exc)}
            self.results.append(result)
            return result

    def check_tls_version(self, hostname, port=443):
        """Check minimum TLS version supported by the inspecting proxy."""
        versions_to_test = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
        ]
        results = []
        for name, ver in versions_to_test:
            if ver is None:
                results.append({"version": name, "status": "not_testable"})
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                with ctx.wrap_socket(socket.socket(),
                                     server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, port))
                    results.append({"version": name, "status": "accepted"})
            except (ssl.SSLError, socket.error):
                results.append({"version": name, "status": "rejected"})
        return results

    def verify_ca_deployed(self):
        """Check if the inspection CA certificate is in the local trust store."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f'Get-ChildItem Cert:\\LocalMachine\\Root | '
                 f'Where-Object {{$_.Subject -like "*{self.internal_ca_cn}*"}} | '
                 f'Select-Object Subject,NotAfter,Thumbprint | ConvertTo-Json'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return {"ca_deployed": True, "certificates": data}
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        return {"ca_deployed": False}

    def audit_exemptions(self, exempt_domains):
        """Verify exempted domains bypass inspection (show original CA)."""
        results = []
        for domain in exempt_domains:
            info = self.check_inspection_active(domain)
            results.append({
                "domain": domain,
                "correctly_exempted": not info.get("inspection_active", True),
                "issuer": info.get("issuer_cn", ""),
            })
        return results

    def scan_multiple(self, hostnames):
        """Check inspection status for multiple external hosts."""
        for host in hostnames:
            self.check_inspection_active(host)
        return self.results

    def generate_report(self):
        """Generate inspection validation report."""
        inspected = sum(1 for r in self.results if r.get("inspection_active"))
        not_inspected = sum(1 for r in self.results
                           if r.get("inspection_active") is False)
        errors = sum(1 for r in self.results if "error" in r)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "internal_ca": self.internal_ca_cn,
            "total_tested": len(self.results),
            "inspected": inspected,
            "not_inspected": not_inspected,
            "errors": errors,
            "results": self.results,
        }
        print(json.dumps(report, indent=2, default=str))
        return report


def main():
    ca_cn = sys.argv[1] if len(sys.argv) > 1 else "SSL Inspection CA"
    hosts = sys.argv[2:] if len(sys.argv) > 2 else [
        "www.google.com", "github.com", "www.example.com"]
    agent = TLSInspectionAgent(internal_ca_cn=ca_cn)
    agent.scan_multiple(hosts)
    agent.generate_report()


if __name__ == "__main__":
    main()
