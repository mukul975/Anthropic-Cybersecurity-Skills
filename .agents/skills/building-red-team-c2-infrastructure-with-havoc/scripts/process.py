#!/usr/bin/env python3
"""
Havoc C2 Infrastructure Health Monitor

Monitors Havoc C2 infrastructure components (teamserver, redirectors,
listeners) and generates operational status reports for red team operations.
"""

import json
import socket
import ssl
import os
import hashlib
import subprocess
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


@dataclass
class InfraComponent:
    """Represents an infrastructure component."""
    name: str
    host: str
    port: int
    component_type: str  # teamserver, redirector, listener, dns
    protocol: str = "tcp"
    expected_response: str = ""
    ssl_enabled: bool = False


@dataclass
class HealthCheck:
    """Result of a health check."""
    component: str
    host: str
    port: int
    status: str  # up, down, degraded
    latency_ms: float = 0.0
    ssl_valid: bool = False
    ssl_expiry: str = ""
    details: str = ""
    timestamp: str = ""


class HavocInfraMonitor:
    """Monitor Havoc C2 infrastructure health and OPSEC status."""

    def __init__(self, config_path: Optional[str] = None):
        self.components: list[InfraComponent] = []
        self.check_results: list[HealthCheck] = []
        self.alerts: list[str] = []

        if config_path and os.path.exists(config_path):
            self._load_config(config_path)

    def _load_config(self, config_path: str) -> None:
        """Load infrastructure configuration from JSON."""
        with open(config_path) as f:
            config = json.load(f)
        for comp in config.get("components", []):
            self.components.append(InfraComponent(**comp))

    def add_component(self, component: InfraComponent) -> None:
        """Add an infrastructure component to monitor."""
        self.components.append(component)

    def check_tcp_port(self, host: str, port: int, timeout: float = 5.0) -> tuple[bool, float]:
        """Check if a TCP port is open and measure latency."""
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            latency = (time.time() - start) * 1000
            sock.close()
            return result == 0, latency
        except (socket.error, socket.timeout):
            return False, 0.0

    def check_ssl_certificate(self, host: str, port: int = 443) -> dict:
        """Check SSL certificate validity and expiration."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter", "")
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))

                    # Parse expiry
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expiry - datetime.utcnow()).days

                    return {
                        "valid": True,
                        "expiry": not_after,
                        "days_remaining": days_remaining,
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "self_signed": subject.get("commonName") == issuer.get("commonName"),
                    }
        except ssl.SSLCertVerificationError as e:
            return {"valid": False, "error": str(e), "self_signed": True}
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def check_http_response(self, host: str, port: int, path: str = "/",
                            ssl_enabled: bool = True, expected_status: int = 200) -> dict:
        """Check HTTP/HTTPS endpoint response."""
        scheme = "https" if ssl_enabled else "http"
        url = f"{scheme}://{host}:{port}{path}"
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            start = time.time()
            resp = urlopen(req, timeout=10, context=context)
            latency = (time.time() - start) * 1000
            return {
                "status_code": resp.getcode(),
                "latency_ms": latency,
                "headers": dict(resp.headers),
                "reachable": True,
            }
        except HTTPError as e:
            return {"status_code": e.code, "reachable": True, "error": str(e)}
        except URLError as e:
            return {"reachable": False, "error": str(e)}

    def check_dns_resolution(self, domain: str) -> dict:
        """Verify DNS resolution for C2 domains."""
        try:
            results = socket.getaddrinfo(domain, None)
            ips = list(set(r[4][0] for r in results))
            return {"resolved": True, "ips": ips}
        except socket.gaierror as e:
            return {"resolved": False, "error": str(e)}

    def run_all_checks(self) -> list[HealthCheck]:
        """Run health checks on all configured components."""
        self.check_results = []
        self.alerts = []

        for comp in self.components:
            print(f"[*] Checking {comp.name} ({comp.host}:{comp.port})...")

            # TCP port check
            is_up, latency = self.check_tcp_port(comp.host, comp.port)

            check = HealthCheck(
                component=comp.name,
                host=comp.host,
                port=comp.port,
                status="up" if is_up else "down",
                latency_ms=latency,
                timestamp=datetime.utcnow().isoformat(),
            )

            if not is_up:
                self.alerts.append(f"CRITICAL: {comp.name} ({comp.host}:{comp.port}) is DOWN")
                check.details = "TCP connection failed"
                self.check_results.append(check)
                continue

            # SSL check for HTTPS components
            if comp.ssl_enabled:
                ssl_info = self.check_ssl_certificate(comp.host, comp.port)
                check.ssl_valid = ssl_info.get("valid", False)
                check.ssl_expiry = ssl_info.get("expiry", "")

                if ssl_info.get("self_signed", False):
                    self.alerts.append(
                        f"OPSEC WARNING: {comp.name} has self-signed certificate!"
                    )
                if ssl_info.get("days_remaining", 999) < 7:
                    self.alerts.append(
                        f"WARNING: {comp.name} SSL expires in "
                        f"{ssl_info['days_remaining']} days"
                    )

            # HTTP response check for web-based components
            if comp.component_type in ("redirector", "listener"):
                http_info = self.check_http_response(
                    comp.host, comp.port, ssl_enabled=comp.ssl_enabled
                )
                if http_info.get("reachable"):
                    server_header = http_info.get("headers", {}).get("Server", "")
                    if "Havoc" in server_header:
                        self.alerts.append(
                            f"OPSEC CRITICAL: {comp.name} leaking Havoc in Server header!"
                        )
                    check.details = f"HTTP {http_info.get('status_code', 'N/A')}"

            # Latency check
            if latency > 1000:
                self.alerts.append(
                    f"WARNING: {comp.name} high latency: {latency:.0f}ms"
                )
                check.status = "degraded"

            self.check_results.append(check)

        return self.check_results

    def check_domain_opsec(self, domain: str) -> dict:
        """Check domain OPSEC status."""
        results = {
            "domain": domain,
            "dns_resolves": False,
            "checks": [],
        }

        # DNS resolution
        dns = self.check_dns_resolution(domain)
        results["dns_resolves"] = dns.get("resolved", False)
        results["resolved_ips"] = dns.get("ips", [])

        # Check if domain is too new (WHOIS-based heuristic)
        results["checks"].append({
            "check": "DNS Resolution",
            "status": "PASS" if dns.get("resolved") else "FAIL",
        })

        # SSL certificate check
        ssl_info = self.check_ssl_certificate(domain)
        results["checks"].append({
            "check": "Valid SSL Certificate",
            "status": "PASS" if ssl_info.get("valid") else "FAIL",
            "details": ssl_info,
        })

        if ssl_info.get("self_signed"):
            results["checks"].append({
                "check": "Not Self-Signed",
                "status": "FAIL",
                "details": "Self-signed certificates are an OPSEC failure",
            })

        return results

    def generate_status_report(self) -> str:
        """Generate infrastructure status report."""
        lines = []
        lines.append("=" * 60)
        lines.append("HAVOC C2 INFRASTRUCTURE STATUS REPORT")
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append("=" * 60)

        # Component status
        lines.append("\nCOMPONENT STATUS:")
        lines.append("-" * 60)
        for check in self.check_results:
            status_icon = {
                "up": "[+]",
                "down": "[!]",
                "degraded": "[~]",
            }.get(check.status, "[?]")
            lines.append(
                f"  {status_icon} {check.component:<25} "
                f"{check.status.upper():<10} "
                f"{check.latency_ms:.0f}ms"
            )
            if check.ssl_valid:
                lines.append(f"      SSL: Valid (expires {check.ssl_expiry})")
            if check.details:
                lines.append(f"      Details: {check.details}")

        # Alerts
        if self.alerts:
            lines.append("\nALERTS:")
            lines.append("-" * 60)
            for alert in self.alerts:
                lines.append(f"  {alert}")

        # Summary
        total = len(self.check_results)
        up = sum(1 for c in self.check_results if c.status == "up")
        down = sum(1 for c in self.check_results if c.status == "down")
        degraded = sum(1 for c in self.check_results if c.status == "degraded")

        lines.append(f"\nSUMMARY: {up}/{total} UP | {degraded} DEGRADED | {down} DOWN")

        if down > 0:
            lines.append("STATUS: INFRASTRUCTURE DEGRADED - IMMEDIATE ACTION REQUIRED")
        elif self.alerts:
            lines.append("STATUS: OPERATIONAL WITH WARNINGS")
        else:
            lines.append("STATUS: FULLY OPERATIONAL")

        return "\n".join(lines)

    def export_json(self, output_path: str) -> None:
        """Export results to JSON."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "components": [asdict(c) for c in self.check_results],
            "alerts": self.alerts,
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Results exported to {output_path}")


def main():
    """Demonstrate infrastructure monitoring."""
    monitor = HavocInfraMonitor()

    # Configure infrastructure components
    monitor.add_component(InfraComponent(
        name="Havoc Teamserver",
        host="127.0.0.1",
        port=40056,
        component_type="teamserver",
        protocol="tcp",
    ))

    monitor.add_component(InfraComponent(
        name="HTTPS Redirector",
        host="127.0.0.1",
        port=443,
        component_type="redirector",
        ssl_enabled=True,
    ))

    monitor.add_component(InfraComponent(
        name="HTTPS Listener",
        host="127.0.0.1",
        port=443,
        component_type="listener",
        ssl_enabled=True,
    ))

    # Run health checks
    print("[*] Running infrastructure health checks...\n")
    monitor.run_all_checks()

    # Generate report
    report = monitor.generate_status_report()
    print(report)

    # Export results
    monitor.export_json("havoc_infra_status.json")


if __name__ == "__main__":
    main()
