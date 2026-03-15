#!/usr/bin/env python3
"""
Sliver C2 Infrastructure Health Check and Management Script

This script provides automated health monitoring for Sliver C2 infrastructure
components including team server, redirectors, and listener status.
Intended for authorized red team engagements only.
"""

import subprocess
import json
import socket
import ssl
import sys
import os
from datetime import datetime
from pathlib import Path


def check_port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a specific port is open on a host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def check_ssl_certificate(host: str, port: int = 443) -> dict:
    """Check SSL certificate validity on a listener."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                return {
                    "status": "valid",
                    "subject": str(cert.get("subject", "N/A")) if cert else "No cert data",
                    "issuer": str(cert.get("issuer", "N/A")) if cert else "No cert data",
                    "expiry": str(cert.get("notAfter", "N/A")) if cert else "No cert data"
                }
    except ssl.SSLError as e:
        return {"status": "ssl_error", "error": str(e)}
    except (socket.error, OSError) as e:
        return {"status": "connection_error", "error": str(e)}


def check_dns_listener(domain: str, nameserver: str = "8.8.8.8") -> dict:
    """Check if DNS C2 domain resolves correctly."""
    try:
        result = subprocess.run(
            ["nslookup", domain, nameserver],
            capture_output=True, text=True, timeout=10
        )
        return {
            "status": "active" if result.returncode == 0 else "inactive",
            "output": result.stdout.strip()[:500]
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"status": "error", "error": str(e)}


def check_redirector_health(redirector_ip: str, port: int = 443) -> dict:
    """Verify redirector is forwarding traffic correctly."""
    result = {
        "ip": redirector_ip,
        "port": port,
        "port_open": check_port_open(redirector_ip, port),
        "ssl": check_ssl_certificate(redirector_ip, port) if port == 443 else "N/A"
    }
    return result


def generate_infrastructure_report(config: dict) -> str:
    """Generate a health report for the C2 infrastructure."""
    report_lines = [
        "=" * 60,
        f"Sliver C2 Infrastructure Health Report",
        f"Generated: {datetime.now().isoformat()}",
        "=" * 60,
        ""
    ]

    team_server = config.get("team_server", {})
    ts_host = team_server.get("host", "127.0.0.1")
    ts_ports = team_server.get("ports", [443, 8888, 53, 51820])

    report_lines.append("[Team Server]")
    report_lines.append(f"  Host: {ts_host}")
    for port in ts_ports:
        status = "OPEN" if check_port_open(ts_host, port) else "CLOSED"
        report_lines.append(f"  Port {port}: {status}")
    report_lines.append("")

    redirectors = config.get("redirectors", [])
    report_lines.append("[Redirectors]")
    for redir in redirectors:
        redir_ip = redir.get("ip", "")
        redir_port = redir.get("port", 443)
        health = check_redirector_health(redir_ip, redir_port)
        status = "HEALTHY" if health["port_open"] else "DOWN"
        report_lines.append(f"  {redir_ip}:{redir_port} - {status}")
    report_lines.append("")

    dns_domains = config.get("dns_domains", [])
    report_lines.append("[DNS Listeners]")
    for domain in dns_domains:
        dns_check = check_dns_listener(domain)
        report_lines.append(f"  {domain}: {dns_check['status']}")
    report_lines.append("")

    report_lines.append("[SSL Certificates]")
    https_hosts = config.get("https_hosts", [])
    for host in https_hosts:
        cert_info = check_ssl_certificate(host)
        report_lines.append(f"  {host}: {cert_info['status']}")
        if cert_info["status"] == "valid":
            report_lines.append(f"    Expiry: {cert_info.get('expiry', 'N/A')}")
    report_lines.append("")

    report_lines.append("=" * 60)
    return "\n".join(report_lines)


def parse_sliver_config(config_path: str) -> dict:
    """Parse a Sliver infrastructure configuration file."""
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading config: {e}")
        return {}


def main():
    """Main entry point for infrastructure health check."""
    config_path = sys.argv[1] if len(sys.argv) > 1 else "c2_infrastructure.json"

    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}")
        print("Creating example configuration...")
        example_config = {
            "team_server": {
                "host": "10.0.0.1",
                "ports": [443, 8888, 53, 51820]
            },
            "redirectors": [
                {"ip": "203.0.113.10", "port": 443},
                {"ip": "203.0.113.20", "port": 443}
            ],
            "dns_domains": ["c2dns.example.com"],
            "https_hosts": ["c2.example.com"]
        }
        with open(config_path, "w") as f:
            json.dump(example_config, f, indent=2)
        print(f"Example config written to {config_path}")
        print("Edit the configuration and re-run the script.")
        return

    config = parse_sliver_config(config_path)
    if not config:
        print("Failed to parse configuration. Exiting.")
        return

    report = generate_infrastructure_report(config)
    print(report)

    report_file = f"c2_health_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(report)
    print(f"Report saved to: {report_file}")


if __name__ == "__main__":
    main()
