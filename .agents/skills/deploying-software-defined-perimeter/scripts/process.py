#!/usr/bin/env python3
"""
Software-Defined Perimeter Deployment Validator

Validates SDP deployment readiness, tests SPA mechanisms,
verifies gateway invisibility, and generates deployment reports.
"""

import json
import socket
import hashlib
import hmac
import struct
import time
import ssl
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


def check_gateway_invisibility(host: str, port_range: tuple = (1, 1024), timeout: float = 0.5) -> dict:
    """Scan gateway ports to verify SDP invisibility (all ports should appear closed/filtered)."""
    result = {
        "host": host,
        "scanned_range": f"{port_range[0]}-{port_range[1]}",
        "open_ports": [],
        "closed_ports": 0,
        "filtered_ports": 0,
        "invisible": True,
        "timestamp": datetime.now().isoformat(),
    }

    for port in range(port_range[0], port_range[1] + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            conn_result = sock.connect_ex((host, port))
            if conn_result == 0:
                result["open_ports"].append(port)
                result["invisible"] = False
            else:
                result["filtered_ports"] += 1
            sock.close()
        except socket.timeout:
            result["filtered_ports"] += 1
        except OSError:
            result["closed_ports"] += 1

    return result


def generate_spa_packet(
    source_ip: str,
    destination_service: str,
    shared_key: str,
    timestamp: Optional[float] = None
) -> bytes:
    """Generate a Single Packet Authorization payload (demonstration)."""
    if timestamp is None:
        timestamp = time.time()

    payload = json.dumps({
        "version": 2,
        "source_ip": source_ip,
        "service": destination_service,
        "timestamp": timestamp,
        "nonce": hashlib.sha256(f"{time.time()}{source_ip}".encode()).hexdigest()[:16],
    }).encode()

    mac = hmac.new(shared_key.encode(), payload, hashlib.sha256).digest()
    packet = struct.pack("!I", len(payload)) + payload + mac

    return packet


def validate_spa_packet(packet: bytes, shared_key: str, max_age_seconds: int = 60) -> dict:
    """Validate a received SPA packet."""
    result = {"valid": False, "errors": [], "payload": None}

    try:
        payload_len = struct.unpack("!I", packet[:4])[0]
        payload = packet[4:4 + payload_len]
        received_mac = packet[4 + payload_len:]

        expected_mac = hmac.new(shared_key.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(received_mac, expected_mac):
            result["errors"].append("HMAC verification failed")
            return result

        data = json.loads(payload.decode())
        result["payload"] = data

        age = time.time() - data.get("timestamp", 0)
        if age > max_age_seconds:
            result["errors"].append(f"Packet expired ({age:.0f}s old, max {max_age_seconds}s)")
            return result

        if age < -5:
            result["errors"].append("Packet timestamp is in the future")
            return result

        result["valid"] = True

    except (struct.error, json.JSONDecodeError, KeyError) as e:
        result["errors"].append(f"Packet parse error: {str(e)}")

    return result


def validate_mtls_certificate(host: str, port: int, ca_cert_path: Optional[str] = None) -> dict:
    """Validate mTLS certificate configuration on SDP gateway."""
    result = {
        "host": host,
        "port": port,
        "tls_configured": False,
        "certificate": None,
        "errors": [],
    }

    try:
        context = ssl.create_default_context()
        if ca_cert_path:
            context.load_verify_locations(ca_cert_path)

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["tls_configured"] = True
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial": cert.get("serialNumber"),
                }

                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_remaining = (expiry - datetime.utcnow()).days
                    result["certificate"]["days_remaining"] = days_remaining
                    if days_remaining < 30:
                        result["errors"].append(f"Certificate expires in {days_remaining} days")

    except ssl.SSLError as e:
        result["errors"].append(f"SSL error: {str(e)}")
    except Exception as e:
        result["errors"].append(f"Connection error: {str(e)}")

    return result


def validate_sdp_config(config: dict) -> dict:
    """Validate SDP deployment configuration."""
    findings = []
    score = 100

    controller = config.get("controller", {})
    if not controller.get("ha_enabled"):
        findings.append({"severity": "high", "finding": "Controller HA not enabled"})
        score -= 15

    if not controller.get("idp_integration"):
        findings.append({"severity": "critical", "finding": "No IdP integration configured"})
        score -= 25

    if not controller.get("audit_logging"):
        findings.append({"severity": "high", "finding": "Audit logging not enabled on controller"})
        score -= 10

    gateways = config.get("gateways", [])
    if not gateways:
        findings.append({"severity": "critical", "finding": "No SDP gateways deployed"})
        score -= 25
    for gw in gateways:
        if not gw.get("default_drop"):
            findings.append({"severity": "critical", "finding": f"Gateway {gw.get('name')}: default-drop not enabled"})
            score -= 20
        if not gw.get("spa_enabled"):
            findings.append({"severity": "critical", "finding": f"Gateway {gw.get('name')}: SPA not enabled"})
            score -= 15
        if not gw.get("mtls_enabled"):
            findings.append({"severity": "high", "finding": f"Gateway {gw.get('name')}: mTLS not configured"})
            score -= 10

    pki = config.get("pki", {})
    cert_lifetime_hours = pki.get("client_cert_lifetime_hours", 8760)
    if cert_lifetime_hours > 72:
        findings.append({
            "severity": "warning",
            "finding": f"Client certificate lifetime is {cert_lifetime_hours}h (recommend <=72h for zero trust)"
        })
        score -= 5

    if not pki.get("ocsp_enabled") and not pki.get("crl_enabled"):
        findings.append({"severity": "high", "finding": "No certificate revocation checking enabled"})
        score -= 10

    monitoring = config.get("monitoring", {})
    if not monitoring.get("siem_integration"):
        findings.append({"severity": "warning", "finding": "No SIEM integration for SDP events"})
        score -= 5

    return {
        "score": max(score, 0),
        "findings": findings,
        "status": "ready" if score >= 80 else "needs_work" if score >= 50 else "not_ready",
        "timestamp": datetime.now().isoformat(),
    }


def generate_sdp_deployment_report(config: dict) -> dict:
    """Generate comprehensive SDP deployment report."""
    validation = validate_sdp_config(config)

    applications = config.get("applications", [])
    users = config.get("authorized_users", [])

    return {
        "generated": datetime.now().isoformat(),
        "deployment_status": validation["status"],
        "security_score": validation["score"],
        "findings": validation["findings"],
        "summary": {
            "controller_ha": config.get("controller", {}).get("ha_enabled", False),
            "gateways_deployed": len(config.get("gateways", [])),
            "applications_protected": len(applications),
            "authorized_users": len(users),
            "spa_enabled": all(g.get("spa_enabled") for g in config.get("gateways", [])),
            "mtls_enabled": all(g.get("mtls_enabled") for g in config.get("gateways", [])),
        },
        "recommendations": [f["finding"] for f in validation["findings"] if f["severity"] in ("critical", "high")],
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SDP Deployment Validator")
    parser.add_argument("--config", type=str, help="Path to SDP configuration JSON")
    parser.add_argument("--scan", type=str, help="Gateway host to scan for invisibility")
    parser.add_argument("--scan-ports", type=str, default="1-1024", help="Port range to scan")
    parser.add_argument("--check-tls", type=str, help="Host:port to check TLS certificate")
    parser.add_argument("--output", type=str, default="sdp_report.json")
    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            config = json.load(f)
        report = generate_sdp_deployment_report(config)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"SDP Status: {report['deployment_status']} (Score: {report['security_score']})")
        for r in report["recommendations"]:
            print(f"  - {r}")

    elif args.scan:
        start, end = args.scan_ports.split("-")
        result = check_gateway_invisibility(args.scan, (int(start), int(end)))
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        status = "INVISIBLE" if result["invisible"] else "EXPOSED"
        print(f"Gateway {args.scan}: {status}")
        if result["open_ports"]:
            print(f"  Open ports: {result['open_ports']}")

    elif args.check_tls:
        parts = args.check_tls.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443
        result = validate_mtls_certificate(host, port)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"TLS on {host}:{port}: {'configured' if result['tls_configured'] else 'not configured'}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
