#!/usr/bin/env python3
"""SCADA HMI Security Assessment agent — analyzes SCADA HMI configurations
for security weaknesses including default credentials, unencrypted protocols,
and missing access controls."""

import argparse
import json
import socket
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import pyshark
except ImportError:
    pyshark = None

SCADA_PORTS = {
    102: "S7comm (Siemens)",
    502: "Modbus TCP",
    2222: "EtherNet/IP",
    4840: "OPC UA",
    20000: "DNP3",
    47808: "BACnet",
    1089: "FF HSE",
    18245: "GE SRTP",
}

DEFAULT_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("operator", "operator"), ("engineer", "engineer"),
    ("guest", "guest"), ("user", "user"),
    ("Administrator", ""), ("root", "root"),
]

INSECURE_PROTOCOLS = {"modbus", "s7comm", "dnp3", "bacnet", "enip"}


def scan_open_ports(target: str, ports: list[int] = None, timeout: float = 2.0) -> list[dict]:
    """Check for open SCADA-specific ports on target."""
    if ports is None:
        ports = list(SCADA_PORTS.keys())
    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                results.append({
                    "port": port,
                    "protocol": SCADA_PORTS.get(port, "unknown"),
                    "status": "open",
                    "risk": "high" if port in (502, 102, 20000) else "medium",
                })
            sock.close()
        except socket.error:
            pass
    return results


def check_default_credentials_http(target: str, port: int = 80) -> list[dict]:
    """Check for default credentials on HMI web interface."""
    import urllib.request
    import base64
    findings = []
    for user, pwd in DEFAULT_CREDENTIALS:
        try:
            url = f"http://{target}:{port}/"
            creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                findings.append({
                    "type": "default_credential",
                    "severity": "critical",
                    "username": user,
                    "port": port,
                    "detail": f"Default credential {user}:{pwd} accepted on port {port}",
                })
        except Exception:
            continue
    return findings


def analyze_pcap_protocols(pcap_path: str) -> list[dict]:
    """Analyze PCAP for insecure SCADA protocols."""
    if pyshark is None:
        return [{"error": "pyshark not installed"}]
    findings = []
    protocol_counts = Counter()
    try:
        cap = pyshark.FileCapture(pcap_path)
        for pkt in cap:
            for layer in pkt.layers:
                lname = layer.layer_name.lower()
                if lname in INSECURE_PROTOCOLS:
                    protocol_counts[lname] += 1
        cap.close()
    except Exception as e:
        return [{"error": str(e)}]

    for proto, count in protocol_counts.items():
        findings.append({
            "type": "insecure_protocol",
            "severity": "high",
            "protocol": proto,
            "packet_count": count,
            "detail": f"{proto} traffic detected ({count} packets) — no encryption or authentication",
        })
    return findings


def check_hmi_configuration(config_path: str) -> list[dict]:
    """Analyze HMI configuration file for security weaknesses."""
    findings = []
    try:
        config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, FileNotFoundError) as e:
        return [{"error": str(e)}]

    if not config.get("authentication", {}).get("enabled", True):
        findings.append({"type": "auth_disabled", "severity": "critical",
                         "detail": "Authentication is disabled on HMI"})
    if config.get("session_timeout", 0) == 0:
        findings.append({"type": "no_session_timeout", "severity": "high",
                         "detail": "No session timeout configured"})
    if not config.get("encryption", {}).get("tls_enabled", True):
        findings.append({"type": "no_tls", "severity": "high",
                         "detail": "TLS not enabled for HMI communications"})
    if config.get("remote_access", {}).get("enabled", False):
        if not config.get("remote_access", {}).get("vpn_required", True):
            findings.append({"type": "remote_no_vpn", "severity": "critical",
                             "detail": "Remote access enabled without VPN requirement"})
    roles = config.get("roles", [])
    if len(roles) <= 1:
        findings.append({"type": "no_rbac", "severity": "high",
                         "detail": "No role-based access control — single role or no roles defined"})
    return findings


def generate_report(target: str, pcap_path: str = None,
                    config_path: str = None, scan_ports: bool = True) -> dict:
    """Run all assessments and build consolidated report."""
    findings = []
    if scan_ports:
        open_ports = scan_open_ports(target)
        for p in open_ports:
            findings.append({"type": "open_scada_port", "severity": p["risk"],
                             "detail": f"Port {p['port']} ({p['protocol']}) is open"})
    if pcap_path:
        findings.extend(analyze_pcap_protocols(pcap_path))
    if config_path:
        findings.extend(check_hmi_configuration(config_path))

    severity_counts = Counter(f.get("severity", "info") for f in findings)
    return {
        "report": "scada_hmi_security_assessment",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "total_findings": len(findings),
        "severity_summary": dict(severity_counts),
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="SCADA HMI Security Assessment Agent")
    parser.add_argument("--target", required=True, help="Target HMI IP address")
    parser.add_argument("--pcap", help="PCAP file with SCADA traffic")
    parser.add_argument("--config", help="HMI configuration JSON file")
    parser.add_argument("--no-scan", action="store_true", help="Skip port scanning")
    parser.add_argument("--output", help="Output JSON file path")
    args = parser.parse_args()

    report = generate_report(args.target, args.pcap, args.config, not args.no_scan)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
