#!/usr/bin/env python3
"""Historian server attack detection agent for ICS/SCADA environments."""

import json
import sys
import argparse
import socket
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install: pip install requests")
    sys.exit(1)


HISTORIAN_PORTS = {
    5450: "OSIsoft PI AF",
    5457: "OSIsoft PI Data Archive",
    5459: "OSIsoft PI Web API",
    1433: "SQL Server (Wonderware/FactoryTalk)",
    3306: "MySQL (Ignition)",
    8088: "Ignition Gateway",
    443: "HTTPS (PI Web API / Ignition)",
}


def scan_historian_ports(host):
    """Scan for exposed historian service ports."""
    results = []
    for port, service in HISTORIAN_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            status = sock.connect_ex((host, port)) == 0
            sock.close()
            result = {"host": host, "port": port, "service": service, "open": status}
            if status:
                result["finding"] = f"Historian port {port} ({service}) accessible"
                result["severity"] = "HIGH"
            results.append(result)
        except socket.error:
            pass
    return results


def check_pi_web_api(host, username=None, password=None):
    """Check OSIsoft PI Web API for authentication and configuration issues."""
    base = f"https://{host}/piwebapi"
    auth = (username, password) if username else None
    results = {"host": host, "checks": []}

    try:
        resp = requests.get(f"{base}/system", auth=auth, verify=False, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            results["product_version"] = data.get("ProductTitle", "")
            results["checks"].append({
                "check": "PI Web API accessible",
                "status": "PASS" if auth else "FAIL",
                "detail": "Anonymous access enabled" if not auth and resp.status_code == 200 else "",
                "severity": "CRITICAL" if not auth else "INFO",
            })
    except requests.exceptions.ConnectionError:
        results["checks"].append({"check": "PI Web API", "status": "UNREACHABLE"})
    except Exception as e:
        results["error"] = str(e)

    try:
        resp = requests.get(f"{base}/points", auth=auth, verify=False,
                            params={"maxCount": 10}, timeout=10)
        if resp.status_code == 200:
            points = resp.json().get("Items", [])
            results["exposed_points"] = len(points)
            results["sample_points"] = [p.get("Name", "") for p in points[:5]]
            if not auth:
                results["checks"].append({
                    "check": "Point data accessible without auth",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                })
    except Exception:
        pass

    return results


def check_ignition_gateway(host, port=8088):
    """Check Inductive Automation Ignition gateway status."""
    results = {"host": host, "port": port}
    try:
        resp = requests.get(f"http://{host}:{port}/StatusPing", timeout=10)
        if resp.status_code == 200:
            results["gateway_accessible"] = True
            results["response"] = resp.text[:200]

        resp2 = requests.get(f"http://{host}:{port}/system/gwinfo", timeout=10)
        if resp2.status_code == 200:
            results["gateway_info_exposed"] = True
            results["finding"] = "Ignition gateway info page accessible"
            results["severity"] = "HIGH"
    except Exception as e:
        results["error"] = str(e)
    return results


def analyze_historian_logs(log_entries):
    """Analyze historian access logs for attack indicators."""
    findings = []
    failed_logins = {}
    bulk_reads = {}

    for entry in log_entries:
        if entry.get("event_type") == "login_failed":
            src = entry.get("src_ip", "")
            failed_logins[src] = failed_logins.get(src, 0) + 1
        if entry.get("event_type") == "data_read" and entry.get("point_count", 0) > 1000:
            src = entry.get("src_ip", "")
            bulk_reads[src] = bulk_reads.get(src, 0) + entry["point_count"]

    for ip, count in failed_logins.items():
        if count > 5:
            findings.append({
                "ip": ip,
                "issue": f"Brute force attempt: {count} failed logins",
                "severity": "HIGH",
            })

    for ip, points in bulk_reads.items():
        if points > 10000:
            findings.append({
                "ip": ip,
                "issue": f"Bulk data exfiltration: {points} points read",
                "severity": "CRITICAL",
            })

    return findings


def run_audit(args):
    """Execute historian server attack detection audit."""
    print(f"\n{'='*60}")
    print(f"  HISTORIAN SERVER ATTACK DETECTION")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    report = {}

    if args.host:
        port_scan = scan_historian_ports(args.host)
        open_ports = [p for p in port_scan if p.get("open")]
        report["port_scan"] = port_scan
        print(f"--- HISTORIAN PORT SCAN ({args.host}) ---")
        for p in open_ports:
            print(f"  [{p.get('severity','INFO')}] Port {p['port']}: {p['service']}")
        if not open_ports:
            print("  No historian ports detected")

    if args.pi_host:
        pi = check_pi_web_api(args.pi_host, args.pi_user, args.pi_pass)
        report["pi_web_api"] = pi
        print(f"\n--- PI WEB API CHECK ---")
        for c in pi.get("checks", []):
            print(f"  [{c.get('severity','INFO')}] {c['check']}: {c['status']}")

    if args.ignition_host:
        ign = check_ignition_gateway(args.ignition_host, args.ignition_port or 8088)
        report["ignition_gateway"] = ign
        print(f"\n--- IGNITION GATEWAY CHECK ---")
        print(f"  Accessible: {ign.get('gateway_accessible', False)}")
        if ign.get("finding"):
            print(f"  [{ign['severity']}] {ign['finding']}")

    return report


def main():
    parser = argparse.ArgumentParser(description="Historian Attack Detection Agent")
    parser.add_argument("--host", help="Historian server to scan")
    parser.add_argument("--pi-host", help="OSIsoft PI Web API host")
    parser.add_argument("--pi-user", help="PI username")
    parser.add_argument("--pi-pass", help="PI password")
    parser.add_argument("--ignition-host", help="Ignition gateway host")
    parser.add_argument("--ignition-port", type=int, default=8088)
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_audit(args)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
