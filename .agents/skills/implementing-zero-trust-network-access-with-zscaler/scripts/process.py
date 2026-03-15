#!/usr/bin/env python3
"""
ZTNA Deployment Readiness Assessment and ZPA Configuration Validator

This script performs pre-deployment checks for Zscaler Private Access (ZPA)
implementation, validates existing configurations, and generates deployment
readiness reports.
"""

import json
import csv
import socket
import ssl
import subprocess
import sys
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Optional


def check_dns_resolution(fqdn: str) -> dict:
    """Validate DNS resolution for application FQDNs."""
    result = {"fqdn": fqdn, "resolved": False, "addresses": [], "error": None}
    try:
        addresses = socket.getaddrinfo(fqdn, None)
        result["resolved"] = True
        result["addresses"] = list(set(addr[4][0] for addr in addresses))
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def check_port_connectivity(host: str, port: int, timeout: int = 5) -> dict:
    """Test TCP connectivity to application endpoints."""
    result = {
        "host": host,
        "port": port,
        "reachable": False,
        "latency_ms": None,
        "error": None,
    }
    start = datetime.now()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        elapsed = (datetime.now() - start).total_seconds() * 1000
        result["reachable"] = True
        result["latency_ms"] = round(elapsed, 2)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)
    return result


def check_tls_certificate(host: str, port: int = 443) -> dict:
    """Validate TLS certificate for HTTPS applications."""
    result = {
        "host": host,
        "port": port,
        "valid": False,
        "issuer": None,
        "subject": None,
        "expiry": None,
        "days_remaining": None,
        "error": None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                result["subject"] = dict(x[0] for x in cert.get("subject", []))
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    result["expiry"] = expiry.isoformat()
                    result["days_remaining"] = (expiry - datetime.utcnow()).days
    except Exception as e:
        result["error"] = str(e)
    return result


def validate_app_segment_config(config: dict) -> list:
    """Validate application segment configuration against best practices."""
    issues = []

    if not config.get("name"):
        issues.append({"severity": "critical", "message": "Application segment name is missing"})

    domains = config.get("domains", [])
    ips = config.get("ip_addresses", [])
    if not domains and not ips:
        issues.append({
            "severity": "critical",
            "message": "No domains or IP addresses defined for segment"
        })

    ports = config.get("tcp_ports", []) + config.get("udp_ports", [])
    if not ports:
        issues.append({"severity": "critical", "message": "No ports defined for segment"})

    for port_range in config.get("tcp_ports", []):
        if "-" in str(port_range):
            start, end = port_range.split("-")
            if int(end) - int(start) > 100:
                issues.append({
                    "severity": "warning",
                    "message": f"Wide port range {port_range} violates least-privilege. Consider narrowing."
                })

    if not config.get("server_group"):
        issues.append({
            "severity": "warning",
            "message": "No server group assigned. High availability not configured."
        })

    for ip in ips:
        try:
            network = ipaddress.ip_network(ip, strict=False)
            if network.prefixlen < 24:
                issues.append({
                    "severity": "warning",
                    "message": f"Broad IP range {ip} (/{network.prefixlen}). Consider narrowing to specific hosts."
                })
        except ValueError:
            pass

    if config.get("bypass_type") == "always":
        issues.append({
            "severity": "critical",
            "message": "Bypass is set to 'always'. Traffic will not be inspected."
        })

    return issues


def validate_access_policy(policy: dict) -> list:
    """Validate access policy configuration."""
    issues = []

    if not policy.get("name"):
        issues.append({"severity": "critical", "message": "Policy name is missing"})

    if not policy.get("conditions"):
        issues.append({
            "severity": "critical",
            "message": "No conditions defined. Policy grants unrestricted access."
        })

    conditions = policy.get("conditions", {})
    if not conditions.get("user_groups") and not conditions.get("users"):
        issues.append({
            "severity": "warning",
            "message": "No user or group conditions. Consider restricting by group."
        })

    if not conditions.get("posture_profiles"):
        issues.append({
            "severity": "warning",
            "message": "No device posture profile attached. Unmanaged devices may access."
        })

    if policy.get("action") == "allow" and not conditions.get("saml_attributes"):
        issues.append({
            "severity": "info",
            "message": "Consider adding SAML attribute conditions for finer-grained access."
        })

    app_segments = policy.get("app_segments", [])
    if len(app_segments) > 20:
        issues.append({
            "severity": "warning",
            "message": f"Policy covers {len(app_segments)} segments. Consider splitting for manageability."
        })

    return issues


def generate_app_inventory_csv(apps: list, output_path: str) -> str:
    """Generate a CSV inventory of applications for ZPA migration planning."""
    fieldnames = [
        "app_name", "fqdn", "ip_address", "port", "protocol",
        "user_groups", "criticality", "current_access_method",
        "migration_wave", "zpa_segment_name", "status"
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for app in apps:
            writer.writerow({field: app.get(field, "") for field in fieldnames})
    return output_path


def assess_deployment_readiness(config: dict) -> dict:
    """Perform comprehensive deployment readiness assessment."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "overall_status": "ready",
        "checks": [],
        "summary": {"critical": 0, "warning": 0, "info": 0, "passed": 0},
    }

    # Check IdP configuration
    idp = config.get("identity_provider", {})
    if idp.get("type") in ["saml", "oidc"]:
        report["checks"].append({
            "category": "Identity Provider",
            "check": "IdP type configured",
            "status": "passed",
            "details": f"Type: {idp['type']}"
        })
        report["summary"]["passed"] += 1
    else:
        report["checks"].append({
            "category": "Identity Provider",
            "check": "IdP type configured",
            "status": "critical",
            "details": "No IdP integration configured"
        })
        report["summary"]["critical"] += 1

    if idp.get("scim_enabled"):
        report["checks"].append({
            "category": "Identity Provider",
            "check": "SCIM provisioning enabled",
            "status": "passed",
            "details": "Automated user/group sync active"
        })
        report["summary"]["passed"] += 1
    else:
        report["checks"].append({
            "category": "Identity Provider",
            "check": "SCIM provisioning enabled",
            "status": "warning",
            "details": "Manual user management required without SCIM"
        })
        report["summary"]["warning"] += 1

    # Check App Connectors
    connectors = config.get("app_connectors", [])
    if len(connectors) >= 2:
        report["checks"].append({
            "category": "App Connectors",
            "check": "High availability",
            "status": "passed",
            "details": f"{len(connectors)} connectors deployed"
        })
        report["summary"]["passed"] += 1
    elif len(connectors) == 1:
        report["checks"].append({
            "category": "App Connectors",
            "check": "High availability",
            "status": "warning",
            "details": "Single connector. Deploy at least 2 for HA."
        })
        report["summary"]["warning"] += 1
    else:
        report["checks"].append({
            "category": "App Connectors",
            "check": "High availability",
            "status": "critical",
            "details": "No App Connectors configured"
        })
        report["summary"]["critical"] += 1

    # Check application segments
    segments = config.get("app_segments", [])
    for seg in segments:
        seg_issues = validate_app_segment_config(seg)
        for issue in seg_issues:
            report["checks"].append({
                "category": f"App Segment: {seg.get('name', 'unknown')}",
                "check": issue["message"],
                "status": issue["severity"],
                "details": ""
            })
            report["summary"][issue["severity"]] += 1
        if not seg_issues:
            report["summary"]["passed"] += 1

    # Check access policies
    policies = config.get("access_policies", [])
    if not policies:
        report["checks"].append({
            "category": "Access Policies",
            "check": "Policies defined",
            "status": "critical",
            "details": "No access policies configured"
        })
        report["summary"]["critical"] += 1
    for pol in policies:
        pol_issues = validate_access_policy(pol)
        for issue in pol_issues:
            report["checks"].append({
                "category": f"Policy: {pol.get('name', 'unknown')}",
                "check": issue["message"],
                "status": issue["severity"],
                "details": ""
            })
            report["summary"][issue["severity"]] += 1
        if not pol_issues:
            report["summary"]["passed"] += 1

    # Check SIEM integration
    siem = config.get("siem_integration", {})
    if siem.get("enabled"):
        report["checks"].append({
            "category": "Monitoring",
            "check": "SIEM integration",
            "status": "passed",
            "details": f"Streaming to {siem.get('type', 'unknown')}"
        })
        report["summary"]["passed"] += 1
    else:
        report["checks"].append({
            "category": "Monitoring",
            "check": "SIEM integration",
            "status": "warning",
            "details": "No SIEM integration. Access events not centrally monitored."
        })
        report["summary"]["warning"] += 1

    if report["summary"]["critical"] > 0:
        report["overall_status"] = "not_ready"
    elif report["summary"]["warning"] > 3:
        report["overall_status"] = "ready_with_warnings"

    return report


def connectivity_scan(targets: list) -> list:
    """Scan application endpoints for connectivity from App Connector perspective."""
    results = []
    for target in targets:
        host = target.get("host", "")
        ports = target.get("ports", [])

        dns_result = check_dns_resolution(host) if not host.replace(".", "").isdigit() else None

        for port in ports:
            conn_result = check_port_connectivity(host, port)
            tls_result = None
            if port == 443:
                tls_result = check_tls_certificate(host, port)

            results.append({
                "host": host,
                "port": port,
                "dns": dns_result,
                "connectivity": conn_result,
                "tls": tls_result,
            })
    return results


def generate_migration_plan(apps: list) -> dict:
    """Generate a phased VPN-to-ZTNA migration plan."""
    waves = {
        "wave_1": {"name": "Low-risk Web Apps", "apps": [], "duration_weeks": 2},
        "wave_2": {"name": "Business-critical Web Apps", "apps": [], "duration_weeks": 3},
        "wave_3": {"name": "Non-web TCP/UDP Apps", "apps": [], "duration_weeks": 3},
        "wave_4": {"name": "Legacy Applications", "apps": [], "duration_weeks": 4},
    }

    for app in apps:
        criticality = app.get("criticality", "medium").lower()
        protocol = app.get("protocol", "https").lower()
        legacy = app.get("is_legacy", False)

        if legacy:
            waves["wave_4"]["apps"].append(app)
        elif protocol not in ["http", "https"]:
            waves["wave_3"]["apps"].append(app)
        elif criticality in ["high", "critical"]:
            waves["wave_2"]["apps"].append(app)
        else:
            waves["wave_1"]["apps"].append(app)

    total_weeks = sum(w["duration_weeks"] for w in waves.values())
    return {
        "total_duration_weeks": total_weeks,
        "waves": waves,
        "generated": datetime.now().isoformat(),
    }


def main():
    """Run the ZTNA deployment readiness assessment."""
    import argparse

    parser = argparse.ArgumentParser(
        description="ZPA Deployment Readiness Assessment Tool"
    )
    parser.add_argument(
        "--config", type=str, help="Path to ZPA configuration JSON file"
    )
    parser.add_argument(
        "--scan", type=str, help="Path to targets JSON for connectivity scan"
    )
    parser.add_argument(
        "--inventory", type=str, help="Path to app inventory JSON for CSV generation"
    )
    parser.add_argument(
        "--migrate", type=str, help="Path to app list JSON for migration planning"
    )
    parser.add_argument(
        "--output", type=str, default="report.json", help="Output file path"
    )
    args = parser.parse_args()

    if args.config:
        with open(args.config) as f:
            config = json.load(f)
        report = assess_deployment_readiness(config)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Readiness report: {report['overall_status']}")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  Warnings: {report['summary']['warning']}")
        print(f"  Passed:   {report['summary']['passed']}")
        print(f"Report saved to {args.output}")

    elif args.scan:
        with open(args.scan) as f:
            targets = json.load(f)
        results = connectivity_scan(targets)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        reachable = sum(1 for r in results if r["connectivity"]["reachable"])
        print(f"Scan complete: {reachable}/{len(results)} endpoints reachable")
        print(f"Results saved to {args.output}")

    elif args.inventory:
        with open(args.inventory) as f:
            apps = json.load(f)
        csv_path = args.output.replace(".json", ".csv")
        generate_app_inventory_csv(apps, csv_path)
        print(f"Inventory CSV saved to {csv_path}")

    elif args.migrate:
        with open(args.migrate) as f:
            apps = json.load(f)
        plan = generate_migration_plan(apps)
        with open(args.output, "w") as f:
            json.dump(plan, f, indent=2)
        for wave_id, wave in plan["waves"].items():
            print(f"  {wave_id}: {wave['name']} - {len(wave['apps'])} apps ({wave['duration_weeks']} weeks)")
        print(f"Migration plan saved to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
