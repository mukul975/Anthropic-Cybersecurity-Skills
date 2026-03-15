#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Network Penetration Testing Agent - Automates host discovery, port scanning, and vuln assessment."""

import json
import logging
import argparse
from datetime import datetime

import nmap

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def host_discovery(target_network):
    """Discover live hosts on the network using ARP ping and ICMP."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target_network, arguments="-sn -PE -PA21,22,80,443")
    hosts = []
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            hosts.append({
                "ip": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
            })
    logger.info("Host discovery: %d live hosts on %s", len(hosts), target_network)
    return hosts


def port_scan(target, ports="1-10000", scan_type="-sS"):
    """Perform TCP SYN scan with service version detection."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, ports=ports, arguments=f"{scan_type} -sV -O --script=banner")
    results = []
    for host in scanner.all_hosts():
        host_info = {
            "ip": host,
            "hostname": scanner[host].hostname(),
            "os_match": [],
            "services": [],
        }
        if "osmatch" in scanner[host]:
            host_info["os_match"] = [
                {"name": m["name"], "accuracy": m["accuracy"]}
                for m in scanner[host]["osmatch"][:3]
            ]
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                svc = scanner[host][proto][port]
                host_info["services"].append({
                    "port": port,
                    "protocol": proto,
                    "state": svc["state"],
                    "service": svc.get("name", ""),
                    "version": svc.get("version", ""),
                    "product": svc.get("product", ""),
                    "extrainfo": svc.get("extrainfo", ""),
                })
        results.append(host_info)
    logger.info("Port scan: %d hosts, %d total services",
                len(results), sum(len(h["services"]) for h in results))
    return results


def vulnerability_scan(target, ports="1-1024"):
    """Run Nmap vulnerability scripts against target."""
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=target, ports=ports,
        arguments="-sV --script=vulners,vulscan/vulscan.nse --script-args vulscan/vulscan.db=cve.csv"
    )
    vulns = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                svc = scanner[host][proto][port]
                scripts = svc.get("script", {})
                if scripts:
                    vulns.append({
                        "host": host,
                        "port": port,
                        "service": svc.get("name", ""),
                        "version": svc.get("version", ""),
                        "scripts": scripts,
                    })
    logger.info("Vulnerability scan: %d services with script output", len(vulns))
    return vulns


def smb_enumeration(target):
    """Enumerate SMB shares and users via Nmap scripts."""
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=target, ports="139,445",
        arguments="--script=smb-enum-shares,smb-enum-users,smb-os-discovery"
    )
    results = {}
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in [139, 445]:
                if port in scanner[host][proto]:
                    scripts = scanner[host][proto][port].get("script", {})
                    results[host] = scripts
    logger.info("SMB enumeration: %d hosts responded", len(results))
    return results


def ssl_audit(target, port=443):
    """Audit SSL/TLS configuration using Nmap ssl-enum-ciphers."""
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=target, ports=str(port),
        arguments="--script=ssl-enum-ciphers,ssl-cert"
    )
    results = {}
    for host in scanner.all_hosts():
        if port in scanner[host].get("tcp", {}):
            results[host] = scanner[host]["tcp"][port].get("script", {})
    return results


def dns_enumeration(domain):
    """Perform DNS enumeration via Nmap dns-brute."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts=domain, arguments="--script=dns-brute")
    return scanner.get_nmap_last_output()


def classify_findings(scan_results, vuln_results):
    """Classify and prioritize all findings by severity."""
    findings = []
    for vuln in vuln_results:
        severity = "Medium"
        scripts = vuln.get("scripts", {})
        script_text = json.dumps(scripts).lower()
        if "critical" in script_text or "cve-2" in script_text:
            severity = "Critical"
        elif "high" in script_text:
            severity = "High"
        findings.append({
            "host": vuln["host"],
            "port": vuln["port"],
            "service": vuln["service"],
            "severity": severity,
            "details": scripts,
        })
    findings.sort(key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4))
    return findings


def generate_report(hosts, scan_results, vuln_findings, smb_results):
    """Generate network penetration test report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "scope": f"{len(hosts)} live hosts discovered",
        "hosts": hosts,
        "services": scan_results,
        "vulnerabilities": vuln_findings,
        "smb_enumeration": smb_results,
        "summary": {
            "critical": len([f for f in vuln_findings if f["severity"] == "Critical"]),
            "high": len([f for f in vuln_findings if f["severity"] == "High"]),
            "medium": len([f for f in vuln_findings if f["severity"] == "Medium"]),
        },
    }
    print(f"NETWORK PENTEST REPORT: {len(hosts)} hosts, {len(vuln_findings)} vulnerabilities")
    return report


def main():
    parser = argparse.ArgumentParser(description="Network Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target host/network CIDR")
    parser.add_argument("--ports", default="1-10000", help="Port range to scan")
    parser.add_argument("--discovery-only", action="store_true", help="Only perform host discovery")
    parser.add_argument("--output", default="network_pentest_report.json")
    args = parser.parse_args()

    hosts = host_discovery(args.target)

    if args.discovery_only:
        with open(args.output, "w") as f:
            json.dump({"hosts": hosts}, f, indent=2)
        return

    scan_results = []
    vuln_results = []
    smb_results = {}

    for host in hosts:
        ip = host["ip"]
        scan = port_scan(ip, args.ports)
        scan_results.extend(scan)
        vulns = vulnerability_scan(ip)
        vuln_results.extend(vulns)
        smb = smb_enumeration(ip)
        smb_results.update(smb)

    findings = classify_findings(scan_results, vuln_results)
    report = generate_report(hosts, scan_results, findings, smb_results)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
