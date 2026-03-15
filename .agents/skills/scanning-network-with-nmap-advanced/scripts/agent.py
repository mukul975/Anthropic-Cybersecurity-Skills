#!/usr/bin/env python3
"""Automated network scanning agent using python-nmap for authorized assessments."""

import nmap
import json
import csv
import sys
import os
import argparse
from datetime import datetime


def discover_hosts(scanner, target, timing="T4"):
    """Run host discovery using multiple probe techniques."""
    print(f"[*] Discovering live hosts on {target}...")
    scanner.scan(hosts=target, arguments=f"-sn -PE -PP -PS22,80,443,445,3389 -{timing}")
    hosts = []
    for host in scanner.all_hosts():
        state = scanner[host].state()
        if state == "up":
            hosts.append(host)
            hostnames = [h["name"] for h in scanner[host].hostnames() if h["name"]]
            hostname_str = ", ".join(hostnames) if hostnames else "N/A"
            print(f"  [+] {host} ({hostname_str}) - {state}")
    print(f"[*] Discovered {len(hosts)} live hosts")
    return hosts


def scan_ports(scanner, hosts, ports="1-1024", timing="T4"):
    """Run SYN scan on discovered hosts for specified ports."""
    results = {}
    target_str = " ".join(hosts) if isinstance(hosts, list) else hosts
    print(f"\n[*] Scanning ports {ports} on {len(hosts) if isinstance(hosts, list) else 1} host(s)...")
    scanner.scan(hosts=target_str, ports=ports, arguments=f"-sS -{timing} --min-rate 3000 --max-retries 2")
    for host in scanner.all_hosts():
        results[host] = []
        for proto in scanner[host].all_protocols():
            ports_list = sorted(scanner[host][proto].keys())
            for port in ports_list:
                port_info = scanner[host][proto][port]
                if port_info["state"] == "open":
                    results[host].append({
                        "port": port,
                        "protocol": proto,
                        "state": port_info["state"],
                        "service": port_info.get("name", "unknown"),
                        "version": port_info.get("version", ""),
                        "product": port_info.get("product", ""),
                    })
                    print(f"  [+] {host}:{port}/{proto} - {port_info.get('name', '?')} "
                          f"{port_info.get('product', '')} {port_info.get('version', '')}")
    return results


def service_version_scan(scanner, host, open_ports):
    """Run aggressive service version detection on open ports."""
    port_str = ",".join(str(p["port"]) for p in open_ports)
    print(f"\n[*] Running service version detection on {host} ports {port_str}...")
    scanner.scan(hosts=host, ports=port_str, arguments="-sV --version-intensity 5 -sC -O --osscan-guess")
    info = {"os_matches": [], "services": []}
    if host in scanner.all_hosts():
        if "osmatch" in scanner[host]:
            for os_match in scanner[host]["osmatch"][:3]:
                info["os_matches"].append({"name": os_match["name"], "accuracy": os_match["accuracy"]})
        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                svc = scanner[host][proto][port]
                info["services"].append({
                    "port": port, "protocol": proto, "service": svc.get("name", ""),
                    "product": svc.get("product", ""), "version": svc.get("version", ""),
                    "extrainfo": svc.get("extrainfo", ""),
                })
    return info


def vuln_scan(scanner, host, open_ports):
    """Run NSE vulnerability scripts against open ports."""
    port_str = ",".join(str(p["port"]) for p in open_ports)
    print(f"\n[*] Running vulnerability scripts on {host}...")
    scanner.scan(hosts=host, ports=port_str, arguments="--script vuln")
    vulns = []
    if host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                svc = scanner[host][proto][port]
                if "script" in svc:
                    for script_name, output in svc["script"].items():
                        if "VULNERABLE" in str(output).upper() or "CVE-" in str(output).upper():
                            vulns.append({"host": host, "port": port, "script": script_name, "output": output[:500]})
                            print(f"  [!] VULN {host}:{port} - {script_name}")
    return vulns


def generate_report(discovery, port_results, version_info, vulnerabilities, output_dir):
    """Generate JSON and CSV reports from scan results."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "scan_date": datetime.now().isoformat(),
        "hosts_discovered": len(discovery),
        "hosts": discovery,
        "port_scan_results": port_results,
        "version_info": version_info,
        "vulnerabilities": vulnerabilities,
    }
    json_path = os.path.join(output_dir, f"scan_report_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] JSON report saved to {json_path}")

    csv_path = os.path.join(output_dir, f"open_ports_{timestamp}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Protocol", "Service", "Product", "Version"])
        for host, ports in port_results.items():
            for p in ports:
                writer.writerow([host, p["port"], p["protocol"], p["service"], p["product"], p["version"]])
    print(f"[*] CSV report saved to {csv_path}")
    return json_path, csv_path


def main():
    parser = argparse.ArgumentParser(description="Nmap Advanced Network Scanner Agent")
    parser.add_argument("target", help="Target IP, CIDR range, or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (default: 1-1024)")
    parser.add_argument("-t", "--timing", default="T4", choices=["T0", "T1", "T2", "T3", "T4", "T5"])
    parser.add_argument("--vuln", action="store_true", help="Run NSE vulnerability scripts")
    parser.add_argument("--version-scan", action="store_true", help="Run service version detection")
    parser.add_argument("-o", "--output", default=".", help="Output directory for reports")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    scanner = nmap.PortScanner()
    print(f"[*] Nmap version: {scanner.nmap_version()}")
    print(f"[*] Target: {args.target} | Ports: {args.ports} | Timing: {args.timing}")

    hosts = discover_hosts(scanner, args.target, args.timing)
    if not hosts:
        print("[-] No live hosts found. Exiting.")
        sys.exit(0)

    port_results = scan_ports(scanner, hosts, args.ports, args.timing)
    version_info, vulnerabilities = {}, []

    for host, open_ports in port_results.items():
        if not open_ports:
            continue
        if args.version_scan:
            version_info[host] = service_version_scan(scanner, host, open_ports)
        if args.vuln:
            vulnerabilities.extend(vuln_scan(scanner, host, open_ports))

    generate_report(hosts, port_results, version_info, vulnerabilities, args.output)
    total_open = sum(len(p) for p in port_results.values())
    print(f"\n[*] Scan complete: {len(hosts)} hosts, {total_open} open ports, {len(vulnerabilities)} vulns found")


if __name__ == "__main__":
    main()
