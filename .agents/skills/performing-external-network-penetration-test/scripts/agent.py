#!/usr/bin/env python3
"""Agent for performing external network penetration test reconnaissance and scanning."""

import json
import argparse
import subprocess
import socket
from datetime import datetime


def tcp_port_scan(host, ports=None):
    """Scan common TCP ports on a target host."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((host, port))
            try:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                banner = ""
            results.append({"port": port, "state": "open", "banner": banner})
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()
    return {"host": host, "open_ports": results, "scanned": len(ports), "timestamp": datetime.utcnow().isoformat()}


def run_nmap_scan(target, scan_type="quick"):
    """Run nmap scan against target."""
    scan_args = {
        "quick": ["-sV", "-T4", "--top-ports", "100"],
        "full": ["-sV", "-sC", "-p-", "-T3"],
        "vuln": ["-sV", "--script", "vuln", "--top-ports", "1000"],
        "udp": ["-sU", "--top-ports", "50", "-T4"],
    }
    args = scan_args.get(scan_type, scan_args["quick"])
    cmd = ["nmap", "-oX", "-"] + args + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        hosts = []
        for host in root.findall(".//host"):
            addr = host.find("address").get("addr", "") if host.find("address") is not None else ""
            ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", ""),
                    "state": state.get("state", "") if state is not None else "",
                    "service": service.get("name", "") if service is not None else "",
                    "version": service.get("product", "") + " " + service.get("version", "") if service is not None else "",
                })
            hosts.append({"ip": addr, "ports": ports})
        return {"target": target, "scan_type": scan_type, "hosts": hosts}
    except FileNotFoundError:
        return {"error": "nmap not installed"}
    except Exception as e:
        return {"error": str(e)}


def dns_enumeration(domain):
    """Enumerate DNS records for a domain."""
    try:
        import dns.resolver
    except ImportError:
        return {"error": "dnspython not installed — pip install dnspython"}
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    subdomains = ["www", "mail", "ftp", "vpn", "remote", "api", "dev", "staging", "admin", "portal"]
    found_subs = []
    for sub in subdomains:
        try:
            answers = dns.resolver.resolve(f"{sub}.{domain}", "A")
            found_subs.append({"subdomain": f"{sub}.{domain}", "ips": [str(r) for r in answers]})
        except Exception:
            pass
    return {"domain": domain, "records": records, "subdomains": found_subs}


def ssl_check(host, port=443):
    """Check SSL/TLS certificate details."""
    import ssl
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()
            return {
                "host": host, "port": port,
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notBefore": cert.get("notBefore"),
                "notAfter": cert.get("notAfter"),
                "version": s.version(),
                "cipher": s.cipher(),
            }
    except Exception as e:
        return {"host": host, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="External Network Penetration Test Agent")
    sub = parser.add_subparsers(dest="command")
    s = sub.add_parser("scan", help="TCP port scan")
    s.add_argument("--host", required=True)
    s.add_argument("--ports", nargs="*", type=int)
    n = sub.add_parser("nmap", help="Run nmap scan")
    n.add_argument("--target", required=True)
    n.add_argument("--type", default="quick", choices=["quick", "full", "vuln", "udp"])
    d = sub.add_parser("dns", help="DNS enumeration")
    d.add_argument("--domain", required=True)
    c = sub.add_parser("ssl", help="SSL certificate check")
    c.add_argument("--host", required=True)
    c.add_argument("--port", type=int, default=443)
    args = parser.parse_args()
    if args.command == "scan":
        result = tcp_port_scan(args.host, args.ports)
    elif args.command == "nmap":
        result = run_nmap_scan(args.target, args.type)
    elif args.command == "dns":
        result = dns_enumeration(args.domain)
    elif args.command == "ssl":
        result = ssl_check(args.host, args.port)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
