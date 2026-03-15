#!/usr/bin/env python3
"""Internal network penetration testing agent using nmap and impacket."""

import json
import sys
import argparse
import subprocess
import socket
from datetime import datetime


def run_nmap_scan(target, scan_type="quick"):
    """Run nmap network discovery and port scanning."""
    scan_args = {
        "quick": ["-sV", "-sC", "--top-ports", "100", "-T4"],
        "full": ["-sV", "-sC", "-p-", "-T3"],
        "stealth": ["-sS", "-Pn", "-T2", "--top-ports", "1000"],
    }
    args = scan_args.get(scan_type, scan_args["quick"])
    cmd = ["nmap"] + args + ["-oX", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"status": "completed", "output": result.stdout[:2000]}
    except FileNotFoundError:
        return {"status": "error", "message": "nmap not installed"}
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}


def check_smb_signing(target):
    """Check if SMB signing is required on target hosts."""
    cmd = ["nmap", "--script", "smb2-security-mode", "-p", "445", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        signing_disabled = "not required" in result.stdout.lower()
        return {
            "target": target,
            "smb_signing_required": not signing_disabled,
            "vulnerable_to_relay": signing_disabled,
            "severity": "HIGH" if signing_disabled else "INFO",
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"target": target, "error": "nmap scan failed"}


def check_llmnr_nbns(interface="eth0"):
    """Check for LLMNR/NBT-NS poisoning opportunities."""
    return {
        "check": "LLMNR/NBT-NS",
        "tool": "Responder",
        "command": f"responder -I {interface} -A",
        "risk": "Cleartext credential capture via name resolution poisoning",
        "severity": "HIGH",
        "mitigation": "Disable LLMNR via GPO, disable NBT-NS in network adapter settings",
    }


def enumerate_ad_info(dc_ip, domain, username, password):
    """Enumerate Active Directory information via LDAP."""
    try:
        import ldap3
        server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=f"{domain}\\{username}",
                                password=password, authentication=ldap3.NTLM, auto_bind=True)
        base_dn = ",".join([f"DC={p}" for p in domain.split(".")])
        conn.search(base_dn, "(objectClass=computer)", attributes=["cn", "operatingSystem"])
        computers = [{"name": str(e.cn), "os": str(e.operatingSystem)} for e in conn.entries]
        conn.search(base_dn, "(&(objectClass=user)(adminCount=1))",
                     attributes=["sAMAccountName"])
        admins = [str(e.sAMAccountName) for e in conn.entries]
        conn.unbind()
        return {"computers": computers[:20], "admin_accounts": admins, "total_hosts": len(computers)}
    except Exception as e:
        return {"error": str(e)}


def check_common_vulns(target):
    """Check for common internal network vulnerabilities."""
    checks = []
    for port, service in [(21, "FTP"), (23, "Telnet"), (80, "HTTP"), (3389, "RDP"),
                          (5900, "VNC"), (1433, "MSSQL"), (3306, "MySQL")]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect((target, port))
            checks.append({"port": port, "service": service, "status": "open"})
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            sock.close()
    return checks


def run_pentest(target, dc_ip=None, domain=None, username=None, password=None):
    """Execute internal network penetration test."""
    print(f"\n{'='*60}")
    print(f"  INTERNAL NETWORK PENETRATION TEST")
    print(f"  Target: {target}")
    print(f"  Generated: {datetime.utcnow().isoformat()} UTC")
    print(f"{'='*60}\n")

    ports = check_common_vulns(target)
    print(f"--- OPEN PORTS ({len(ports)}) ---")
    for p in ports:
        print(f"  Port {p['port']}/{p['service']}: {p['status']}")

    smb = check_smb_signing(target)
    print(f"\n--- SMB SIGNING ---")
    print(f"  Signing required: {smb.get('smb_signing_required', 'N/A')}")
    print(f"  Relay vulnerable: {smb.get('vulnerable_to_relay', 'N/A')}")

    llmnr = check_llmnr_nbns()
    print(f"\n--- LLMNR/NBT-NS ---")
    print(f"  Risk: {llmnr['risk']}")
    print(f"  Severity: {llmnr['severity']}")

    ad_info = {}
    if dc_ip and domain and username and password:
        ad_info = enumerate_ad_info(dc_ip, domain, username, password)
        print(f"\n--- AD ENUMERATION ---")
        print(f"  Total hosts: {ad_info.get('total_hosts', 0)}")
        print(f"  Admin accounts: {ad_info.get('admin_accounts', [])}")

    return {"ports": ports, "smb": smb, "llmnr": llmnr, "ad": ad_info}


def main():
    parser = argparse.ArgumentParser(description="Internal Network Pentest Agent")
    parser.add_argument("--target", required=True, help="Target IP or CIDR range")
    parser.add_argument("--dc-ip", help="Domain controller IP for AD enumeration")
    parser.add_argument("--domain", help="AD domain name")
    parser.add_argument("--username", help="AD username")
    parser.add_argument("--password", help="AD password")
    parser.add_argument("--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = run_pentest(args.target, args.dc_ip, args.domain, args.username, args.password)
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
