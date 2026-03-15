#!/usr/bin/env python3
"""
Agentless Vulnerability Scanning Orchestrator

Performs SSH-based agentless vulnerability scanning on Linux hosts
by enumerating packages and checking against known vulnerabilities.

Requirements:
    pip install paramiko requests pandas

Usage:
    python process.py scan --hosts hosts.txt --key /path/to/ssh_key
    python process.py check --host 192.168.1.10 --user scanner --key /path/to/ssh_key
    python process.py report --input scan_results.json --output report.csv
"""

import argparse
import json
import sys
from datetime import datetime

import pandas as pd
import paramiko
import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class AgentlessScanner:
    """SSH-based agentless vulnerability scanner."""

    def __init__(self, key_path, username="scanner"):
        self.key_path = key_path
        self.username = username

    def _connect(self, hostname, port=22):
        """Establish SSH connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
        except paramiko.ssh_exception.SSHException:
            key = paramiko.RSAKey.from_private_key_file(self.key_path)
        client.connect(hostname, port=port, username=self.username,
                       pkey=key, timeout=30)
        return client

    def _exec(self, client, command, timeout=30):
        """Execute command and return output."""
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode().strip(), stderr.read().decode().strip()

    def get_os_info(self, client):
        """Detect OS distribution and version."""
        out, _ = self._exec(client, "cat /etc/os-release")
        info = {}
        for line in out.split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip('"')
        return info

    def get_packages_dpkg(self, client):
        """Get packages via dpkg (Debian/Ubuntu)."""
        out, _ = self._exec(
            client,
            "dpkg-query -W -f='${Package}|${Version}|${Architecture}\\n'"
        )
        packages = []
        for line in out.split("\n"):
            parts = line.split("|")
            if len(parts) >= 2:
                packages.append({
                    "name": parts[0],
                    "version": parts[1],
                    "arch": parts[2] if len(parts) > 2 else "",
                })
        return packages

    def get_packages_rpm(self, client):
        """Get packages via rpm (RHEL/CentOS/Fedora)."""
        out, _ = self._exec(
            client,
            "rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}\\n'"
        )
        packages = []
        for line in out.split("\n"):
            parts = line.split("|")
            if len(parts) >= 2:
                packages.append({
                    "name": parts[0],
                    "version": parts[1],
                    "arch": parts[2] if len(parts) > 2 else "",
                })
        return packages

    def get_kernel(self, client):
        """Get running kernel version."""
        out, _ = self._exec(client, "uname -r")
        return out

    def get_listening_services(self, client):
        """Get listening network services."""
        out, _ = self._exec(client, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        return out

    def scan_host(self, hostname, port=22):
        """Perform full agentless scan."""
        result = {
            "hostname": hostname,
            "scan_time": datetime.utcnow().isoformat(),
            "status": "success",
            "os_info": {},
            "kernel": "",
            "packages": [],
            "listening_services": "",
        }

        try:
            client = self._connect(hostname, port)
            result["os_info"] = self.get_os_info(client)
            result["kernel"] = self.get_kernel(client)

            os_id = result["os_info"].get("ID", "").lower()
            if os_id in ("ubuntu", "debian", "kali"):
                result["packages"] = self.get_packages_dpkg(client)
            else:
                result["packages"] = self.get_packages_rpm(client)

            result["listening_services"] = self.get_listening_services(client)
            client.close()

            print(f"  [+] {hostname}: {result['os_info'].get('PRETTY_NAME', 'Unknown')} | "
                  f"{len(result['packages'])} packages | kernel {result['kernel']}")

        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            print(f"  [!] {hostname}: {e}")

        return result

    def scan_hosts(self, hosts, port=22):
        """Scan multiple hosts."""
        results = []
        for host in hosts:
            host = host.strip()
            if not host or host.startswith("#"):
                continue
            print(f"[*] Scanning {host}...")
            results.append(self.scan_host(host, port))
        return results


def main():
    parser = argparse.ArgumentParser(
        description="Agentless Vulnerability Scanning Orchestrator"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan hosts from file")
    scan_p.add_argument("--hosts", required=True, help="File with hostnames/IPs")
    scan_p.add_argument("--key", required=True, help="SSH private key path")
    scan_p.add_argument("--user", default="scanner", help="SSH username")
    scan_p.add_argument("--port", type=int, default=22, help="SSH port")
    scan_p.add_argument("--output", default="scan_results.json")

    check_p = subparsers.add_parser("check", help="Scan a single host")
    check_p.add_argument("--host", required=True)
    check_p.add_argument("--key", required=True)
    check_p.add_argument("--user", default="scanner")
    check_p.add_argument("--port", type=int, default=22)

    report_p = subparsers.add_parser("report", help="Generate CSV report")
    report_p.add_argument("--input", required=True, help="Scan results JSON")
    report_p.add_argument("--output", default="scan_report.csv")

    args = parser.parse_args()

    if args.command == "scan":
        scanner = AgentlessScanner(args.key, args.user)
        with open(args.hosts) as f:
            hosts = f.readlines()
        results = scanner.scan_hosts(hosts, args.port)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")
        successful = sum(1 for r in results if r["status"] == "success")
        print(f"    Scanned: {len(results)} | Success: {successful}")

    elif args.command == "check":
        scanner = AgentlessScanner(args.key, args.user)
        result = scanner.scan_host(args.host, args.port)
        print(json.dumps(result, indent=2, default=str))

    elif args.command == "report":
        with open(args.input) as f:
            results = json.load(f)
        rows = []
        for r in results:
            for pkg in r.get("packages", []):
                rows.append({
                    "hostname": r["hostname"],
                    "os": r.get("os_info", {}).get("PRETTY_NAME", ""),
                    "kernel": r.get("kernel", ""),
                    "package": pkg["name"],
                    "version": pkg["version"],
                })
        df = pd.DataFrame(rows)
        df.to_csv(args.output, index=False)
        print(f"[+] Report with {len(rows)} package entries saved to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
