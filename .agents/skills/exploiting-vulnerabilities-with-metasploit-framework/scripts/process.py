#!/usr/bin/env python3
"""
Metasploit Vulnerability Validation Automation

Uses Metasploit RPC API (msfrpcd) to automate vulnerability validation
by running check commands against scan findings.

Requirements:
    pip install requests pandas pymetasploit3

Usage:
    python process.py validate --vulns vulns.csv --msf-host 127.0.0.1 --msf-pass password
    python process.py report --results validation_results.csv
"""

import argparse
import json
import sys
import time
from datetime import datetime

import pandas as pd
import requests


class MetasploitRPC:
    """Interface to Metasploit RPC API for automated vulnerability validation."""

    def __init__(self, host: str = "127.0.0.1", port: int = 55553,
                 username: str = "msf", password: str = "password",
                 ssl: bool = True):
        self.base_url = f"{'https' if ssl else 'http'}://{host}:{port}/api/"
        self.token = None
        self.session = requests.Session()
        self.session.verify = False

        # Authenticate
        self._login(username, password)

    def _login(self, username: str, password: str):
        """Authenticate to msfrpcd."""
        result = self._call("auth.login", [username, password])
        if result.get("result") == "success":
            self.token = result["token"]
            print(f"[+] Authenticated to Metasploit RPC")
        else:
            raise ConnectionError(f"Metasploit RPC auth failed: {result}")

    def _call(self, method: str, params: list = None) -> dict:
        """Make an RPC call to Metasploit."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
            "id": 1,
            "params": [self.token] + (params or []) if self.token else (params or [])
        })

        try:
            response = self.session.post(
                self.base_url, data=payload,
                headers={"Content-Type": "application/json"},
                timeout=60
            )
            return response.json().get("result", response.json())
        except Exception as e:
            return {"error": str(e)}

    def create_console(self) -> str:
        """Create a new Metasploit console."""
        result = self._call("console.create")
        console_id = result.get("id")
        print(f"[+] Console created: {console_id}")
        return console_id

    def console_write(self, console_id: str, command: str):
        """Write a command to a console."""
        self._call("console.write", [console_id, command + "\n"])

    def console_read(self, console_id: str, timeout: int = 30) -> str:
        """Read output from a console with polling."""
        output = ""
        start = time.time()
        while time.time() - start < timeout:
            result = self._call("console.read", [console_id])
            data = result.get("data", "")
            output += data
            if not result.get("busy", True):
                break
            time.sleep(2)
        return output

    def run_check(self, console_id: str, module: str, rhosts: str,
                  options: dict = None) -> dict:
        """Run a module check command and return results."""
        self.console_write(console_id, f"use {module}")
        time.sleep(1)
        self.console_read(console_id, timeout=5)

        self.console_write(console_id, f"set RHOSTS {rhosts}")
        time.sleep(0.5)

        if options:
            for key, value in options.items():
                self.console_write(console_id, f"set {key} {value}")
                time.sleep(0.5)

        self.console_read(console_id, timeout=5)
        self.console_write(console_id, "check")
        output = self.console_read(console_id, timeout=60)

        is_vulnerable = any(
            indicator in output.lower()
            for indicator in ["is vulnerable", "appears vulnerable", "[+]"]
        )
        is_not_vulnerable = any(
            indicator in output.lower()
            for indicator in ["not vulnerable", "does not appear", "safe"]
        )

        status = "unknown"
        if is_vulnerable and not is_not_vulnerable:
            status = "vulnerable"
        elif is_not_vulnerable:
            status = "not_vulnerable"
        elif "check is not supported" in output.lower():
            status = "check_unsupported"

        return {
            "module": module,
            "target": rhosts,
            "status": status,
            "output": output[:2000],
            "timestamp": datetime.now().isoformat(),
        }

    def search_module(self, console_id: str, search_term: str) -> list:
        """Search for Metasploit modules."""
        self.console_write(console_id, f"search {search_term}")
        output = self.console_read(console_id, timeout=30)

        modules = []
        for line in output.split("\n"):
            if line.strip().startswith(("exploit/", "auxiliary/")):
                parts = line.strip().split()
                if len(parts) >= 3:
                    modules.append({
                        "module": parts[0],
                        "date": parts[1],
                        "rank": parts[2] if len(parts) > 2 else "",
                        "description": " ".join(parts[3:]) if len(parts) > 3 else "",
                    })
        return modules

    def destroy_console(self, console_id: str):
        """Destroy a console."""
        self._call("console.destroy", [console_id])


class VulnerabilityValidator:
    """Validate scanner findings using Metasploit check capabilities."""

    # Map common CVEs to Metasploit modules
    CVE_MODULE_MAP = {
        "CVE-2017-0144": "exploit/windows/smb/ms17_010_eternalblue",
        "CVE-2019-0708": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "CVE-2020-1472": "exploit/windows/dcerpc/cve_2020_1472_zerologon",
        "CVE-2021-44228": "exploit/multi/http/log4shell_header_injection",
        "CVE-2021-34527": "exploit/windows/dcerpc/cve_2021_1675_printnightmare",
        "CVE-2022-26134": "exploit/multi/http/atlassian_confluence_namespace_ognl",
        "CVE-2023-27997": "exploit/linux/http/fortinet_fortigate_sslvpn_rce",
        "CVE-2024-3094": "auxiliary/scanner/ssh/xz_backdoor_scanner",
        "CVE-2014-0160": "auxiliary/scanner/ssl/openssl_heartbleed",
        "CVE-2014-6271": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    }

    # Map service/plugin families to auxiliary scanner modules
    SERVICE_SCANNER_MAP = {
        "smb": "auxiliary/scanner/smb/smb_ms17_010",
        "rdp": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "ssl_heartbleed": "auxiliary/scanner/ssl/openssl_heartbleed",
        "http_dir_listing": "auxiliary/scanner/http/dir_listing",
        "ftp_anonymous": "auxiliary/scanner/ftp/anonymous",
        "ssh_enumusers": "auxiliary/scanner/ssh/ssh_enumusers",
        "mssql_login": "auxiliary/scanner/mssql/mssql_login",
    }

    def __init__(self):
        self.results = []

    def find_module(self, cve: str) -> str:
        """Find the best Metasploit module for a given CVE."""
        return self.CVE_MODULE_MAP.get(cve, "")

    def validate_from_csv(self, csv_path: str, msf: MetasploitRPC) -> pd.DataFrame:
        """Validate vulnerabilities from a CSV file using Metasploit."""
        df = pd.read_csv(csv_path)
        console_id = msf.create_console()

        try:
            for _, row in df.iterrows():
                cve = row.get("cve", "")
                host = row.get("host", row.get("hostname", ""))
                module = row.get("msf_module", self.find_module(cve))

                if not module:
                    self.results.append({
                        "cve": cve, "host": host, "module": "",
                        "status": "no_module", "output": "No Metasploit module mapped",
                        "timestamp": datetime.now().isoformat(),
                    })
                    print(f"  [?] {cve} on {host}: No module available")
                    continue

                print(f"  [*] Checking {cve} on {host} with {module}...")
                result = msf.run_check(console_id, module, host)
                result["cve"] = cve
                self.results.append(result)

                status_icon = "[+]" if result["status"] == "vulnerable" else "[-]"
                print(f"  {status_icon} {cve} on {host}: {result['status']}")

        finally:
            msf.destroy_console(console_id)

        return pd.DataFrame(self.results)

    def generate_report(self, output_path: str):
        """Generate validation report."""
        if not self.results:
            print("[-] No results to report")
            return

        df = pd.DataFrame(self.results)
        total = len(df)
        confirmed = len(df[df["status"] == "vulnerable"])
        not_vuln = len(df[df["status"] == "not_vulnerable"])
        unknown = len(df[df["status"].isin(["unknown", "check_unsupported"])])
        no_module = len(df[df["status"] == "no_module"])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Metasploit Validation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        .metrics {{ display: flex; gap: 15px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; text-align: center;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        .confirmed {{ border-top: 4px solid #e74c3c; }}
        .safe {{ border-top: 4px solid #27ae60; }}
        .unknown {{ border-top: 4px solid #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 15px 0; }}
        th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #eee; }}
        .status-vulnerable {{ color: #e74c3c; font-weight: bold; }}
        .status-not_vulnerable {{ color: #27ae60; }}
        .status-unknown {{ color: #f39c12; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Validation Report</h1>
        <p>Tool: Metasploit Framework | Date: {datetime.now().strftime('%Y-%m-%d')}</p>
    </div>
    <div class="metrics">
        <div class="card confirmed"><h3>{confirmed}</h3><p>Confirmed Vulnerable</p></div>
        <div class="card safe"><h3>{not_vuln}</h3><p>Not Vulnerable</p></div>
        <div class="card unknown"><h3>{unknown}</h3><p>Inconclusive</p></div>
        <div class="card"><h3>{no_module}</h3><p>No Module Available</p></div>
    </div>
    <h2>Validation Results</h2>
    <table>
        <tr><th>CVE</th><th>Host</th><th>Module</th><th>Status</th></tr>
        {''.join(f'<tr><td>{r.get("cve","")}</td><td>{r.get("target",r.get("host",""))}</td><td>{r.get("module","")}</td><td class="status-{r["status"]}">{r["status"]}</td></tr>' for r in self.results)}
    </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Metasploit Vulnerability Validation")
    subparsers = parser.add_subparsers(dest="command")

    val_p = subparsers.add_parser("validate", help="Validate vulnerabilities with Metasploit")
    val_p.add_argument("--vulns", required=True, help="CSV with cve, host columns")
    val_p.add_argument("--msf-host", default="127.0.0.1", help="msfrpcd host")
    val_p.add_argument("--msf-port", type=int, default=55553, help="msfrpcd port")
    val_p.add_argument("--msf-user", default="msf", help="msfrpcd username")
    val_p.add_argument("--msf-pass", required=True, help="msfrpcd password")
    val_p.add_argument("--output", default="validation_results.csv")
    val_p.add_argument("--report", default="validation_report.html")

    args = parser.parse_args()

    if args.command == "validate":
        msf = MetasploitRPC(
            host=args.msf_host, port=args.msf_port,
            username=args.msf_user, password=args.msf_pass
        )
        validator = VulnerabilityValidator()
        results_df = validator.validate_from_csv(args.vulns, msf)
        results_df.to_csv(args.output, index=False)
        print(f"[+] Results saved to: {args.output}")
        validator.generate_report(args.report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
