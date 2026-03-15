#!/usr/bin/env python3
"""
Nessus Infrastructure Scanning Automation Script

Automates vulnerability scanning workflows using the Nessus REST API:
- Creates and launches scans
- Monitors scan progress
- Exports and parses results
- Generates summary reports with severity breakdown

Requirements:
    pip install requests defusedxml pandas jinja2

Usage:
    python process.py --host https://localhost:8834 --user admin --password <pass> --targets 192.168.1.0/24
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
import defusedxml.ElementTree as ET
import pandas as pd

# Suppress SSL warnings for self-signed Nessus certs
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class NessusScanner:
    """Manages Nessus vulnerability scanning via REST API."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None
        self.headers = {"Content-Type": "application/json"}

    def authenticate(self) -> bool:
        """Authenticate to Nessus and obtain session token."""
        url = f"{self.host}/session"
        payload = {"username": self.username, "password": self.password}
        response = requests.post(url, json=payload, verify=self.verify_ssl)
        if response.status_code == 200:
            self.token = response.json()["token"]
            self.headers["X-Cookie"] = f"token={self.token}"
            print(f"[+] Authenticated successfully to {self.host}")
            return True
        else:
            print(f"[-] Authentication failed: {response.status_code} {response.text}")
            return False

    def logout(self):
        """Destroy the current session."""
        if self.token:
            url = f"{self.host}/session"
            requests.delete(url, headers=self.headers, verify=self.verify_ssl)
            print("[+] Session destroyed")

    def list_scan_templates(self) -> list:
        """Retrieve available scan templates."""
        url = f"{self.host}/editor/scan/templates"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            templates = response.json().get("templates", [])
            return [{"uuid": t["uuid"], "name": t["name"], "title": t["title"]} for t in templates]
        return []

    def get_template_uuid(self, template_name: str = "advanced") -> str:
        """Get UUID for a specific scan template."""
        templates = self.list_scan_templates()
        for t in templates:
            if t["name"] == template_name:
                return t["uuid"]
        if templates:
            return templates[0]["uuid"]
        raise ValueError(f"No template found matching '{template_name}'")

    def create_scan(self, name: str, targets: str, template_name: str = "advanced",
                    credentials: dict = None, policy_id: int = None) -> int:
        """Create a new scan configuration."""
        url = f"{self.host}/scans"
        template_uuid = self.get_template_uuid(template_name)

        settings = {
            "name": name,
            "text_targets": targets,
            "launch": "ON_DEMAND",
            "enabled": True,
            "description": f"Automated infrastructure scan created {datetime.now().isoformat()}"
        }

        if policy_id:
            settings["policy_id"] = policy_id

        payload = {"uuid": template_uuid, "settings": settings}

        if credentials:
            payload["credentials"] = credentials

        response = requests.post(url, headers=self.headers, json=payload, verify=self.verify_ssl)
        if response.status_code == 200:
            scan_id = response.json()["scan"]["id"]
            print(f"[+] Scan created: ID={scan_id}, Name='{name}'")
            return scan_id
        else:
            raise RuntimeError(f"Failed to create scan: {response.status_code} {response.text}")

    def launch_scan(self, scan_id: int) -> str:
        """Launch a scan and return the scan UUID."""
        url = f"{self.host}/scans/{scan_id}/launch"
        response = requests.post(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            scan_uuid = response.json().get("scan_uuid", "")
            print(f"[+] Scan {scan_id} launched (UUID: {scan_uuid})")
            return scan_uuid
        else:
            raise RuntimeError(f"Failed to launch scan: {response.status_code}")

    def get_scan_status(self, scan_id: int) -> dict:
        """Get current scan status and summary."""
        url = f"{self.host}/scans/{scan_id}"
        response = requests.get(url, headers=self.headers, verify=self.verify_ssl)
        if response.status_code == 200:
            data = response.json()
            info = data.get("info", {})
            return {
                "status": info.get("status", "unknown"),
                "host_count": info.get("hostcount", 0),
                "scanner_name": info.get("scanner_name", ""),
                "policy": info.get("policy", ""),
                "hosts": data.get("hosts", []),
                "vulnerabilities": data.get("vulnerabilities", [])
            }
        return {"status": "error"}

    def wait_for_scan(self, scan_id: int, poll_interval: int = 30, timeout: int = 7200) -> bool:
        """Poll scan status until completion or timeout."""
        start_time = time.time()
        print(f"[*] Waiting for scan {scan_id} to complete (timeout: {timeout}s)...")

        while time.time() - start_time < timeout:
            status = self.get_scan_status(scan_id)
            current = status["status"]
            elapsed = int(time.time() - start_time)

            if current == "completed":
                print(f"[+] Scan completed in {elapsed}s. Hosts scanned: {status['host_count']}")
                return True
            elif current in ("canceled", "aborted"):
                print(f"[-] Scan {current} after {elapsed}s")
                return False
            elif current == "running":
                print(f"[*] Scan running... ({elapsed}s elapsed, {status['host_count']} hosts)")
            else:
                print(f"[*] Scan status: {current} ({elapsed}s elapsed)")

            time.sleep(poll_interval)

        print(f"[-] Scan timed out after {timeout}s")
        return False

    def export_scan(self, scan_id: int, export_format: str = "nessus",
                    output_dir: str = ".") -> str:
        """Export scan results to file."""
        url = f"{self.host}/scans/{scan_id}/export"
        payload = {"format": export_format}

        if export_format == "csv":
            payload["reportContents"] = {
                "csvColumns": {
                    "id": True, "cve": True, "cvss": True, "risk": True,
                    "hostname": True, "protocol": True, "port": True,
                    "plugin_name": True, "synopsis": True, "description": True,
                    "solution": True, "see_also": True, "plugin_output": True
                }
            }

        response = requests.post(url, headers=self.headers, json=payload, verify=self.verify_ssl)
        if response.status_code != 200:
            raise RuntimeError(f"Export request failed: {response.status_code}")

        file_id = response.json()["file"]
        print(f"[*] Export requested (file_id: {file_id}, format: {export_format})")

        # Poll export status
        status_url = f"{self.host}/scans/{scan_id}/export/{file_id}/status"
        for _ in range(60):
            status_resp = requests.get(status_url, headers=self.headers, verify=self.verify_ssl)
            if status_resp.status_code == 200 and status_resp.json().get("status") == "ready":
                break
            time.sleep(5)

        # Download file
        download_url = f"{self.host}/scans/{scan_id}/export/{file_id}/download"
        download_resp = requests.get(download_url, headers=self.headers, verify=self.verify_ssl)

        ext = {"nessus": "nessus", "csv": "csv", "html": "html", "pdf": "pdf"}.get(export_format, "xml")
        output_path = os.path.join(output_dir, f"scan_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}")

        with open(output_path, "wb") as f:
            f.write(download_resp.content)

        print(f"[+] Results exported to: {output_path}")
        return output_path


class NessusResultParser:
    """Parse and analyze Nessus scan results (.nessus XML format)."""

    SEVERITY_MAP = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

    def __init__(self, nessus_file: str):
        self.nessus_file = nessus_file
        self.tree = ET.parse(nessus_file)
        self.root = self.tree.getroot()
        self.findings = []

    def parse(self) -> list:
        """Parse all findings from the .nessus XML file."""
        self.findings = []

        for report in self.root.findall(".//Report"):
            for host in report.findall("ReportHost"):
                hostname = host.get("name", "unknown")
                host_ip = ""
                host_os = ""

                # Extract host properties
                for tag in host.findall(".//HostProperties/tag"):
                    if tag.get("name") == "host-ip":
                        host_ip = tag.text or ""
                    elif tag.get("name") == "operating-system":
                        host_os = tag.text or ""

                for item in host.findall("ReportItem"):
                    severity = int(item.get("severity", "0"))
                    plugin_id = item.get("pluginID", "")
                    plugin_name = item.get("pluginName", "")
                    port = item.get("port", "0")
                    protocol = item.get("protocol", "")
                    svc_name = item.get("svc_name", "")

                    finding = {
                        "hostname": hostname,
                        "host_ip": host_ip,
                        "host_os": host_os,
                        "plugin_id": plugin_id,
                        "plugin_name": plugin_name,
                        "severity": severity,
                        "severity_name": self.SEVERITY_MAP.get(severity, "Unknown"),
                        "port": port,
                        "protocol": protocol,
                        "service": svc_name,
                        "cvss_base": item.findtext("cvss3_base_score", item.findtext("cvss_base_score", "0")),
                        "cve": item.findtext("cve", ""),
                        "synopsis": item.findtext("synopsis", ""),
                        "description": item.findtext("description", ""),
                        "solution": item.findtext("solution", ""),
                        "see_also": item.findtext("see_also", ""),
                        "plugin_output": item.findtext("plugin_output", ""),
                        "exploit_available": item.findtext("exploit_available", "false"),
                        "exploitability_ease": item.findtext("exploitability_ease", ""),
                    }
                    self.findings.append(finding)

        print(f"[+] Parsed {len(self.findings)} findings from {self.nessus_file}")
        return self.findings

    def to_dataframe(self) -> pd.DataFrame:
        """Convert findings to a pandas DataFrame."""
        if not self.findings:
            self.parse()
        return pd.DataFrame(self.findings)

    def severity_summary(self) -> dict:
        """Generate severity breakdown summary."""
        df = self.to_dataframe()
        summary = df["severity_name"].value_counts().to_dict()
        return {
            "Critical": summary.get("Critical", 0),
            "High": summary.get("High", 0),
            "Medium": summary.get("Medium", 0),
            "Low": summary.get("Low", 0),
            "Informational": summary.get("Informational", 0),
            "Total": len(df),
            "Unique Hosts": df["hostname"].nunique(),
            "Unique Plugins": df["plugin_id"].nunique(),
            "Exploitable": len(df[df["exploit_available"] == "true"])
        }

    def top_vulnerabilities(self, n: int = 20) -> pd.DataFrame:
        """Get top N vulnerabilities by severity and host count."""
        df = self.to_dataframe()
        vuln_df = df[df["severity"] >= 2].copy()

        top = (vuln_df.groupby(["plugin_id", "plugin_name", "severity_name", "cvss_base", "cve"])
               .agg(affected_hosts=("hostname", "nunique"))
               .reset_index()
               .sort_values(["severity_name", "affected_hosts"], ascending=[True, False])
               .head(n))

        return top

    def host_risk_scores(self) -> pd.DataFrame:
        """Calculate risk score per host based on vulnerability severity."""
        df = self.to_dataframe()
        severity_weights = {4: 10, 3: 5, 2: 2, 1: 0.5, 0: 0}

        df["weight"] = df["severity"].map(severity_weights)
        host_scores = (df.groupby(["hostname", "host_ip", "host_os"])
                       .agg(
                           risk_score=("weight", "sum"),
                           critical=("severity", lambda x: (x == 4).sum()),
                           high=("severity", lambda x: (x == 3).sum()),
                           medium=("severity", lambda x: (x == 2).sum()),
                           low=("severity", lambda x: (x == 1).sum()),
                           total_findings=("severity", "count")
                       )
                       .reset_index()
                       .sort_values("risk_score", ascending=False))

        return host_scores

    def generate_report(self, output_path: str):
        """Generate an HTML summary report."""
        summary = self.severity_summary()
        top_vulns = self.top_vulnerabilities()
        host_risks = self.host_risk_scores().head(20)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Nessus Scan Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .critical {{ border-top: 4px solid #e74c3c; }}
        .high {{ border-top: 4px solid #e67e22; }}
        .medium {{ border-top: 4px solid #f1c40f; }}
        .low {{ border-top: 4px solid #3498db; }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        .card p {{ margin: 5px 0 0; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Scan Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Source: {self.nessus_file}</p>
    </div>

    <div class="summary">
        <div class="card critical"><h3>{summary['Critical']}</h3><p>Critical</p></div>
        <div class="card high"><h3>{summary['High']}</h3><p>High</p></div>
        <div class="card medium"><h3>{summary['Medium']}</h3><p>Medium</p></div>
        <div class="card low"><h3>{summary['Low']}</h3><p>Low</p></div>
    </div>

    <p><strong>Total Findings:</strong> {summary['Total']} |
       <strong>Unique Hosts:</strong> {summary['Unique Hosts']} |
       <strong>Exploitable:</strong> {summary['Exploitable']}</p>

    <h2>Top Vulnerabilities</h2>
    <table>
        <tr><th>Plugin ID</th><th>Name</th><th>Severity</th><th>CVSS</th><th>CVE</th><th>Affected Hosts</th></tr>
        {''.join(f'<tr><td>{r.plugin_id}</td><td>{r.plugin_name}</td><td>{r.severity_name}</td><td>{r.cvss_base}</td><td>{r.cve}</td><td>{r.affected_hosts}</td></tr>' for r in top_vulns.itertuples())}
    </table>

    <h2>Host Risk Scores (Top 20)</h2>
    <table>
        <tr><th>Host</th><th>IP</th><th>OS</th><th>Risk Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Total</th></tr>
        {''.join(f'<tr><td>{r.hostname}</td><td>{r.host_ip}</td><td>{str(r.host_os)[:50]}</td><td>{r.risk_score:.0f}</td><td>{r.critical}</td><td>{r.high}</td><td>{r.medium}</td><td>{r.total_findings}</td></tr>' for r in host_risks.itertuples())}
    </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Report generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Nessus Infrastructure Scanning Automation")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Create and run a vulnerability scan")
    scan_parser.add_argument("--host", required=True, help="Nessus server URL (e.g., https://localhost:8834)")
    scan_parser.add_argument("--user", required=True, help="Nessus username")
    scan_parser.add_argument("--password", required=True, help="Nessus password")
    scan_parser.add_argument("--targets", required=True, help="Target IPs/ranges (comma-separated or CIDR)")
    scan_parser.add_argument("--name", default=None, help="Scan name")
    scan_parser.add_argument("--template", default="advanced", help="Scan template name")
    scan_parser.add_argument("--export-format", default="nessus", choices=["nessus", "csv", "html", "pdf"])
    scan_parser.add_argument("--output-dir", default=".", help="Directory for exported results")
    scan_parser.add_argument("--timeout", type=int, default=7200, help="Scan timeout in seconds")

    # Parse command
    parse_parser = subparsers.add_parser("parse", help="Parse and analyze .nessus scan results")
    parse_parser.add_argument("--file", required=True, help="Path to .nessus XML file")
    parse_parser.add_argument("--report", default=None, help="Output HTML report path")
    parse_parser.add_argument("--csv-output", default=None, help="Export findings to CSV")
    parse_parser.add_argument("--min-severity", type=int, default=0, choices=[0, 1, 2, 3, 4],
                              help="Minimum severity to include (0=Info, 4=Critical)")

    args = parser.parse_args()

    if args.command == "scan":
        scanner = NessusScanner(args.host, args.user, args.password)

        if not scanner.authenticate():
            sys.exit(1)

        try:
            scan_name = args.name or f"Infrastructure_Scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            scan_id = scanner.create_scan(scan_name, args.targets, args.template)
            scanner.launch_scan(scan_id)

            if scanner.wait_for_scan(scan_id, timeout=args.timeout):
                os.makedirs(args.output_dir, exist_ok=True)
                export_path = scanner.export_scan(scan_id, args.export_format, args.output_dir)

                # Auto-parse if exported in nessus format
                if args.export_format == "nessus":
                    result_parser = NessusResultParser(export_path)
                    result_parser.parse()
                    summary = result_parser.severity_summary()
                    print("\n=== Scan Summary ===")
                    for key, value in summary.items():
                        print(f"  {key}: {value}")

                    report_path = os.path.join(args.output_dir, f"report_{scan_id}.html")
                    result_parser.generate_report(report_path)
            else:
                print("[-] Scan did not complete successfully")
                sys.exit(1)
        finally:
            scanner.logout()

    elif args.command == "parse":
        result_parser = NessusResultParser(args.file)
        result_parser.parse()

        summary = result_parser.severity_summary()
        print("\n=== Vulnerability Summary ===")
        for key, value in summary.items():
            print(f"  {key}: {value}")

        if args.min_severity > 0:
            df = result_parser.to_dataframe()
            filtered = df[df["severity"] >= args.min_severity]
            print(f"\n[*] Findings with severity >= {args.min_severity}: {len(filtered)}")

        if args.report:
            result_parser.generate_report(args.report)

        if args.csv_output:
            df = result_parser.to_dataframe()
            df.to_csv(args.csv_output, index=False)
            print(f"[+] CSV exported to: {args.csv_output}")

        print("\n=== Top 10 Vulnerabilities ===")
        top = result_parser.top_vulnerabilities(10)
        print(top.to_string(index=False))

        print("\n=== Top 10 Riskiest Hosts ===")
        hosts = result_parser.host_risk_scores().head(10)
        print(hosts.to_string(index=False))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
