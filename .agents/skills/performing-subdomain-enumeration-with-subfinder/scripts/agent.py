#!/usr/bin/env python3
"""Agent for subdomain enumeration using subfinder and httpx.

Runs ProjectDiscovery subfinder for passive subdomain discovery,
validates live hosts with httpx, resolves DNS, and generates
an attack surface report.
"""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path
from collections import defaultdict


class SubdomainEnumerationAgent:
    """Enumerates subdomains using subfinder and validates with httpx."""

    def __init__(self, domain, output_dir="./recon"):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.subdomains = []
        self.live_hosts = []

    def run_subfinder(self, all_sources=False, recursive=False):
        """Run subfinder for passive subdomain enumeration."""
        out_file = self.output_dir / f"{self.domain}_subdomains.txt"
        cmd = ["subfinder", "-d", self.domain, "-o", str(out_file), "-silent"]
        if all_sources:
            cmd.append("-all")
        if recursive:
            cmd.append("-recursive")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if out_file.exists():
                self.subdomains = [
                    line.strip() for line in out_file.read_text().splitlines()
                    if line.strip()
                ]
            return {"count": len(self.subdomains),
                    "output_file": str(out_file),
                    "stderr": result.stderr[:200] if result.stderr else ""}
        except FileNotFoundError:
            return {"error": "subfinder not installed. Install: go install -v "
                    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}
        except subprocess.TimeoutExpired:
            return {"error": "subfinder timed out after 300s"}

    def run_subfinder_json(self):
        """Run subfinder with JSON output for source tracking."""
        cmd = ["subfinder", "-d", self.domain, "-oJ", "-silent"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            entries = []
            for line in result.stdout.strip().splitlines():
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                    host = entry.get("host", "")
                    if host and host not in self.subdomains:
                        self.subdomains.append(host)
                except json.JSONDecodeError:
                    continue
            return entries
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def validate_with_httpx(self, ports="80,443"):
        """Validate discovered subdomains with httpx probe."""
        if not self.subdomains:
            return []

        input_file = self.output_dir / f"{self.domain}_to_probe.txt"
        input_file.write_text("\n".join(self.subdomains))
        out_file = self.output_dir / f"{self.domain}_live.json"

        cmd = ["httpx", "-l", str(input_file), "-ports", ports,
               "-status-code", "-title", "-json", "-o", str(out_file), "-silent"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if out_file.exists():
                for line in out_file.read_text().splitlines():
                    try:
                        self.live_hosts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return self.live_hosts
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def resolve_dns(self):
        """Resolve subdomains to IP addresses using dnsx."""
        if not self.subdomains:
            return []
        input_file = self.output_dir / f"{self.domain}_to_resolve.txt"
        input_file.write_text("\n".join(self.subdomains))
        cmd = ["dnsx", "-l", str(input_file), "-a", "-resp", "-json", "-silent"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            records = []
            for line in result.stdout.strip().splitlines():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return records
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def detect_takeover_candidates(self):
        """Identify subdomains potentially vulnerable to takeover."""
        candidates = []
        cloud_cnames = ["amazonaws.com", "azurewebsites.net", "cloudfront.net",
                        "herokuapp.com", "github.io", "s3.amazonaws.com",
                        "blob.core.windows.net", "cloudapp.azure.com"]
        dns_records = self.resolve_dns()
        for record in dns_records:
            cname = record.get("cname", "")
            if any(cloud in cname for cloud in cloud_cnames):
                candidates.append({
                    "subdomain": record.get("host", ""),
                    "cname": cname,
                    "risk": "Potential subdomain takeover"
                })
        return candidates

    def generate_report(self):
        """Generate attack surface enumeration report."""
        status_dist = defaultdict(int)
        for host in self.live_hosts:
            code = host.get("status_code", 0)
            status_dist[str(code)] += 1

        report = {
            "domain": self.domain,
            "report_date": datetime.utcnow().isoformat(),
            "total_subdomains": len(self.subdomains),
            "live_hosts": len(self.live_hosts),
            "status_distribution": dict(status_dist),
            "subdomains": self.subdomains[:100],
            "live_host_details": self.live_hosts[:50],
            "takeover_candidates": self.detect_takeover_candidates(),
        }

        report_path = self.output_dir / f"{self.domain}_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <domain> [output_dir]")
        sys.exit(1)
    domain = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./recon"
    agent = SubdomainEnumerationAgent(domain, output_dir)
    agent.run_subfinder(all_sources=True)
    agent.validate_with_httpx()
    agent.generate_report()


if __name__ == "__main__":
    main()
