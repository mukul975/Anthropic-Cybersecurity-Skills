#!/usr/bin/env python3
"""
Nikto Web Application Scanning Automation

Automates Nikto scanning across multiple targets, parses results,
and generates consolidated vulnerability reports.

Requirements:
    pip install pandas defusedxml jinja2
    System: nikto installed and in PATH

Usage:
    python process.py scan --targets targets.txt --output-dir ./results
    python process.py parse --xml-dir ./results --report report.html
"""

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import defusedxml.ElementTree as ET
import pandas as pd


class NiktoScanner:
    """Automated Nikto web scanning manager."""

    def __init__(self, output_dir: str = "./nikto_results", timeout: int = 600):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.results = []

    def scan_target(self, target: str, tuning: str = "123456789abc",
                    pause: int = 1, ssl: bool = False) -> dict:
        """Run Nikto scan against a single target."""
        parsed = urlparse(target if "://" in target else f"http://{target}")
        safe_name = parsed.netloc.replace(":", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_output = self.output_dir / f"{safe_name}_{timestamp}.xml"

        cmd = [
            "nikto",
            "-h", target,
            "-Tuning", tuning,
            "-Pause", str(pause),
            "-timeout", "10",
            "-nointeractive",
            "-output", str(xml_output),
            "-Format", "xml",
        ]

        if ssl or parsed.scheme == "https":
            cmd.append("-ssl")

        result = {
            "target": target,
            "status": "unknown",
            "output_file": str(xml_output),
            "findings": [],
            "start_time": datetime.now().isoformat(),
        }

        print(f"[*] Scanning {target}...")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
            result["status"] = "completed"
            result["end_time"] = datetime.now().isoformat()
            result["stdout"] = proc.stdout[-2000:] if proc.stdout else ""
            result["stderr"] = proc.stderr[-500:] if proc.stderr else ""

            if xml_output.exists():
                result["findings"] = self.parse_xml(str(xml_output))
                finding_count = len(result["findings"])
                print(f"[+] {target}: {finding_count} findings")
            else:
                print(f"[!] {target}: No XML output generated")
                result["status"] = "no_output"

        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            print(f"[-] {target}: Scan timed out after {self.timeout}s")
        except FileNotFoundError:
            result["status"] = "error"
            result["error"] = "nikto not found in PATH"
            print("[-] Error: nikto not found. Install with: apt install nikto")
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            print(f"[-] {target}: Error - {e}")

        self.results.append(result)
        return result

    def scan_targets(self, targets: list, max_parallel: int = 3, **kwargs) -> list:
        """Scan multiple targets with optional parallelism."""
        self.results = []

        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            futures = {
                executor.submit(self.scan_target, target, **kwargs): target
                for target in targets
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    target = futures[future]
                    print(f"[-] {target}: Scan failed - {e}")

        return self.results

    @staticmethod
    def parse_xml(xml_path: str) -> list:
        """Parse Nikto XML output into structured findings."""
        findings = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            for scan_details in root.findall(".//scandetails"):
                target_ip = scan_details.get("targetip", "")
                target_host = scan_details.get("targethostname", "")
                target_port = scan_details.get("targetport", "")
                target_banner = scan_details.get("targetbanner", "")

                for item in scan_details.findall("item"):
                    finding = {
                        "target_ip": target_ip,
                        "target_host": target_host,
                        "target_port": target_port,
                        "server_banner": target_banner,
                        "nikto_id": item.get("id", ""),
                        "osvdb_id": item.get("osvdbid", ""),
                        "osvdb_link": item.get("osvdblink", ""),
                        "method": item.get("method", "GET"),
                        "uri": item.findtext("uri", ""),
                        "description": item.findtext("description", ""),
                        "name_link": item.findtext("namelink", ""),
                        "ip_link": item.findtext("iplink", ""),
                    }

                    # Classify severity based on description keywords
                    desc_lower = finding["description"].lower()
                    if any(w in desc_lower for w in ["remote code", "command execution", "backdoor", "rce"]):
                        finding["severity"] = "Critical"
                    elif any(w in desc_lower for w in ["sql injection", "xss", "cross-site", "file inclusion"]):
                        finding["severity"] = "High"
                    elif any(w in desc_lower for w in ["directory listing", "information disclosure", "version"]):
                        finding["severity"] = "Medium"
                    elif any(w in desc_lower for w in ["header", "cookie", "x-frame"]):
                        finding["severity"] = "Low"
                    else:
                        finding["severity"] = "Info"

                    findings.append(finding)

        except Exception as e:
            print(f"[!] XML parse error for {xml_path}: {e}")

        return findings

    def generate_report(self, output_path: str):
        """Generate consolidated HTML report from all scan results."""
        all_findings = []
        for result in self.results:
            for finding in result.get("findings", []):
                finding["scan_target"] = result["target"]
                finding["scan_status"] = result["status"]
                all_findings.append(finding)

        if not all_findings:
            print("[-] No findings to report")
            return

        df = pd.DataFrame(all_findings)

        # Severity counts
        sev_counts = df["severity"].value_counts().to_dict()

        # Target summary
        target_summary = (df.groupby(["scan_target", "target_port"])
                          .agg(findings=("nikto_id", "count"),
                               critical=("severity", lambda x: (x == "Critical").sum()),
                               high=("severity", lambda x: (x == "High").sum()))
                          .reset_index())

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Nikto Scan Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #16213e; color: white; padding: 20px; border-radius: 8px; }}
        .cards {{ display: flex; gap: 15px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; flex: 1; text-align: center;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h3 {{ margin: 0; font-size: 2em; }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 15px 0;
                 border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th {{ background: #2c3e50; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 0.9em; }}
        .sev-critical {{ color: #e74c3c; font-weight: bold; }}
        .sev-high {{ color: #e67e22; font-weight: bold; }}
        .sev-medium {{ color: #f39c12; }}
        .sev-low {{ color: #3498db; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Nikto Web Scan Report</h1>
        <p>Targets: {len(self.results)} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>

    <div class="cards">
        <div class="card" style="border-top:4px solid #e74c3c"><h3>{sev_counts.get('Critical', 0)}</h3><p>Critical</p></div>
        <div class="card" style="border-top:4px solid #e67e22"><h3>{sev_counts.get('High', 0)}</h3><p>High</p></div>
        <div class="card" style="border-top:4px solid #f39c12"><h3>{sev_counts.get('Medium', 0)}</h3><p>Medium</p></div>
        <div class="card" style="border-top:4px solid #3498db"><h3>{sev_counts.get('Low', 0)}</h3><p>Low</p></div>
    </div>

    <h2>Target Summary</h2>
    <table>
        <tr><th>Target</th><th>Port</th><th>Total</th><th>Critical</th><th>High</th></tr>
        {''.join(f"<tr><td>{r.scan_target}</td><td>{r.target_port}</td><td>{r.findings}</td><td>{r.critical}</td><td>{r.high}</td></tr>" for r in target_summary.itertuples())}
    </table>

    <h2>All Findings</h2>
    <table>
        <tr><th>Target</th><th>Severity</th><th>URI</th><th>Description</th><th>OSVDB</th></tr>
        {''.join(f'<tr><td>{r.scan_target}</td><td class="sev-{r.severity.lower()}">{r.severity}</td><td>{r.uri}</td><td>{r.description[:150]}</td><td>{r.osvdb_id}</td></tr>' for r in df.sort_values("severity").itertuples())}
    </table>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Nikto Web Scanning Automation")
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan web targets with Nikto")
    scan_p.add_argument("--targets", required=True, help="File with target URLs")
    scan_p.add_argument("--output-dir", default="./nikto_results")
    scan_p.add_argument("--report", default=None, help="HTML report output path")
    scan_p.add_argument("--tuning", default="123456789abc", help="Nikto tuning options")
    scan_p.add_argument("--parallel", type=int, default=3, help="Max parallel scans")
    scan_p.add_argument("--timeout", type=int, default=600, help="Per-target timeout")
    scan_p.add_argument("--pause", type=int, default=1, help="Pause between requests")

    parse_p = subparsers.add_parser("parse", help="Parse existing Nikto XML results")
    parse_p.add_argument("--xml-dir", required=True, help="Directory with Nikto XML files")
    parse_p.add_argument("--report", required=True, help="HTML report output path")

    args = parser.parse_args()

    if args.command == "scan":
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        scanner = NiktoScanner(args.output_dir, args.timeout)
        scanner.scan_targets(targets, max_parallel=args.parallel,
                             tuning=args.tuning, pause=args.pause)

        report_path = args.report or os.path.join(args.output_dir, "nikto_report.html")
        scanner.generate_report(report_path)

    elif args.command == "parse":
        scanner = NiktoScanner()
        xml_dir = Path(args.xml_dir)

        for xml_file in xml_dir.glob("*.xml"):
            findings = scanner.parse_xml(str(xml_file))
            scanner.results.append({
                "target": xml_file.stem,
                "status": "parsed",
                "findings": findings,
            })

        scanner.generate_report(args.report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
