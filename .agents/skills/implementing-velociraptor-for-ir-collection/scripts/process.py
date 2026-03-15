"""
Velociraptor IR Collection Automation Script
Manages artifact collection, hunt creation, and result analysis via Velociraptor API.
"""

import json
import os
import csv
import hashlib
from datetime import datetime
from pathlib import Path
from collections import defaultdict


class VelociraptorCollector:
    """Manages Velociraptor artifact collection for incident response."""

    TRIAGE_ARTIFACTS_WINDOWS = [
        "Windows.EventLogs.EvtxHunter",
        "Windows.Forensics.Prefetch",
        "Windows.Registry.AppCompatCache",
        "Windows.Forensics.Amcache",
        "Windows.Forensics.UserAssist",
        "Windows.System.TaskScheduler",
        "Windows.System.Pslist",
        "Windows.Network.Netstat",
        "Windows.Network.DNSCache",
        "Windows.Forensics.PowerShellHistory",
        "Windows.System.Services",
        "Windows.System.StartupItems",
        "Windows.Persistence.PermanentWMIEvents",
    ]

    TRIAGE_ARTIFACTS_LINUX = [
        "Linux.Sys.AuthLogs",
        "Linux.Forensics.BashHistory",
        "Linux.Sys.Crontab",
        "Linux.Sys.Pslist",
        "Linux.Network.Netstat",
        "Linux.Ssh.AuthorizedKeys",
        "Linux.Services",
    ]

    def __init__(self, server_url=None, api_key=None, output_dir="velociraptor_results"):
        self.server_url = server_url or "https://localhost:8001"
        self.api_key = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.collection_manifest = []

    def generate_vql_triage_pack(self, target_os="windows", output_file=None):
        """Generate VQL artifact collection pack for triage."""
        artifacts = (
            self.TRIAGE_ARTIFACTS_WINDOWS
            if target_os == "windows"
            else self.TRIAGE_ARTIFACTS_LINUX
        )

        vql_queries = []
        for artifact in artifacts:
            vql_queries.append({
                "artifact": artifact,
                "vql": f"SELECT * FROM Artifact.{artifact}()",
                "description": f"Collect {artifact.split('.')[-1]} artifacts",
            })

        pack = {
            "name": f"IR Triage Pack - {target_os.title()}",
            "version": "1.0",
            "generated": datetime.utcnow().isoformat(),
            "target_os": target_os,
            "artifacts": vql_queries,
        }

        if output_file is None:
            output_file = self.output_dir / f"triage_pack_{target_os}.json"

        with open(output_file, "w") as f:
            json.dump(pack, f, indent=2)

        print(f"[+] Generated {target_os} triage pack: {output_file}")
        print(f"    Artifacts: {len(vql_queries)}")
        return pack

    def generate_hunt_config(self, hunt_name, description, artifacts, parameters=None,
                              include_labels=None, exclude_labels=None):
        """Generate hunt configuration for enterprise-wide collection."""
        hunt_config = {
            "hunt_name": hunt_name,
            "description": description,
            "created": datetime.utcnow().isoformat(),
            "artifacts": artifacts,
            "parameters": parameters or {},
            "targeting": {
                "include_labels": include_labels or [],
                "exclude_labels": exclude_labels or [],
            },
            "resource_limits": {
                "cpu_limit": 50,
                "iops_limit": 100,
                "timeout_seconds": 600,
                "max_rows": 100000,
                "max_upload_bytes": 104857600,
            },
        }

        config_file = self.output_dir / f"hunt_{hunt_name.replace(' ', '_')}.json"
        with open(config_file, "w") as f:
            json.dump(hunt_config, f, indent=2)

        print(f"[+] Generated hunt config: {config_file}")
        return hunt_config

    def generate_ioc_hunt(self, iocs, hunt_name="IOC Hunt"):
        """Generate VQL-based IOC hunt queries."""
        vql_queries = []

        if "hashes" in iocs:
            hash_list = "|".join(iocs["hashes"])
            vql_queries.append({
                "name": "Hash Hunt",
                "vql": f"""SELECT * FROM Artifact.Generic.Detection.HashHunter(
                    Hashes='{hash_list}'
                )""",
            })

        if "ips" in iocs:
            ip_regex = "|".join(ip.replace(".", "\\.") for ip in iocs["ips"])
            vql_queries.append({
                "name": "Network Connection Hunt",
                "vql": f"""SELECT * FROM Artifact.Windows.Network.Netstat()
                    WHERE RemoteAddr =~ '{ip_regex}'""",
            })

        if "domains" in iocs:
            domain_regex = "|".join(d.replace(".", "\\.") for d in iocs["domains"])
            vql_queries.append({
                "name": "DNS Cache Hunt",
                "vql": f"""SELECT * FROM Artifact.Windows.Network.DNSCache()
                    WHERE Name =~ '{domain_regex}'""",
            })

        if "filenames" in iocs:
            file_regex = "|".join(iocs["filenames"])
            vql_queries.append({
                "name": "File Hunt",
                "vql": f"""SELECT * FROM Artifact.Windows.NTFS.MFT(
                    FileRegex='{file_regex}'
                )""",
            })

        if "yara_rules" in iocs:
            for rule_name, rule_content in iocs["yara_rules"].items():
                vql_queries.append({
                    "name": f"YARA Hunt - {rule_name}",
                    "vql": f"""SELECT * FROM Artifact.Windows.Detection.Yara.Process(
                        YaraRule='{rule_content}'
                    )""",
                })

        hunt_file = self.output_dir / f"ioc_hunt_{hunt_name.replace(' ', '_')}.json"
        with open(hunt_file, "w") as f:
            json.dump({"name": hunt_name, "queries": vql_queries}, f, indent=2)

        print(f"[+] Generated IOC hunt with {len(vql_queries)} queries: {hunt_file}")
        return vql_queries

    def generate_collection_checklist(self, case_id, target_hosts):
        """Generate collection checklist for IR case."""
        checklist = {
            "case_id": case_id,
            "generated": datetime.utcnow().isoformat(),
            "targets": [],
        }

        for host in target_hosts:
            target = {
                "hostname": host,
                "collections": [
                    {"artifact": "Volatile Data", "status": "pending", "items": [
                        "Running processes", "Network connections", "DNS cache",
                        "Logged-in users", "Open files",
                    ]},
                    {"artifact": "Event Logs", "status": "pending", "items": [
                        "Security.evtx", "System.evtx", "Application.evtx",
                        "PowerShell/Operational.evtx", "Sysmon/Operational.evtx",
                    ]},
                    {"artifact": "Execution Evidence", "status": "pending", "items": [
                        "Prefetch files", "Amcache.hve", "Shimcache",
                        "UserAssist", "BAM/DAM",
                    ]},
                    {"artifact": "Persistence Mechanisms", "status": "pending", "items": [
                        "Scheduled tasks", "Services", "Registry Run keys",
                        "WMI subscriptions", "Startup items",
                    ]},
                    {"artifact": "File System", "status": "pending", "items": [
                        "MFT entries", "USN Journal", "Recycle Bin",
                        "Recent files", "Downloads folder",
                    ]},
                    {"artifact": "User Activity", "status": "pending", "items": [
                        "Browser history", "PowerShell history", "RDP cache",
                        "Recent documents", "Jump lists",
                    ]},
                ],
            }
            checklist["targets"].append(target)

        checklist_file = self.output_dir / f"collection_checklist_{case_id}.json"
        with open(checklist_file, "w") as f:
            json.dump(checklist, f, indent=2)

        print(f"[+] Collection checklist for {len(target_hosts)} hosts: {checklist_file}")
        return checklist

    def analyze_collection_results(self, results_dir):
        """Analyze collected Velociraptor results for suspicious indicators."""
        results_path = Path(results_dir)
        findings = []

        for json_file in results_path.glob("**/*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        finding = self._check_for_indicators(item, str(json_file))
                        if finding:
                            findings.append(finding)
            except (json.JSONDecodeError, KeyError):
                continue

        findings_file = self.output_dir / "analysis_findings.json"
        with open(findings_file, "w") as f:
            json.dump(findings, f, indent=2, default=str)

        print(f"[+] Analysis complete: {len(findings)} findings -> {findings_file}")
        return findings

    def _check_for_indicators(self, item, source_file):
        """Check a single result item for suspicious indicators."""
        suspicious_processes = [
            "mimikatz", "rubeus", "lazagne", "sharphound", "bloodhound",
            "cobaltstrike", "beacon", "psexec", "wmiexec", "smbexec",
        ]
        suspicious_commands = [
            "invoke-mimikatz", "invoke-expression", "downloadstring",
            "net user /add", "net localgroup administrators",
            "reg save hklm\\sam", "reg save hklm\\system",
            "ntdsutil", "vssadmin create shadow",
        ]

        name = str(item.get("Name", "") or item.get("CommandLine", "")).lower()

        for proc in suspicious_processes:
            if proc in name:
                return {
                    "severity": "CRITICAL",
                    "indicator": f"Suspicious process: {proc}",
                    "detail": item,
                    "source": source_file,
                }

        for cmd in suspicious_commands:
            if cmd in name:
                return {
                    "severity": "HIGH",
                    "indicator": f"Suspicious command: {cmd}",
                    "detail": item,
                    "source": source_file,
                }

        return None

    def generate_report(self):
        """Generate collection summary report."""
        report = {
            "title": "Velociraptor IR Collection Report",
            "generated": datetime.utcnow().isoformat(),
            "collections": self.collection_manifest,
            "output_directory": str(self.output_dir),
        }

        report_file = self.output_dir / "collection_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[+] Collection report: {report_file}")
        return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Velociraptor IR Collection Manager")
    parser.add_argument("--action", choices=[
        "triage-pack", "hunt-config", "ioc-hunt", "checklist", "analyze",
    ], required=True)
    parser.add_argument("--os", default="windows", choices=["windows", "linux"])
    parser.add_argument("--case-id", default="IR-2025-001")
    parser.add_argument("--hosts", nargs="+", help="Target hostnames")
    parser.add_argument("--iocs", help="JSON file with IOCs")
    parser.add_argument("--results-dir", help="Directory with collection results")
    parser.add_argument("-o", "--output", default="velociraptor_results")

    args = parser.parse_args()
    collector = VelociraptorCollector(output_dir=args.output)

    if args.action == "triage-pack":
        collector.generate_vql_triage_pack(target_os=args.os)
    elif args.action == "hunt-config":
        collector.generate_hunt_config("IR Hunt", "Incident response hunt",
                                        collector.TRIAGE_ARTIFACTS_WINDOWS)
    elif args.action == "ioc-hunt":
        if args.iocs:
            with open(args.iocs) as f:
                iocs = json.load(f)
            collector.generate_ioc_hunt(iocs)
    elif args.action == "checklist":
        hosts = args.hosts or ["WKS001", "SRV001", "DC01"]
        collector.generate_collection_checklist(args.case_id, hosts)
    elif args.action == "analyze":
        if args.results_dir:
            collector.analyze_collection_results(args.results_dir)


if __name__ == "__main__":
    main()
