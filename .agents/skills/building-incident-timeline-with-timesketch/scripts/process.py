"""
Timesketch Timeline Builder Script
Automates creation, import, and analysis of forensic timelines in Timesketch.
"""

import json
import csv
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path


class TimesketchTimelineBuilder:
    """Builds and manages forensic timelines using Timesketch."""

    PLASO_PARSER_SETS = {
        "quick_triage": "winevtx,prefetch,chrome_history,firefox_history",
        "windows_full": "winevtx,prefetch,amcache,shimcache,userassist,mft,winreg,recycler,lnk",
        "linux_full": "syslog,utmp,bash_history,cron,dpkg,selinux",
        "network_focused": "winevtx,syslog",
        "cloud_focused": "jsonl",
    }

    SIGMA_CATEGORIES = {
        "lateral_movement": [
            "event_identifier:4624 AND LogonType:3",
            "event_identifier:4624 AND LogonType:10",
            "event_identifier:5140",
        ],
        "privilege_escalation": [
            "event_identifier:4672",
            "event_identifier:4728",
            "event_identifier:4732",
        ],
        "execution": [
            "event_identifier:4688",
            "event_identifier:4104",
            "data_type:windows:prefetch:execution",
        ],
        "persistence": [
            "event_identifier:7045",
            "event_identifier:4698",
            "data_type:windows:registry:key_value",
        ],
        "credential_access": [
            "event_identifier:4768",
            "event_identifier:4769",
            "event_identifier:4776",
        ],
    }

    def __init__(self, timesketch_url=None, output_dir="timeline_output"):
        self.timesketch_url = timesketch_url or "https://localhost"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timelines = []
        self.events = []

    def process_evidence_with_plaso(self, evidence_path, output_plaso, parser_set="quick_triage"):
        """Run log2timeline (Plaso) to process evidence into timeline format."""
        parsers = self.PLASO_PARSER_SETS.get(parser_set, parser_set)

        cmd = [
            "log2timeline.py",
            "--parsers", parsers,
            "--storage-file", str(output_plaso),
            str(evidence_path),
        ]

        print(f"[*] Running Plaso with parsers: {parsers}")
        print(f"[*] Evidence: {evidence_path}")
        print(f"[*] Output: {output_plaso}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if result.returncode == 0:
                print("[+] Plaso processing completed successfully")
                return True
            else:
                print(f"[!] Plaso error: {result.stderr[:500]}")
                return False
        except FileNotFoundError:
            print("[!] log2timeline.py not found. Install Plaso: pip install plaso")
            return False
        except subprocess.TimeoutExpired:
            print("[!] Plaso processing timed out after 1 hour")
            return False

    def convert_evtx_to_csv(self, evtx_dir, output_csv):
        """Convert Windows event logs to CSV format for direct Timesketch import."""
        events = []

        for evtx_file in Path(evtx_dir).glob("*.evtx"):
            print(f"[*] Processing: {evtx_file.name}")
            # This would use python-evtx library in practice
            # Placeholder for EVTX parsing logic

        # Write CSV in Timesketch format
        fieldnames = ["message", "datetime", "timestamp_desc", "source_short", "hostname", "tag"]

        with open(output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for event in events:
                writer.writerow(event)

        print(f"[+] Wrote {len(events)} events to {output_csv}")
        return output_csv

    def create_csv_timeline_from_logs(self, log_entries, timeline_name):
        """Create a Timesketch-compatible CSV from structured log entries."""
        output_file = self.output_dir / f"{timeline_name}.csv"

        fieldnames = [
            "message", "datetime", "timestamp_desc",
            "source_short", "hostname", "tag",
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for entry in log_entries:
                row = {
                    "message": entry.get("message", ""),
                    "datetime": entry.get("datetime", ""),
                    "timestamp_desc": entry.get("timestamp_desc", "Event Recorded"),
                    "source_short": entry.get("source", ""),
                    "hostname": entry.get("hostname", ""),
                    "tag": entry.get("tag", ""),
                }
                writer.writerow(row)

        print(f"[+] Created timeline CSV: {output_file} ({len(log_entries)} events)")
        self.timelines.append({"name": timeline_name, "file": str(output_file)})
        return str(output_file)

    def create_jsonl_timeline(self, events, timeline_name):
        """Create a Timesketch-compatible JSONL timeline."""
        output_file = self.output_dir / f"{timeline_name}.jsonl"

        with open(output_file, "w", encoding="utf-8") as f:
            for event in events:
                jsonl_event = {
                    "message": event.get("message", ""),
                    "datetime": event.get("datetime", ""),
                    "timestamp_desc": event.get("timestamp_desc", "Event Recorded"),
                    "source_short": event.get("source", ""),
                    "hostname": event.get("hostname", ""),
                }
                # Include any additional fields
                for key, value in event.items():
                    if key not in jsonl_event:
                        jsonl_event[key] = value

                f.write(json.dumps(jsonl_event) + "\n")

        print(f"[+] Created JSONL timeline: {output_file} ({len(events)} events)")
        self.timelines.append({"name": timeline_name, "file": str(output_file)})
        return str(output_file)

    def import_to_timesketch(self, sketch_name, timeline_file, timeline_name):
        """Import timeline file into Timesketch using the CLI importer."""
        cmd = [
            "timesketch_importer",
            "-s", sketch_name,
            "-t", timeline_name,
            str(timeline_file),
        ]

        print(f"[*] Importing {timeline_name} into sketch '{sketch_name}'")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                print(f"[+] Successfully imported {timeline_name}")
                return True
            else:
                print(f"[!] Import error: {result.stderr[:500]}")
                return False
        except FileNotFoundError:
            print("[!] timesketch_importer not found. Install: pip install timesketch-import-client")
            return False

    def generate_search_queries(self, iocs=None):
        """Generate Timesketch search queries for common investigation patterns."""
        queries = {}

        # Standard investigation queries
        queries["lateral_movement"] = {
            "query": 'event_identifier:4624 AND xml_string:"LogonType\\">3"',
            "description": "Network logons indicating lateral movement",
        }
        queries["rdp_sessions"] = {
            "query": 'event_identifier:4624 AND xml_string:"LogonType\\">10"',
            "description": "RDP logon sessions",
        }
        queries["powershell_execution"] = {
            "query": "event_identifier:4104 OR event_identifier:4103",
            "description": "PowerShell script block logging events",
        }
        queries["process_creation"] = {
            "query": "event_identifier:4688",
            "description": "New process creation events",
        }
        queries["service_installation"] = {
            "query": "event_identifier:7045",
            "description": "New service installations",
        }
        queries["scheduled_tasks"] = {
            "query": "event_identifier:4698 OR event_identifier:4702",
            "description": "Scheduled task creation and modification",
        }
        queries["privilege_escalation"] = {
            "query": "event_identifier:4672",
            "description": "Special privileges assigned to new logon",
        }
        queries["account_changes"] = {
            "query": "event_identifier:4720 OR event_identifier:4722 OR event_identifier:4738",
            "description": "User account creation and modification",
        }
        queries["group_membership"] = {
            "query": "event_identifier:4728 OR event_identifier:4732 OR event_identifier:4756",
            "description": "Security group membership changes",
        }
        queries["file_access"] = {
            "query": 'data_type:"fs:stat"',
            "description": "File system activity",
        }

        # IOC-specific queries
        if iocs:
            for ioc_type, values in iocs.items():
                for value in values:
                    key = f"ioc_{ioc_type}_{value[:20]}"
                    queries[key] = {
                        "query": f'"{value}"',
                        "description": f"IOC search: {ioc_type} = {value}",
                    }

        # Save queries
        query_file = self.output_dir / "investigation_queries.json"
        with open(query_file, "w") as f:
            json.dump(queries, f, indent=2)

        print(f"[+] Generated {len(queries)} search queries -> {query_file}")
        return queries

    def build_attack_narrative(self, findings):
        """Build structured attack narrative from investigation findings."""
        narrative = {
            "title": "Attack Timeline Narrative",
            "generated": datetime.utcnow().isoformat(),
            "phases": [],
        }

        attack_phases = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Exfiltration",
            "Impact",
        ]

        for phase in attack_phases:
            phase_findings = [f for f in findings if f.get("mitre_tactic") == phase]
            if phase_findings:
                narrative["phases"].append({
                    "tactic": phase,
                    "events": sorted(phase_findings, key=lambda x: x.get("datetime", "")),
                })

        narrative_file = self.output_dir / "attack_narrative.json"
        with open(narrative_file, "w") as f:
            json.dump(narrative, f, indent=2, default=str)

        print(f"[+] Attack narrative saved to {narrative_file}")
        return narrative

    def generate_timeline_report(self):
        """Generate summary report of all timelines and analysis."""
        report = {
            "report_title": "Forensic Timeline Analysis Report",
            "generated": datetime.utcnow().isoformat(),
            "timelines_processed": len(self.timelines),
            "timelines": self.timelines,
            "total_events": len(self.events),
            "analysis_queries": str(self.output_dir / "investigation_queries.json"),
        }

        report_file = self.output_dir / "timeline_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Timeline report saved to {report_file}")
        return report


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Timesketch Timeline Builder - Forensic Timeline Creation Tool"
    )
    parser.add_argument(
        "--evidence", "-e",
        help="Path to evidence directory or disk image",
    )
    parser.add_argument(
        "--parsers", "-p",
        default="quick_triage",
        choices=["quick_triage", "windows_full", "linux_full", "network_focused"],
        help="Plaso parser set to use",
    )
    parser.add_argument(
        "--sketch", "-s",
        default="Investigation",
        help="Timesketch sketch name",
    )
    parser.add_argument(
        "--output", "-o",
        default="timeline_output",
        help="Output directory",
    )
    parser.add_argument(
        "--iocs",
        help="JSON file with IOCs to search for",
    )

    args = parser.parse_args()

    builder = TimesketchTimelineBuilder(output_dir=args.output)

    if args.evidence:
        plaso_output = Path(args.output) / "evidence.plaso"
        builder.process_evidence_with_plaso(args.evidence, plaso_output, args.parsers)

    iocs = None
    if args.iocs:
        with open(args.iocs) as f:
            iocs = json.load(f)

    builder.generate_search_queries(iocs=iocs)
    builder.generate_timeline_report()


if __name__ == "__main__":
    main()
