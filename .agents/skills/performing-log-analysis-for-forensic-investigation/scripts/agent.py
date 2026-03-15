#!/usr/bin/env python3
"""Agent for performing log analysis for forensic investigation.

Parses Windows EVTX, Linux syslog, and web access logs to build
correlated forensic timelines for incident investigations.
"""

import json
import sys
import csv
import re
from datetime import datetime
from collections import defaultdict
from pathlib import Path


class ForensicLogAnalyzer:
    """Analyzes and correlates logs for forensic investigations."""

    def __init__(self, case_id, output_dir):
        self.case_id = case_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events = []

    def parse_evtx(self, evtx_path):
        """Parse Windows EVTX event log files."""
        try:
            import Evtx.Evtx as evtx
            import xml.etree.ElementTree as ET
        except ImportError:
            print("Install python-evtx: pip install python-evtx")
            return []

        records = []
        target_ids = {"4624", "4625", "4648", "4672", "4688", "4697", "4698", "1102"}

        with evtx.Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    event_id = root.find(".//ns:EventID", ns).text
                    if event_id not in target_ids:
                        continue
                    time_elem = root.find(".//ns:TimeCreated", ns)
                    timestamp = time_elem.get("SystemTime") if time_elem is not None else ""
                    data_fields = {}
                    for data in root.findall(".//ns:Data", ns):
                        name = data.get("Name", "")
                        data_fields[name] = data.text or ""

                    event = {
                        "timestamp": timestamp,
                        "source": "Windows-Security",
                        "event_id": event_id,
                        "computer": data_fields.get("Computer", ""),
                        "user": data_fields.get("TargetUserName", ""),
                        "details": data_fields,
                    }
                    records.append(event)
                    self.events.append(event)
                except Exception:
                    continue
        return records

    def parse_syslog(self, log_path):
        """Parse Linux syslog/auth.log files."""
        records = []
        syslog_re = re.compile(
            r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)"
        )
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                match = syslog_re.match(line.strip())
                if match:
                    event = {
                        "timestamp": match.group(1),
                        "source": "Linux-Syslog",
                        "host": match.group(2),
                        "service": match.group(3),
                        "message": match.group(4),
                    }
                    records.append(event)
                    self.events.append(event)
        return records

    def parse_web_access_log(self, log_path):
        """Parse Apache/Nginx combined access log format."""
        records = []
        access_re = re.compile(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+)'
        )
        with open(log_path, "r", errors="ignore") as f:
            for line in f:
                match = access_re.match(line.strip())
                if match:
                    event = {
                        "timestamp": match.group(2),
                        "source": "Web-Access",
                        "client_ip": match.group(1),
                        "request": match.group(3),
                        "status": match.group(4),
                        "size": match.group(5),
                    }
                    records.append(event)
                    self.events.append(event)
        return records

    def detect_attack_patterns(self, web_events):
        """Detect common web attack patterns in access logs."""
        patterns = {
            "sql_injection": re.compile(r"(union.*select|or\s+1\s*=\s*1|drop\s+table)", re.I),
            "xss": re.compile(r"(<script|javascript:|onerror=|onload=)", re.I),
            "path_traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)", re.I),
            "command_injection": re.compile(r"(;\s*(ls|cat|wget|curl|nc)\b|`|\$\()", re.I),
        }
        findings = defaultdict(list)
        for event in web_events:
            request = event.get("request", "")
            for attack_type, pattern in patterns.items():
                if pattern.search(request):
                    findings[attack_type].append({
                        "timestamp": event["timestamp"],
                        "client_ip": event.get("client_ip", ""),
                        "request": request[:200],
                        "status": event.get("status", ""),
                    })
        return dict(findings)

    def detect_brute_force(self):
        """Detect brute force patterns in authentication events."""
        failed_by_source = defaultdict(lambda: {"count": 0, "users": set()})
        for event in self.events:
            if event.get("event_id") == "4625":
                src = event.get("details", {}).get("IpAddress", "unknown")
                user = event.get("user", "unknown")
                failed_by_source[src]["count"] += 1
                failed_by_source[src]["users"].add(user)

        return [
            {"source_ip": src, "failed_attempts": data["count"],
             "targeted_users": sorted(data["users"])}
            for src, data in failed_by_source.items()
            if data["count"] > 5
        ]

    def detect_log_clearing(self):
        """Detect audit log clearing events (anti-forensics)."""
        return [
            event for event in self.events
            if event.get("event_id") == "1102"
        ]

    def build_correlated_timeline(self):
        """Build a unified correlated timeline from all log sources."""
        sorted_events = sorted(self.events, key=lambda e: e.get("timestamp", ""))
        return sorted_events

    def generate_forensic_report(self):
        """Generate a comprehensive forensic log analysis report."""
        timeline = self.build_correlated_timeline()
        brute_force = self.detect_brute_force()
        log_clearing = self.detect_log_clearing()

        web_events = [e for e in self.events if e.get("source") == "Web-Access"]
        attack_patterns = self.detect_attack_patterns(web_events)

        source_counts = defaultdict(int)
        for event in self.events:
            source_counts[event.get("source", "unknown")] += 1

        report = {
            "case_id": self.case_id,
            "report_date": datetime.utcnow().isoformat(),
            "total_events": len(self.events),
            "source_breakdown": dict(source_counts),
            "brute_force_detections": brute_force,
            "log_clearing_events": log_clearing,
            "web_attack_patterns": {k: len(v) for k, v in attack_patterns.items()},
            "timeline_entries": len(timeline),
        }

        report_path = self.output_dir / f"{self.case_id}_log_analysis.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=list)

        timeline_path = self.output_dir / f"{self.case_id}_timeline.csv"
        if timeline:
            with open(timeline_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=list(timeline[0].keys()))
                writer.writeheader()
                for event in timeline[:10000]:
                    writer.writerow({k: str(v)[:200] for k, v in event.items()})

        print(json.dumps(report, indent=2, default=list))
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: agent.py <case_id> <output_dir> [evtx_file] [syslog_file] [access_log]")
        sys.exit(1)

    case_id = sys.argv[1]
    output_dir = sys.argv[2]
    analyzer = ForensicLogAnalyzer(case_id, output_dir)

    if len(sys.argv) > 3:
        analyzer.parse_evtx(sys.argv[3])
    if len(sys.argv) > 4:
        analyzer.parse_syslog(sys.argv[4])
    if len(sys.argv) > 5:
        analyzer.parse_web_access_log(sys.argv[5])

    analyzer.generate_forensic_report()


if __name__ == "__main__":
    main()
