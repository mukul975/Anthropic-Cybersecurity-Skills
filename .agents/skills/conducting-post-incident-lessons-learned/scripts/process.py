#!/usr/bin/env python3
"""
Post-Incident Lessons Learned Automation Script

Generates structured post-incident review reports including:
- Incident metrics calculation (MTTD, MTTC, MTTR)
- Timeline compilation
- Action item tracking
- Trend analysis across incidents

Requirements:
    pip install requests jinja2
"""

import argparse
import json
import logging
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("lessons_learned")


class IncidentMetrics:
    """Calculate incident response metrics from timeline data."""

    def __init__(self, timeline: dict):
        self.timeline = timeline
        self.fmt = "%Y-%m-%dT%H:%M:%S"

    def _parse(self, key: str) -> Optional[datetime]:
        val = self.timeline.get(key)
        if val:
            try:
                return datetime.strptime(val, self.fmt)
            except ValueError:
                return datetime.fromisoformat(val)
        return None

    def calculate(self) -> dict:
        compromise = self._parse("compromise_time")
        detection = self._parse("detection_time")
        triage = self._parse("triage_time")
        containment = self._parse("containment_time")
        eradication = self._parse("eradication_time")
        recovery = self._parse("recovery_time")
        closure = self._parse("closure_time")

        metrics = {}
        if compromise and detection:
            metrics["dwell_time_hours"] = round((detection - compromise).total_seconds() / 3600, 2)
        if detection and triage:
            metrics["mttd_minutes"] = round((triage - detection).total_seconds() / 60, 2)
        if detection and containment:
            metrics["mttc_hours"] = round((containment - detection).total_seconds() / 3600, 2)
        if eradication and recovery:
            metrics["mttr_hours"] = round((recovery - eradication).total_seconds() / 3600, 2)
        if containment and eradication:
            metrics["eradication_hours"] = round((eradication - containment).total_seconds() / 3600, 2)
        if detection and closure:
            metrics["total_duration_hours"] = round((closure - detection).total_seconds() / 3600, 2)
            metrics["total_duration_days"] = round(metrics["total_duration_hours"] / 24, 1)

        return metrics


class RootCauseAnalyzer:
    """Structure root cause analysis using 5 Whys technique."""

    def __init__(self):
        self.whys = []

    def add_why(self, question: str, answer: str):
        self.whys.append({"level": len(self.whys) + 1, "question": question, "answer": answer})

    def get_root_cause(self) -> str:
        if self.whys:
            return self.whys[-1]["answer"]
        return "Root cause not determined"

    def to_dict(self) -> dict:
        return {
            "method": "5 Whys",
            "analysis": self.whys,
            "root_cause": self.get_root_cause(),
        }


class LessonsLearnedReport:
    """Generate comprehensive post-incident lessons learned report."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.report = {
            "incident_id": incident_id,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "incident_summary": "",
            "timeline": {},
            "metrics": {},
            "what_worked": [],
            "what_failed": [],
            "root_cause_analysis": {},
            "action_items": [],
            "playbook_updates": [],
            "detection_improvements": [],
        }

    def set_summary(self, summary: str):
        self.report["incident_summary"] = summary

    def set_timeline(self, timeline: dict):
        self.report["timeline"] = timeline
        calculator = IncidentMetrics(timeline)
        self.report["metrics"] = calculator.calculate()

    def add_positive(self, item: str):
        self.report["what_worked"].append(item)

    def add_improvement(self, item: str):
        self.report["what_failed"].append(item)

    def set_root_cause(self, rca: RootCauseAnalyzer):
        self.report["root_cause_analysis"] = rca.to_dict()

    def add_action_item(self, title: str, owner: str, priority: str,
                        deadline: str, category: str):
        self.report["action_items"].append({
            "title": title,
            "owner": owner,
            "priority": priority,
            "deadline": deadline,
            "category": category,
            "status": "open",
        })

    def add_playbook_update(self, playbook: str, change: str):
        self.report["playbook_updates"].append({"playbook": playbook, "change": change})

    def add_detection_improvement(self, rule_name: str, description: str, technique: str):
        self.report["detection_improvements"].append({
            "rule_name": rule_name,
            "description": description,
            "mitre_technique": technique,
        })

    def generate_markdown(self) -> str:
        m = self.report["metrics"]
        md = f"# Post-Incident Lessons Learned Report\n\n"
        md += f"## Incident: {self.incident_id}\n"
        md += f"**Report Date:** {self.report['report_date']}\n\n"
        md += f"## Summary\n{self.report['incident_summary']}\n\n"

        md += f"## Response Metrics\n"
        md += f"| Metric | Value |\n|--------|-------|\n"
        for k, v in m.items():
            label = k.replace("_", " ").title()
            md += f"| {label} | {v} |\n"

        md += f"\n## What Worked Well\n"
        for item in self.report["what_worked"]:
            md += f"- {item}\n"

        md += f"\n## What Needs Improvement\n"
        for item in self.report["what_failed"]:
            md += f"- {item}\n"

        md += f"\n## Root Cause Analysis\n"
        rca = self.report["root_cause_analysis"]
        if rca:
            md += f"**Method:** {rca.get('method', 'N/A')}\n\n"
            for why in rca.get("analysis", []):
                md += f"**Why {why['level']}:** {why['question']}\n"
                md += f"  **Answer:** {why['answer']}\n\n"
            md += f"**Root Cause:** {rca.get('root_cause', 'N/A')}\n"

        md += f"\n## Action Items\n"
        md += f"| Title | Owner | Priority | Deadline | Status |\n"
        md += f"|-------|-------|----------|----------|--------|\n"
        for ai in self.report["action_items"]:
            md += f"| {ai['title']} | {ai['owner']} | {ai['priority']} | {ai['deadline']} | {ai['status']} |\n"

        return md

    def save(self, output_dir: str):
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, f"lessons_learned_{self.incident_id}.json")
        md_path = os.path.join(output_dir, f"lessons_learned_{self.incident_id}.md")

        with open(json_path, "w") as f:
            json.dump(self.report, f, indent=2)
        with open(md_path, "w") as f:
            f.write(self.generate_markdown())

        logger.info(f"Report saved: {json_path}")
        logger.info(f"Markdown saved: {md_path}")


class IncidentTrendAnalyzer:
    """Analyze trends across multiple incidents."""

    def __init__(self, incidents: list):
        self.incidents = incidents

    def analyze(self) -> dict:
        if not self.incidents:
            return {"error": "No incidents to analyze"}

        types = Counter(i.get("type", "unknown") for i in self.incidents)
        severities = Counter(i.get("severity", "unknown") for i in self.incidents)
        root_causes = Counter(i.get("root_cause_category", "unknown") for i in self.incidents)

        dwell_times = [i.get("dwell_time_hours", 0) for i in self.incidents if i.get("dwell_time_hours")]
        mttc_values = [i.get("mttc_hours", 0) for i in self.incidents if i.get("mttc_hours")]

        return {
            "total_incidents": len(self.incidents),
            "by_type": dict(types),
            "by_severity": dict(severities),
            "by_root_cause": dict(root_causes),
            "avg_dwell_time_hours": round(sum(dwell_times) / len(dwell_times), 2) if dwell_times else None,
            "avg_mttc_hours": round(sum(mttc_values) / len(mttc_values), 2) if mttc_values else None,
        }


def main():
    parser = argparse.ArgumentParser(description="Post-Incident Lessons Learned Generator")
    parser.add_argument("--incident-id", required=True, help="Incident ID")
    parser.add_argument("--summary", default="", help="Incident summary")
    parser.add_argument("--timeline-file", help="JSON file with incident timeline")
    parser.add_argument("--output-dir", default="./lessons_learned_output")

    args = parser.parse_args()

    report = LessonsLearnedReport(args.incident_id)
    report.set_summary(args.summary or f"Post-incident review for {args.incident_id}")

    if args.timeline_file and os.path.exists(args.timeline_file):
        with open(args.timeline_file) as f:
            timeline = json.load(f)
        report.set_timeline(timeline)
    else:
        logger.info("No timeline file provided. Create a JSON with keys: "
                     "compromise_time, detection_time, triage_time, containment_time, "
                     "eradication_time, recovery_time, closure_time")

    report.save(args.output_dir)
    print(f"Lessons learned report generated in: {args.output_dir}")


if __name__ == "__main__":
    main()
