#!/usr/bin/env python3
"""
XSOAR Playbook Builder and Validator

Generates XSOAR-compatible playbook YAML structures,
validates playbook logic, and tracks automation metrics.
"""

import json
import yaml
from datetime import datetime
from typing import Optional


class PlaybookTask:
    """Represents a single task in an XSOAR playbook."""

    def __init__(
        self,
        task_id: str,
        name: str,
        task_type: str = "regular",
        script: Optional[str] = None,
        playbook_name: Optional[str] = None,
        conditions: Optional[list] = None,
        next_tasks: Optional[dict] = None,
        script_arguments: Optional[dict] = None,
    ):
        self.task_id = task_id
        self.name = name
        self.task_type = task_type  # start, regular, condition, playbook, manual, title
        self.script = script
        self.playbook_name = playbook_name
        self.conditions = conditions or []
        self.next_tasks = next_tasks or {}
        self.script_arguments = script_arguments or {}

    def to_dict(self) -> dict:
        task = {
            "id": self.task_id,
            "taskid": self.task_id,
            "type": self.task_type,
            "task": {"name": self.name},
            "nexttasks": self.next_tasks,
        }
        if self.script:
            task["task"]["script"] = self.script
        if self.playbook_name:
            task["task"]["playbookName"] = self.playbook_name
        if self.conditions:
            task["conditions"] = self.conditions
        if self.script_arguments:
            task["scriptarguments"] = self.script_arguments
        return task


class XSOARPlaybook:
    """Represents a complete XSOAR playbook."""

    def __init__(self, name: str, description: str, incident_type: str):
        self.name = name
        self.description = description
        self.incident_type = incident_type
        self.tasks = {}
        self.start_task_id = "0"
        self.version = -1

    def add_task(self, task: PlaybookTask):
        self.tasks[task.task_id] = task

    def validate(self) -> dict:
        """Validate playbook structure and logic."""
        issues = []

        # Check start task exists
        if self.start_task_id not in self.tasks:
            issues.append("ERROR: Start task not found")

        # Check all referenced next tasks exist
        for task_id, task in self.tasks.items():
            for label, next_ids in task.next_tasks.items():
                for next_id in next_ids:
                    if next_id not in self.tasks:
                        issues.append(f"ERROR: Task {task_id} references non-existent task {next_id}")

        # Check for orphaned tasks (not reachable from start)
        reachable = set()
        queue = [self.start_task_id]
        while queue:
            current = queue.pop(0)
            if current in reachable:
                continue
            reachable.add(current)
            if current in self.tasks:
                for next_ids in self.tasks[current].next_tasks.values():
                    queue.extend(next_ids)

        orphaned = set(self.tasks.keys()) - reachable
        for orphan in orphaned:
            issues.append(f"WARNING: Task {orphan} ({self.tasks[orphan].name}) is not reachable")

        # Check conditional tasks have conditions
        for task_id, task in self.tasks.items():
            if task.task_type == "condition" and not task.conditions:
                issues.append(f"WARNING: Conditional task {task_id} has no conditions defined")

        # Check for manual review gates before destructive actions
        destructive_keywords = ["isolate", "block", "delete", "disable", "purge", "quarantine"]
        for task_id, task in self.tasks.items():
            if task.script and any(kw in task.script.lower() for kw in destructive_keywords):
                # Check if preceding task is manual
                has_manual_gate = False
                for other_id, other_task in self.tasks.items():
                    for next_ids in other_task.next_tasks.values():
                        if task_id in next_ids and other_task.task_type == "manual":
                            has_manual_gate = True
                if not has_manual_gate:
                    issues.append(
                        f"INFO: Destructive task {task_id} ({task.name}) "
                        f"has no manual approval gate"
                    )

        return {
            "playbook_name": self.name,
            "valid": not any(i.startswith("ERROR") for i in issues),
            "total_tasks": len(self.tasks),
            "reachable_tasks": len(reachable),
            "orphaned_tasks": len(orphaned),
            "issues": issues,
        }

    def to_yaml(self) -> str:
        playbook_dict = {
            "id": self.name.lower().replace(" ", "-"),
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "starttaskid": self.start_task_id,
            "tasks": {tid: t.to_dict() for tid, t in self.tasks.items()},
        }
        return yaml.dump(playbook_dict, default_flow_style=False, sort_keys=False)


class SOARMetrics:
    """Track SOAR playbook performance metrics."""

    def __init__(self):
        self.executions = []

    def add_execution(
        self,
        playbook_name: str,
        incident_type: str,
        duration_seconds: int,
        manual_duration_seconds: int,
        tasks_automated: int,
        tasks_manual: int,
        success: bool,
    ):
        self.executions.append({
            "playbook_name": playbook_name,
            "incident_type": incident_type,
            "duration_seconds": duration_seconds,
            "manual_duration_seconds": manual_duration_seconds,
            "tasks_automated": tasks_automated,
            "tasks_manual": tasks_manual,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def calculate_roi(self, analyst_hourly_rate: float = 75.0) -> dict:
        total_manual_time = sum(e["manual_duration_seconds"] for e in self.executions)
        total_automated_time = sum(e["duration_seconds"] for e in self.executions)
        saved_seconds = total_manual_time - total_automated_time
        saved_hours = saved_seconds / 3600

        return {
            "total_executions": len(self.executions),
            "total_manual_time_hours": round(total_manual_time / 3600, 1),
            "total_automated_time_hours": round(total_automated_time / 3600, 1),
            "time_saved_hours": round(saved_hours, 1),
            "cost_savings": round(saved_hours * analyst_hourly_rate, 2),
            "automation_rate": round(
                sum(e["tasks_automated"] for e in self.executions)
                / max(1, sum(e["tasks_automated"] + e["tasks_manual"] for e in self.executions))
                * 100, 1
            ),
            "success_rate": round(
                sum(1 for e in self.executions if e["success"]) / max(1, len(self.executions)) * 100, 1
            ),
        }


def build_phishing_playbook() -> XSOARPlaybook:
    """Build a sample phishing investigation playbook."""
    pb = XSOARPlaybook(
        "Phishing Investigation",
        "Automated phishing email investigation with enrichment and response",
        "Phishing",
    )

    pb.add_task(PlaybookTask("0", "Start", "start", next_tasks={"#none#": ["1"]}))
    pb.add_task(PlaybookTask("1", "Extract Indicators from Email", "regular",
                             script="ParseEmailFiles", next_tasks={"#none#": ["2", "3", "4"]}))
    pb.add_task(PlaybookTask("2", "URL Enrichment", "playbook",
                             playbook_name="URL Enrichment - Generic v2", next_tasks={"#none#": ["5"]}))
    pb.add_task(PlaybookTask("3", "File Enrichment", "playbook",
                             playbook_name="File Enrichment - Generic v2", next_tasks={"#none#": ["5"]}))
    pb.add_task(PlaybookTask("4", "IP Enrichment", "playbook",
                             playbook_name="IP Enrichment - Generic v2", next_tasks={"#none#": ["5"]}))
    pb.add_task(PlaybookTask("5", "Is Email Malicious?", "condition",
                             conditions=[{"label": "yes", "operator": "isEqualString", "left": "DBotScore.Score", "right": "3"}],
                             next_tasks={"yes": ["6"], "no": ["9"]}))
    pb.add_task(PlaybookTask("6", "Approve Containment", "manual", next_tasks={"#none#": ["7"]}))
    pb.add_task(PlaybookTask("7", "Block Sender and Purge Emails", "regular",
                             script="o365-mail-block-sender", next_tasks={"#none#": ["8"]}))
    pb.add_task(PlaybookTask("8", "Notify User", "regular",
                             script="send-mail", next_tasks={"#none#": ["9"]}))
    pb.add_task(PlaybookTask("9", "Close Incident", "regular", script="closeInvestigation"))

    return pb


if __name__ == "__main__":
    playbook = build_phishing_playbook()

    print("=" * 70)
    print("XSOAR PLAYBOOK VALIDATOR")
    print("=" * 70)

    validation = playbook.validate()
    print(f"\nPlaybook: {validation['playbook_name']}")
    print(f"Valid: {validation['valid']}")
    print(f"Total Tasks: {validation['total_tasks']}")
    print(f"Reachable Tasks: {validation['reachable_tasks']}")
    for issue in validation["issues"]:
        print(f"  {issue}")

    print(f"\n{'=' * 70}")
    print("GENERATED PLAYBOOK YAML")
    print("=" * 70)
    print(playbook.to_yaml())

    # Simulate metrics
    metrics = SOARMetrics()
    metrics.add_execution("Phishing Investigation", "Phishing", 300, 2700, 8, 1, True)
    metrics.add_execution("Phishing Investigation", "Phishing", 240, 2700, 8, 1, True)
    metrics.add_execution("Phishing Investigation", "Phishing", 360, 2700, 7, 2, True)
    metrics.add_execution("Phishing Investigation", "Phishing", 280, 2700, 8, 1, False)

    print(f"\n{'=' * 70}")
    print("SOAR ROI METRICS")
    print("=" * 70)
    roi = metrics.calculate_roi()
    for key, value in roi.items():
        print(f"  {key}: {value}")
