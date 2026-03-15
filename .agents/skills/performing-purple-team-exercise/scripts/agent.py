#!/usr/bin/env python3
"""Agent for performing purple team exercises.

Coordinates red team technique execution with blue team detection
validation, tracks ATT&CK-mapped test results, and generates
detection coverage reports.
"""

import json
import sys
import subprocess
from datetime import datetime
from pathlib import Path


class PurpleTeamAgent:
    """Manages purple team exercise execution and tracking."""

    def __init__(self, exercise_id, output_dir):
        self.exercise_id = exercise_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.test_plan = []
        self.results = []

    def add_technique(self, attack_id, name, tool, expected_detection):
        """Add a technique to the test plan."""
        self.test_plan.append({
            "attack_id": attack_id,
            "name": name,
            "tool": tool,
            "expected_detection": expected_detection,
            "status": "pending",
        })

    def load_test_plan(self, plan_path):
        """Load test plan from a JSON file."""
        with open(plan_path, "r") as f:
            data = json.load(f)
            self.test_plan = data.get("techniques", [])

    def build_default_test_plan(self):
        """Build a default FIN7-style purple team test plan."""
        techniques = [
            ("T1059.001", "PowerShell Execution", "Atomic Red Team", "PowerShell alert"),
            ("T1053.005", "Scheduled Task", "Atomic Red Team", "Task creation alert"),
            ("T1547.001", "Registry Run Keys", "Atomic Red Team", "Registry modification alert"),
            ("T1003.001", "LSASS Memory Access", "Mimikatz", "Credential dumping alert"),
            ("T1550.002", "Pass-the-Hash", "Mimikatz", "NTLM anomaly detection"),
            ("T1021.002", "PsExec", "PsExec.exe", "PsExec service creation alert"),
            ("T1047", "WMI Execution", "wmic", "WMI remote execution alert"),
            ("T1021.001", "RDP Lateral Movement", "xfreerdp", "RDP lateral movement alert"),
            ("T1071.001", "Web C2 Channel", "C2 framework", "C2 beacon detection"),
            ("T1041", "Exfiltration over C2", "rclone", "Data exfiltration alert"),
            ("T1490", "Inhibit Recovery", "vssadmin", "Shadow copy deletion alert"),
            ("T1070.001", "Clear Event Logs", "wevtutil", "Log clearing detection"),
        ]
        for attack_id, name, tool, detection in techniques:
            self.add_technique(attack_id, name, tool, detection)

    def record_execution(self, attack_id, execution_time=None):
        """Record that a red team technique has been executed."""
        if execution_time is None:
            execution_time = datetime.utcnow().isoformat()
        for technique in self.test_plan:
            if technique["attack_id"] == attack_id:
                technique["execution_time"] = execution_time
                technique["status"] = "executed"
                break

    def record_detection(self, attack_id, detected, alert_name=None,
                         detection_time=None, notes=""):
        """Record blue team detection result for a technique."""
        if detection_time is None and detected:
            detection_time = datetime.utcnow().isoformat()

        for technique in self.test_plan:
            if technique["attack_id"] == attack_id:
                exec_time = technique.get("execution_time", "")
                latency = None
                if detected and exec_time and detection_time:
                    try:
                        t1 = datetime.fromisoformat(exec_time)
                        t2 = datetime.fromisoformat(detection_time)
                        latency = (t2 - t1).total_seconds()
                    except ValueError:
                        pass

                result = {
                    "attack_id": attack_id,
                    "name": technique["name"],
                    "detected": detected,
                    "alert_name": alert_name,
                    "execution_time": exec_time,
                    "detection_time": detection_time,
                    "latency_seconds": latency,
                    "notes": notes,
                    "status": "PASS" if detected else "FAIL",
                }
                self.results.append(result)
                technique["status"] = "detected" if detected else "gap"
                return result
        return None

    def get_coverage_metrics(self):
        """Calculate detection coverage metrics."""
        if not self.results:
            return {}

        total = len(self.results)
        detected = sum(1 for r in self.results if r["detected"])
        gaps = total - detected
        latencies = [r["latency_seconds"] for r in self.results
                     if r["latency_seconds"] is not None]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        return {
            "total_techniques": total,
            "detected": detected,
            "gaps": gaps,
            "coverage_pct": round(detected / total * 100, 1) if total else 0,
            "avg_latency_seconds": round(avg_latency, 1),
            "min_latency": round(min(latencies), 1) if latencies else None,
            "max_latency": round(max(latencies), 1) if latencies else None,
        }

    def get_gap_analysis(self):
        """Identify detection gaps requiring remediation."""
        return [
            {
                "attack_id": r["attack_id"],
                "name": r["name"],
                "notes": r["notes"],
                "remediation": f"Create detection rule for {r['name']}",
            }
            for r in self.results if not r["detected"]
        ]

    def generate_report(self):
        """Generate comprehensive purple team exercise report."""
        metrics = self.get_coverage_metrics()
        gaps = self.get_gap_analysis()

        report = {
            "exercise_id": self.exercise_id,
            "report_date": datetime.utcnow().isoformat(),
            "coverage_metrics": metrics,
            "detailed_results": self.results,
            "detection_gaps": gaps,
            "test_plan": self.test_plan,
        }

        report_path = self.output_dir / f"{self.exercise_id}_report.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"PURPLE TEAM EXERCISE REPORT - {self.exercise_id}")
        print("=" * 50)
        print(f"Techniques Tested:     {metrics.get('total_techniques', 0)}")
        print(f"Detected:              {metrics.get('detected', 0)} ({metrics.get('coverage_pct', 0)}%)")
        print(f"Gaps:                  {metrics.get('gaps', 0)}")
        print(f"Avg Detection Latency: {metrics.get('avg_latency_seconds', 0)}s")
        print(f"\nDetailed Results:")
        for r in self.results:
            status = "PASS" if r["detected"] else "FAIL"
            latency = f"{r['latency_seconds']}s" if r["latency_seconds"] else "N/A"
            print(f"  [{status}] {r['attack_id']} {r['name']} (Latency: {latency})")

        if gaps:
            print(f"\nDetection Gaps:")
            for g in gaps:
                print(f"  - {g['attack_id']} {g['name']}: {g['notes']}")

        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <exercise_id> [output_dir] [plan_file]")
        sys.exit(1)

    exercise_id = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./purple_team_output"

    agent = PurpleTeamAgent(exercise_id, output_dir)

    if len(sys.argv) > 3:
        agent.load_test_plan(sys.argv[3])
    else:
        agent.build_default_test_plan()

    print(json.dumps({"test_plan": agent.test_plan}, indent=2))
    print(f"\nTest plan created with {len(agent.test_plan)} techniques")
    print(f"Output directory: {output_dir}")


if __name__ == "__main__":
    main()
