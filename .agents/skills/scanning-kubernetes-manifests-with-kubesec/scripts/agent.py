#!/usr/bin/env python3
"""Agent for scanning Kubernetes manifests with Kubesec.

Runs Kubesec security risk analysis on K8s manifests, evaluates
security scores, identifies critical misconfigurations, and
enforces security baselines in CI/CD pipelines.
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime


class KubesecScanAgent:
    """Scans Kubernetes manifests using Kubesec for security risks."""

    def __init__(self, output_dir="./kubesec_scan"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_results = []

    def scan_manifest(self, manifest_path):
        """Scan a single Kubernetes manifest file."""
        cmd = ["kubesec", "scan", manifest_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            parsed = json.loads(result.stdout) if result.stdout.strip() else []
        except FileNotFoundError:
            return self._scan_via_api(manifest_path)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return {"error": "Kubesec scan failed", "file": manifest_path}

        findings = []
        for item in parsed:
            findings.append({
                "object": item.get("object", ""),
                "score": item.get("score", 0),
                "message": item.get("message", ""),
                "passed": [p.get("id") for p in item.get("scoring", {}).get("passed", [])],
                "advise": [
                    {"id": a.get("id"), "reason": a.get("reason"), "points": a.get("points")}
                    for a in item.get("scoring", {}).get("advise", [])
                ],
                "critical": [
                    {"id": c.get("id"), "reason": c.get("reason")}
                    for c in item.get("scoring", {}).get("critical", [])
                ],
            })

        scan = {
            "file": manifest_path,
            "scan_date": datetime.utcnow().isoformat(),
            "findings": findings,
        }
        self.scan_results.append(scan)
        return scan

    def _scan_via_api(self, manifest_path):
        """Fallback: scan via Kubesec public HTTP API."""
        try:
            import requests
            with open(manifest_path, "rb") as f:
                resp = requests.post("https://v2.kubesec.io/scan",
                                     data=f.read(), timeout=30)
            parsed = resp.json()
            findings = []
            for item in parsed:
                findings.append({
                    "object": item.get("object", ""),
                    "score": item.get("score", 0),
                    "message": item.get("message", ""),
                    "passed": [p.get("id") for p in item.get("scoring", {}).get("passed", [])],
                    "advise": [
                        {"id": a.get("id"), "reason": a.get("reason"), "points": a.get("points")}
                        for a in item.get("scoring", {}).get("advise", [])
                    ],
                    "critical": [
                        {"id": c.get("id"), "reason": c.get("reason")}
                        for c in item.get("scoring", {}).get("critical", [])
                    ],
                })
            scan = {"file": manifest_path, "scan_date": datetime.utcnow().isoformat(), "findings": findings}
            self.scan_results.append(scan)
            return scan
        except Exception as e:
            return {"error": f"API scan failed: {e}", "file": manifest_path}

    def scan_directory(self, dir_path):
        """Scan all YAML files in a directory."""
        p = Path(dir_path)
        results = []
        for f in sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")):
            results.append(self.scan_manifest(str(f)))
        return results

    def enforce_score_threshold(self, min_score=0):
        """Check if any manifests fail the minimum score threshold."""
        failures = []
        for scan in self.scan_results:
            for finding in scan.get("findings", []):
                if finding.get("score", 0) < min_score:
                    failures.append({
                        "file": scan["file"],
                        "object": finding["object"],
                        "score": finding["score"],
                    })
                if finding.get("critical"):
                    failures.append({
                        "file": scan["file"],
                        "object": finding["object"],
                        "critical_issues": finding["critical"],
                    })
        return {"gate": "FAILED" if failures else "PASSED", "failures": failures}

    def generate_report(self):
        gate = self.enforce_score_threshold(min_score=0)
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "manifests_scanned": len(self.scan_results),
            "scans": self.scan_results,
            "quality_gate": gate,
        }
        out = self.output_dir / "kubesec_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <manifest.yaml|directory> [--min-score 0]")
        sys.exit(1)

    target = sys.argv[1]
    min_score = 0
    if "--min-score" in sys.argv:
        min_score = int(sys.argv[sys.argv.index("--min-score") + 1])

    agent = KubesecScanAgent()
    if Path(target).is_dir():
        agent.scan_directory(target)
    else:
        agent.scan_manifest(target)

    report = agent.generate_report()
    gate = agent.enforce_score_threshold(min_score)
    if gate["gate"] == "FAILED":
        sys.exit(1)


if __name__ == "__main__":
    main()
