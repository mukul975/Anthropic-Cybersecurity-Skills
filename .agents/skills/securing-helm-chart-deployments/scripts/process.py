#!/usr/bin/env python3
"""
Helm Chart Security Scanner - Render Helm templates and scan
for security misconfigurations in Kubernetes manifests.
"""

import json
import subprocess
import sys
import argparse
import re
from pathlib import Path


SECURITY_CHECKS = [
    {
        "id": "HELM-001",
        "name": "Container runs as root",
        "severity": "HIGH",
        "pattern": r"runAsNonRoot:\s*false|runAsUser:\s*0",
        "remediation": "Set securityContext.runAsNonRoot: true and runAsUser to non-zero",
    },
    {
        "id": "HELM-002",
        "name": "Privileged container",
        "severity": "CRITICAL",
        "pattern": r"privileged:\s*true",
        "remediation": "Set securityContext.privileged: false",
    },
    {
        "id": "HELM-003",
        "name": "Allow privilege escalation",
        "severity": "HIGH",
        "pattern": r"allowPrivilegeEscalation:\s*true",
        "remediation": "Set securityContext.allowPrivilegeEscalation: false",
    },
    {
        "id": "HELM-004",
        "name": "No resource limits",
        "severity": "MEDIUM",
        "pattern": r"resources:\s*\{\}|resources:\s*null",
        "remediation": "Set resources.limits.cpu and resources.limits.memory",
    },
    {
        "id": "HELM-005",
        "name": "Uses latest image tag",
        "severity": "MEDIUM",
        "pattern": r"image:.*:latest|image:\s*[^:]+\s*$",
        "remediation": "Use specific image tag or digest instead of :latest",
    },
    {
        "id": "HELM-006",
        "name": "HostPath volume mount",
        "severity": "HIGH",
        "pattern": r"hostPath:",
        "remediation": "Avoid hostPath volumes; use PersistentVolumeClaim instead",
    },
    {
        "id": "HELM-007",
        "name": "Host network enabled",
        "severity": "HIGH",
        "pattern": r"hostNetwork:\s*true",
        "remediation": "Set hostNetwork: false",
    },
    {
        "id": "HELM-008",
        "name": "Host PID namespace",
        "severity": "HIGH",
        "pattern": r"hostPID:\s*true",
        "remediation": "Set hostPID: false",
    },
    {
        "id": "HELM-009",
        "name": "Service account token auto-mounted",
        "severity": "MEDIUM",
        "pattern": r"automountServiceAccountToken:\s*true",
        "remediation": "Set automountServiceAccountToken: false unless needed",
    },
    {
        "id": "HELM-010",
        "name": "Writable root filesystem",
        "severity": "MEDIUM",
        "pattern": r"readOnlyRootFilesystem:\s*false",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true",
    },
]


def render_chart(chart_path: str, values_file: str = None, release_name: str = "scan") -> str:
    """Render Helm chart templates."""
    cmd = ["helm", "template", release_name, chart_path]
    if values_file:
        cmd.extend(["-f", values_file])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Helm template error: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout


def scan_rendered(content: str) -> list:
    """Scan rendered YAML for security issues."""
    findings = []
    lines = content.split("\n")
    for check in SECURITY_CHECKS:
        for i, line in enumerate(lines, 1):
            if re.search(check["pattern"], line):
                findings.append({
                    "id": check["id"],
                    "name": check["name"],
                    "severity": check["severity"],
                    "line": i,
                    "content": line.strip(),
                    "remediation": check["remediation"],
                })
    return findings


def lint_chart(chart_path: str) -> dict:
    """Run helm lint on chart."""
    result = subprocess.run(
        ["helm", "lint", chart_path, "--strict"],
        capture_output=True, text=True,
    )
    return {
        "passed": result.returncode == 0,
        "output": result.stdout + result.stderr,
    }


def generate_report(findings: list, chart_path: str) -> str:
    """Generate security scan report."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    report = f"""# Helm Chart Security Scan Report

**Chart:** `{chart_path}`
**Findings:** {len(findings)}

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | {severity_counts['CRITICAL']} |
| HIGH | {severity_counts['HIGH']} |
| MEDIUM | {severity_counts['MEDIUM']} |
| LOW | {severity_counts['LOW']} |

## Findings

| ID | Severity | Finding | Line | Remediation |
|----|----------|---------|------|-------------|
"""
    for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[x["severity"]]):
        report += f"| {f['id']} | {f['severity']} | {f['name']} | {f['line']} | {f['remediation']} |\n"

    return report


def main():
    parser = argparse.ArgumentParser(description="Helm Chart Security Scanner")
    parser.add_argument("chart", help="Path to Helm chart")
    parser.add_argument("--values", "-f", help="Values file path")
    parser.add_argument("--report", "-r", help="Output report file")
    parser.add_argument("--lint", action="store_true", help="Run helm lint")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium"],
                       default="high", help="Fail threshold")

    args = parser.parse_args()

    if args.lint:
        lint_result = lint_chart(args.chart)
        print(lint_result["output"])
        if not lint_result["passed"]:
            print("Lint FAILED")
            sys.exit(1)

    rendered = render_chart(args.chart, args.values)
    findings = scan_rendered(rendered)
    report = generate_report(findings, args.chart)

    if args.report:
        Path(args.report).write_text(report)
        print(f"Report written to {args.report}")
    else:
        print(report)

    threshold = {"critical": ["CRITICAL"], "high": ["CRITICAL", "HIGH"],
                 "medium": ["CRITICAL", "HIGH", "MEDIUM"]}
    blocking = [f for f in findings if f["severity"] in threshold[args.fail_on]]
    if blocking:
        print(f"\nFAILED: {len(blocking)} findings at or above {args.fail_on} severity")
        sys.exit(1)


if __name__ == "__main__":
    main()
