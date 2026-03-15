#!/usr/bin/env python3
"""Agent for securing GitHub Actions workflows.

Audits GitHub Actions workflow files for security issues including
unpinned actions, excessive permissions, script injection risks,
dangerous triggers, and missing secret protections.
"""

import json
import re
import sys
from pathlib import Path
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None


class GitHubActionsSecurityAgent:
    """Audits GitHub Actions workflows for security vulnerabilities."""

    def __init__(self, repo_path=".", output_dir="./gha_audit"):
        self.repo_path = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _load_workflow(self, path):
        if yaml:
            with open(path) as f:
                return yaml.safe_load(f)
        with open(path) as f:
            return {"raw": f.read()}

    def find_workflows(self):
        """Discover all workflow files in the repository."""
        wf_dir = self.repo_path / ".github" / "workflows"
        if not wf_dir.exists():
            return []
        return sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))

    def check_sha_pinning(self, workflow_path, content):
        """Check if actions are pinned to SHA digests."""
        unpinned = []
        raw = content.get("raw", "") if "raw" in content else ""
        if not raw:
            try:
                raw = Path(workflow_path).read_text()
            except Exception:
                return unpinned

        for line_num, line in enumerate(raw.splitlines(), 1):
            m = re.search(r'uses:\s+([^@\s]+)@([^\s#]+)', line)
            if m:
                action, ref = m.group(1), m.group(2)
                if not re.match(r'^[a-f0-9]{40}$', ref):
                    unpinned.append({
                        "action": action,
                        "ref": ref,
                        "line": line_num,
                        "file": str(workflow_path),
                    })
                    self.findings.append({
                        "severity": "medium",
                        "type": "Unpinned Action",
                        "detail": f"{action}@{ref} at line {line_num}",
                        "file": str(workflow_path),
                    })
        return unpinned

    def check_permissions(self, workflow_path, content):
        """Check for overly permissive GITHUB_TOKEN permissions."""
        issues = []
        if not isinstance(content, dict) or "raw" in content:
            return issues

        top_perms = content.get("permissions")
        if top_perms is None:
            issues.append({
                "issue": "No top-level permissions defined (inherits defaults)",
                "file": str(workflow_path),
            })
            self.findings.append({
                "severity": "medium",
                "type": "Missing Permissions",
                "detail": "Workflow has no permissions block",
                "file": str(workflow_path),
            })

        if top_perms == "write-all" or (isinstance(top_perms, dict) and
                top_perms.get("contents") == "write" and
                top_perms.get("actions") == "write"):
            issues.append({"issue": "Overly permissive write-all", "file": str(workflow_path)})
            self.findings.append({
                "severity": "high",
                "type": "Excessive Permissions",
                "detail": "write-all permissions granted",
                "file": str(workflow_path),
            })

        return issues

    def check_script_injection(self, workflow_path, content):
        """Check for user-controlled input in run steps (script injection)."""
        injections = []
        raw = content.get("raw", "") if "raw" in content else ""
        if not raw:
            try:
                raw = Path(workflow_path).read_text()
            except Exception:
                return injections

        dangerous_contexts = [
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.issue.title",
            "github.event.issue.body",
            "github.event.comment.body",
            "github.event.review.body",
            "github.head_ref",
        ]

        in_run = False
        for line_num, line in enumerate(raw.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("run:") or stripped.startswith("run: |"):
                in_run = True
            elif in_run and not stripped.startswith("-") and not stripped.startswith("#"):
                for ctx in dangerous_contexts:
                    if f"${{{{ {ctx}" in line or f"${{{{{ctx}" in line:
                        injections.append({
                            "context": ctx,
                            "line": line_num,
                            "file": str(workflow_path),
                        })
                        self.findings.append({
                            "severity": "high",
                            "type": "Script Injection",
                            "detail": f"{ctx} in run step at line {line_num}",
                            "file": str(workflow_path),
                        })
            if stripped and not stripped.startswith("-") and not stripped.startswith("#") and ":" in stripped and not stripped.startswith("run"):
                in_run = False

        return injections

    def check_dangerous_triggers(self, workflow_path, content):
        """Check for dangerous event triggers."""
        issues = []
        if not isinstance(content, dict) or "raw" in content:
            raw = content.get("raw", "")
            if "pull_request_target" in raw:
                issues.append({"trigger": "pull_request_target", "file": str(workflow_path)})
                self.findings.append({
                    "severity": "high",
                    "type": "Dangerous Trigger",
                    "detail": "pull_request_target allows fork code to run with base permissions",
                    "file": str(workflow_path),
                })
            return issues

        on_block = content.get("on", content.get(True, {}))
        if isinstance(on_block, dict) and "pull_request_target" in on_block:
            issues.append({"trigger": "pull_request_target", "file": str(workflow_path)})
            self.findings.append({
                "severity": "high",
                "type": "Dangerous Trigger",
                "detail": "pull_request_target trigger used",
                "file": str(workflow_path),
            })
        return issues

    def audit_all(self):
        """Run all security checks on all workflow files."""
        workflows = self.find_workflows()
        results = []
        for wf in workflows:
            content = self._load_workflow(wf)
            unpinned = self.check_sha_pinning(wf, content)
            perms = self.check_permissions(wf, content)
            injections = self.check_script_injection(wf, content)
            triggers = self.check_dangerous_triggers(wf, content)
            results.append({
                "workflow": str(wf),
                "unpinned_actions": len(unpinned),
                "permission_issues": len(perms),
                "script_injections": len(injections),
                "dangerous_triggers": len(triggers),
            })
        return results

    def generate_report(self):
        audit = self.audit_all()
        report = {
            "report_date": datetime.utcnow().isoformat(),
            "repository": str(self.repo_path),
            "workflows_scanned": len(audit),
            "audit_summary": audit,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "gha_security_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    agent = GitHubActionsSecurityAgent(repo)
    agent.generate_report()


if __name__ == "__main__":
    main()
