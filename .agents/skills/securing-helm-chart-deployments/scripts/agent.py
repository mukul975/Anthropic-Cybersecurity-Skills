#!/usr/bin/env python3
"""Agent for securing Helm chart deployments.

Validates chart provenance, renders and scans templates for
security misconfigurations, checks security contexts, and
enforces Helm deployment security baselines.
"""

import json
import subprocess
import sys
import re
from pathlib import Path
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None


class HelmSecurityAgent:
    """Audits Helm chart deployments for security issues."""

    def __init__(self, chart_path, output_dir="./helm_audit"):
        self.chart_path = Path(chart_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.findings = []

    def _run(self, cmd, timeout=60):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            return "", str(e), -1

    def lint_chart(self, values_file=None):
        """Run helm lint with strict mode."""
        cmd = ["helm", "lint", str(self.chart_path), "--strict"]
        if values_file:
            cmd.extend(["--values", values_file])
        stdout, stderr, rc = self._run(cmd)
        if rc != 0:
            self.findings.append({
                "severity": "medium",
                "type": "Lint Failure",
                "detail": stderr.strip() or stdout.strip(),
            })
        return {"returncode": rc, "output": stdout.strip(), "errors": stderr.strip()}

    def render_templates(self, values_file=None, release_name="audit"):
        """Render Helm templates without deploying."""
        cmd = ["helm", "template", release_name, str(self.chart_path)]
        if values_file:
            cmd.extend(["--values", values_file])
        stdout, stderr, rc = self._run(cmd)
        if rc == 0:
            rendered_path = self.output_dir / "rendered.yaml"
            rendered_path.write_text(stdout)
            return str(rendered_path)
        return None

    def check_security_contexts(self, rendered_path):
        """Check rendered manifests for security context issues."""
        issues = []
        content = Path(rendered_path).read_text()

        checks = [
            (r"privileged:\s*true", "high", "Privileged container detected"),
            (r"hostNetwork:\s*true", "high", "Host network access enabled"),
            (r"hostPID:\s*true", "high", "Host PID namespace shared"),
            (r"allowPrivilegeEscalation:\s*true", "medium", "Privilege escalation allowed"),
            (r"runAsUser:\s*0\b", "medium", "Running as root (UID 0)"),
        ]

        positive_checks = [
            (r"readOnlyRootFilesystem:\s*true", "readOnlyRootFilesystem"),
            (r"runAsNonRoot:\s*true", "runAsNonRoot"),
            (r"drop:\s*\n\s*-\s*ALL", "drop ALL capabilities"),
        ]

        for pattern, severity, msg in checks:
            if re.search(pattern, content):
                issues.append({"severity": severity, "issue": msg})
                self.findings.append({"severity": severity, "type": "Security Context", "detail": msg})

        for pattern, name in positive_checks:
            if not re.search(pattern, content):
                issues.append({"severity": "medium", "issue": f"Missing: {name}"})
                self.findings.append({"severity": "medium", "type": "Missing Hardening", "detail": f"Missing: {name}"})

        if "resources:" not in content:
            issues.append({"severity": "medium", "issue": "No resource limits defined"})
            self.findings.append({"severity": "medium", "type": "Missing Resources", "detail": "No CPU/memory limits"})

        return issues

    def verify_chart_signature(self, keyring=None):
        """Verify Helm chart provenance signature."""
        tgz = list(self.chart_path.parent.glob(f"{self.chart_path.name}-*.tgz"))
        if not tgz:
            return {"verified": False, "reason": "No packaged chart found"}
        cmd = ["helm", "verify", str(tgz[0])]
        if keyring:
            cmd.extend(["--keyring", keyring])
        stdout, stderr, rc = self._run(cmd)
        if rc != 0:
            self.findings.append({"severity": "medium", "type": "Unsigned Chart", "detail": "Chart signature not verified"})
        return {"verified": rc == 0, "output": stdout.strip() or stderr.strip()}

    def check_image_references(self, rendered_path):
        """Check if image references use digests or tags."""
        content = Path(rendered_path).read_text()
        issues = []
        for m in re.finditer(r'image:\s*["\']?([^"\'\s]+)["\']?', content):
            image = m.group(1)
            if ":latest" in image:
                issues.append({"image": image, "issue": "Uses :latest tag"})
                self.findings.append({"severity": "medium", "type": "Image Tag", "detail": f"latest tag: {image}"})
            elif "@sha256:" not in image and ":" not in image:
                issues.append({"image": image, "issue": "No tag or digest specified"})
        return issues

    def scan_with_kubesec(self, rendered_path):
        """Scan rendered templates with kubesec if available."""
        stdout, stderr, rc = self._run(["kubesec", "scan", rendered_path])
        if rc < 0:
            return {"available": False}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"error": "Parse failed"}

    def generate_report(self, values_file=None):
        lint = self.lint_chart(values_file)
        rendered = self.render_templates(values_file)
        sec_ctx = []
        images = []
        if rendered:
            sec_ctx = self.check_security_contexts(rendered)
            images = self.check_image_references(rendered)

        report = {
            "report_date": datetime.utcnow().isoformat(),
            "chart": str(self.chart_path),
            "lint_result": lint,
            "security_context_issues": sec_ctx,
            "image_issues": images,
            "findings": self.findings,
            "total_findings": len(self.findings),
        }
        out = self.output_dir / "helm_security_report.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2)
        print(json.dumps(report, indent=2))
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <chart_path> [--values values.yaml]")
        sys.exit(1)
    chart = sys.argv[1]
    values = None
    if "--values" in sys.argv:
        values = sys.argv[sys.argv.index("--values") + 1]
    agent = HelmSecurityAgent(chart)
    agent.generate_report(values)


if __name__ == "__main__":
    main()
