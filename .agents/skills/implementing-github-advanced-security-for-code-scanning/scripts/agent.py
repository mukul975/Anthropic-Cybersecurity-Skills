#!/usr/bin/env python3
"""Agent for managing GitHub Advanced Security code scanning with CodeQL."""

import json
import argparse
import subprocess
from datetime import datetime
from collections import Counter


def gh_api(endpoint, method="GET"):
    """Call GitHub API via gh CLI."""
    cmd = ["gh", "api", endpoint, "--method", method]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


def get_code_scanning_alerts(owner, repo, state="open"):
    """Get code scanning alerts for a repository."""
    alerts = gh_api(f"/repos/{owner}/{repo}/code-scanning/alerts?state={state}&per_page=100")
    if isinstance(alerts, dict) and "error" in alerts:
        return alerts
    return alerts if isinstance(alerts, list) else []


def get_secret_scanning_alerts(owner, repo, state="open"):
    """Get secret scanning alerts for a repository."""
    alerts = gh_api(f"/repos/{owner}/{repo}/secret-scanning/alerts?state={state}&per_page=100")
    if isinstance(alerts, dict) and "error" in alerts:
        return alerts
    return alerts if isinstance(alerts, list) else []


def get_dependabot_alerts(owner, repo, state="open"):
    """Get Dependabot alerts for a repository."""
    alerts = gh_api(f"/repos/{owner}/{repo}/dependabot/alerts?state={state}&per_page=100")
    if isinstance(alerts, dict) and "error" in alerts:
        return alerts
    return alerts if isinstance(alerts, list) else []


def analyze_code_scanning_alerts(alerts):
    """Analyze code scanning alerts and produce summary."""
    if not isinstance(alerts, list):
        return {"error": "No alerts data"}
    by_severity = Counter()
    by_rule = Counter()
    by_tool = Counter()
    critical_alerts = []
    for alert in alerts:
        rule = alert.get("rule", {})
        severity = rule.get("security_severity_level", rule.get("severity", "unknown"))
        by_severity[severity] += 1
        by_rule[rule.get("id", "unknown")] += 1
        tool = alert.get("tool", {}).get("name", "unknown")
        by_tool[tool] += 1
        if severity in ("critical", "high"):
            critical_alerts.append({
                "number": alert.get("number"),
                "rule": rule.get("id", ""),
                "description": rule.get("description", "")[:120],
                "severity": severity,
                "state": alert.get("state", ""),
                "created_at": alert.get("created_at", ""),
                "html_url": alert.get("html_url", ""),
            })
    return {
        "total_alerts": len(alerts),
        "by_severity": dict(by_severity),
        "by_rule": dict(by_rule.most_common(10)),
        "by_tool": dict(by_tool),
        "critical_and_high": critical_alerts[:20],
    }


def analyze_secret_alerts(alerts):
    """Analyze secret scanning alerts."""
    if not isinstance(alerts, list):
        return {"error": "No alerts data"}
    by_type = Counter()
    for alert in alerts:
        by_type[alert.get("secret_type_display_name", alert.get("secret_type", "unknown"))] += 1
    return {
        "total_secrets": len(alerts),
        "by_type": dict(by_type),
        "alerts": [
            {"number": a.get("number"), "type": a.get("secret_type_display_name", ""),
             "state": a.get("state", ""), "created_at": a.get("created_at", "")}
            for a in alerts[:20]
        ],
    }


def analyze_dependabot_alerts(alerts):
    """Analyze Dependabot vulnerability alerts."""
    if not isinstance(alerts, list):
        return {"error": "No alerts data"}
    by_severity = Counter()
    by_ecosystem = Counter()
    for alert in alerts:
        vuln = alert.get("security_vulnerability", alert.get("security_advisory", {}))
        severity = vuln.get("severity", alert.get("severity", "unknown"))
        by_severity[severity] += 1
        dep = alert.get("dependency", {})
        pkg = dep.get("package", {})
        by_ecosystem[pkg.get("ecosystem", "unknown")] += 1
    return {
        "total_alerts": len(alerts),
        "by_severity": dict(by_severity),
        "by_ecosystem": dict(by_ecosystem),
    }


def generate_codeql_workflow(languages, query_suite="security-extended"):
    """Generate a CodeQL analysis GitHub Actions workflow."""
    lang_list = ", ".join(f"'{l}'" for l in languages)
    return f"""name: CodeQL Analysis
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '30 2 * * 1'
jobs:
  analyze:
    name: Analyze (${{{{ matrix.language }}}})
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read
    strategy:
      fail-fast: false
      matrix:
        language: [{lang_list}]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{{{ matrix.language }}}}
          queries: +{query_suite}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{{{ matrix.language }}}}"
"""


def full_security_audit(owner, repo):
    """Run full GHAS security audit for a repository."""
    code_alerts = get_code_scanning_alerts(owner, repo)
    secret_alerts = get_secret_scanning_alerts(owner, repo)
    dependabot_alerts = get_dependabot_alerts(owner, repo)
    return {
        "code_scanning": analyze_code_scanning_alerts(code_alerts),
        "secret_scanning": analyze_secret_alerts(secret_alerts),
        "dependabot": analyze_dependabot_alerts(dependabot_alerts),
    }


def main():
    parser = argparse.ArgumentParser(description="GitHub Advanced Security Agent")
    parser.add_argument("--owner", help="Repository owner")
    parser.add_argument("--repo", help="Repository name")
    parser.add_argument("--action", choices=["audit", "code-alerts", "secrets",
                                              "dependabot", "gen-workflow"],
                        default="audit")
    parser.add_argument("--languages", nargs="+", default=["python", "javascript-typescript"])
    parser.add_argument("--output", default="ghas_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.action == "audit" and args.owner and args.repo:
        results = full_security_audit(args.owner, args.repo)
        report["results"] = results
        cs = results["code_scanning"]
        print(f"[+] Code scanning: {cs.get('total_alerts', 0)} alerts")
        print(f"[+] Secrets: {results['secret_scanning'].get('total_secrets', 0)}")
        print(f"[+] Dependabot: {results['dependabot'].get('total_alerts', 0)}")

    elif args.action == "code-alerts" and args.owner and args.repo:
        alerts = get_code_scanning_alerts(args.owner, args.repo)
        analysis = analyze_code_scanning_alerts(alerts)
        report["results"]["code_scanning"] = analysis
        print(f"[+] {analysis.get('total_alerts', 0)} code scanning alerts")

    elif args.action == "secrets" and args.owner and args.repo:
        alerts = get_secret_scanning_alerts(args.owner, args.repo)
        analysis = analyze_secret_alerts(alerts)
        report["results"]["secret_scanning"] = analysis
        print(f"[+] {analysis.get('total_secrets', 0)} secret alerts")

    elif args.action == "gen-workflow":
        workflow = generate_codeql_workflow(args.languages)
        report["results"]["workflow"] = workflow
        print("[+] CodeQL workflow generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
