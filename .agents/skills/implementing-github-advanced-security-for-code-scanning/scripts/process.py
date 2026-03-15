#!/usr/bin/env python3
"""
GitHub Advanced Security Code Scanning Alert Management

Uses the GitHub REST API to query, triage, and report on CodeQL
code scanning alerts across an organization's repositories.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from collections import defaultdict


def get_github_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def github_api_get(url: str, token: str) -> list | dict:
    headers = get_github_headers(token)
    results = []
    page = 1
    while True:
        paginated_url = f"{url}{'&' if '?' in url else '?'}per_page=100&page={page}"
        req = urllib.request.Request(paginated_url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode())
                if isinstance(data, list):
                    if not data:
                        break
                    results.extend(data)
                    page += 1
                else:
                    return data
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code} for {paginated_url}: {e.read().decode()}")
            break
    return results


def list_org_repos(org: str, token: str) -> list:
    url = f"https://api.github.com/orgs/{org}/repos?type=all"
    repos = github_api_get(url, token)
    return [r["full_name"] for r in repos if isinstance(r, dict)]


def get_code_scanning_alerts(repo: str, token: str, state: str = "open") -> list:
    url = f"https://api.github.com/repos/{repo}/code-scanning/alerts?state={state}"
    return github_api_get(url, token)


def categorize_alerts(alerts: list) -> dict:
    categories = defaultdict(lambda: defaultdict(int))
    for alert in alerts:
        rule = alert.get("rule", {})
        severity = rule.get("security_severity_level", "unknown")
        cwe_tags = [t for t in rule.get("tags", []) if t.startswith("cwe-")]
        tool_name = alert.get("tool", {}).get("name", "unknown")
        categories["by_severity"][severity] += 1
        categories["by_tool"][tool_name] += 1
        for cwe in cwe_tags:
            categories["by_cwe"][cwe] += 1
    return dict(categories)


def calculate_mttr(alerts: list) -> dict:
    resolved = [a for a in alerts if a.get("state") == "fixed"]
    if not resolved:
        return {"total_resolved": 0, "avg_mttr_hours": None}

    durations = []
    for alert in resolved:
        created = datetime.fromisoformat(alert["created_at"].replace("Z", "+00:00"))
        fixed = datetime.fromisoformat(
            alert.get("fixed_at", alert.get("dismissed_at", "")).replace("Z", "+00:00")
        )
        durations.append((fixed - created).total_seconds() / 3600)

    return {
        "total_resolved": len(resolved),
        "avg_mttr_hours": round(sum(durations) / len(durations), 1),
        "min_mttr_hours": round(min(durations), 1),
        "max_mttr_hours": round(max(durations), 1),
    }


def generate_org_report(org: str, token: str) -> dict:
    repos = list_org_repos(org, token)
    report = {
        "organization": org,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_repositories": len(repos),
        "repositories_with_scanning": 0,
        "total_open_alerts": 0,
        "severity_summary": defaultdict(int),
        "top_cwes": defaultdict(int),
        "repo_details": [],
    }

    for repo in repos:
        alerts = get_code_scanning_alerts(repo, token, state="open")
        if not alerts:
            continue

        report["repositories_with_scanning"] += 1
        report["total_open_alerts"] += len(alerts)
        categories = categorize_alerts(alerts)

        for sev, count in categories.get("by_severity", {}).items():
            report["severity_summary"][sev] += count
        for cwe, count in categories.get("by_cwe", {}).items():
            report["top_cwes"][cwe] += count

        closed_alerts = get_code_scanning_alerts(repo, token, state="fixed")
        mttr = calculate_mttr(closed_alerts)

        report["repo_details"].append(
            {
                "repository": repo,
                "open_alerts": len(alerts),
                "severity_breakdown": dict(categories.get("by_severity", {})),
                "mttr": mttr,
            }
        )

    report["severity_summary"] = dict(report["severity_summary"])
    top_cwes_sorted = sorted(report["top_cwes"].items(), key=lambda x: x[1], reverse=True)[:10]
    report["top_cwes"] = dict(top_cwes_sorted)
    return report


def print_report(report: dict) -> None:
    print(f"\n{'='*60}")
    print(f"GHAS Code Scanning Report: {report['organization']}")
    print(f"Generated: {report['generated_at']}")
    print(f"{'='*60}")
    print(f"Total repositories: {report['total_repositories']}")
    print(f"Repositories with scanning enabled: {report['repositories_with_scanning']}")
    coverage = (
        report["repositories_with_scanning"] / report["total_repositories"] * 100
        if report["total_repositories"] > 0
        else 0
    )
    print(f"Coverage: {coverage:.1f}%")
    print(f"Total open alerts: {report['total_open_alerts']}")
    print(f"\nSeverity Summary:")
    for sev in ["critical", "high", "medium", "low", "unknown"]:
        count = report["severity_summary"].get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():12s}: {count}")
    print(f"\nTop CWEs:")
    for cwe, count in report.get("top_cwes", {}).items():
        print(f"  {cwe:15s}: {count}")
    print(f"\nRepository Details:")
    for repo in sorted(report["repo_details"], key=lambda r: r["open_alerts"], reverse=True):
        mttr_str = (
            f"{repo['mttr']['avg_mttr_hours']}h" if repo["mttr"]["avg_mttr_hours"] else "N/A"
        )
        print(f"  {repo['repository']:40s} | Open: {repo['open_alerts']:4d} | Avg MTTR: {mttr_str}")


def main():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable is required")
        sys.exit(1)

    org = os.environ.get("GITHUB_ORG")
    if not org:
        print("Error: GITHUB_ORG environment variable is required")
        sys.exit(1)

    print(f"Fetching code scanning data for organization: {org}")
    report = generate_org_report(org, token)
    print_report(report)

    output_file = f"ghas_report_{org}_{datetime.utcnow().strftime('%Y%m%d')}.json"
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nDetailed report saved to: {output_file}")


if __name__ == "__main__":
    main()
