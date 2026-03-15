#!/usr/bin/env python3
"""
GitLab DevSecOps Pipeline Security Report Generator

Queries GitLab API to aggregate security scanning results
across projects and generate compliance reports.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict


def gitlab_api_get(url: str, token: str) -> list | dict:
    headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
    results = []
    page = 1
    while True:
        sep = "&" if "?" in url else "?"
        paginated = f"{url}{sep}per_page=100&page={page}"
        req = urllib.request.Request(paginated, headers=headers)
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
            print(f"HTTP {e.code}: {e.read().decode()}")
            break
    return results


def get_group_projects(base_url: str, token: str, group_id: str) -> list:
    url = f"{base_url}/api/v4/groups/{group_id}/projects?include_subgroups=true"
    return gitlab_api_get(url, token)


def get_project_vulnerabilities(base_url: str, token: str, project_id: int) -> list:
    url = f"{base_url}/api/v4/projects/{project_id}/vulnerabilities?state=detected"
    return gitlab_api_get(url, token)


def get_pipeline_jobs(base_url: str, token: str, project_id: int, pipeline_id: int) -> list:
    url = f"{base_url}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs"
    return gitlab_api_get(url, token)


def check_security_scanners(jobs: list) -> dict:
    scanner_names = {
        "sast": False,
        "secret_detection": False,
        "dependency_scanning": False,
        "container_scanning": False,
        "dast": False,
        "license_scanning": False,
    }
    for job in jobs:
        name = job.get("name", "").lower()
        for scanner in scanner_names:
            if scanner.replace("_", "-") in name or scanner in name:
                scanner_names[scanner] = True
    return scanner_names


def generate_report(base_url: str, token: str, group_id: str) -> dict:
    projects = get_group_projects(base_url, token, group_id)
    report = {
        "gitlab_instance": base_url,
        "group_id": group_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_projects": len(projects),
        "scanner_coverage": defaultdict(int),
        "severity_totals": defaultdict(int),
        "project_details": [],
    }

    for project in projects:
        pid = project["id"]
        name = project["path_with_namespace"]

        vulns = get_project_vulnerabilities(base_url, token, pid)
        severity_counts = defaultdict(int)
        scanner_counts = defaultdict(int)
        for v in vulns:
            severity_counts[v.get("severity", "unknown")] += 1
            scanner_counts[v.get("scanner", {}).get("name", "unknown")] += 1
            report["severity_totals"][v.get("severity", "unknown")] += 1

        pipelines = gitlab_api_get(
            f"{base_url}/api/v4/projects/{pid}/pipelines?per_page=1&status=success", token
        )
        scanners_enabled = {}
        if pipelines and isinstance(pipelines, list):
            jobs = get_pipeline_jobs(base_url, token, pid, pipelines[0]["id"])
            scanners_enabled = check_security_scanners(jobs)
            for scanner, enabled in scanners_enabled.items():
                if enabled:
                    report["scanner_coverage"][scanner] += 1

        report["project_details"].append({
            "project": name,
            "open_vulnerabilities": len(vulns),
            "by_severity": dict(severity_counts),
            "by_scanner": dict(scanner_counts),
            "scanners_enabled": scanners_enabled,
        })

    report["scanner_coverage"] = dict(report["scanner_coverage"])
    report["severity_totals"] = dict(report["severity_totals"])
    return report


def print_report(report: dict) -> None:
    print(f"\n{'='*65}")
    print(f"GitLab DevSecOps Security Report")
    print(f"Instance: {report['gitlab_instance']}")
    print(f"Generated: {report['generated_at']}")
    print(f"{'='*65}")
    print(f"\nTotal Projects: {report['total_projects']}")

    print(f"\nScanner Coverage:")
    for scanner, count in sorted(report["scanner_coverage"].items()):
        pct = count / report["total_projects"] * 100 if report["total_projects"] > 0 else 0
        print(f"  {scanner:25s}: {count:3d}/{report['total_projects']} ({pct:.0f}%)")

    print(f"\nVulnerability Summary:")
    for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
        count = report["severity_totals"].get(sev, 0)
        if count > 0:
            print(f"  {sev.upper():12s}: {count}")

    total = sum(report["severity_totals"].values())
    print(f"  {'TOTAL':12s}: {total}")

    print(f"\nTop 10 Projects by Open Vulnerabilities:")
    sorted_projects = sorted(
        report["project_details"], key=lambda p: p["open_vulnerabilities"], reverse=True
    )
    for p in sorted_projects[:10]:
        print(f"  {p['project']:45s} | Vulns: {p['open_vulnerabilities']}")


def main():
    token = os.environ.get("GITLAB_TOKEN")
    base_url = os.environ.get("GITLAB_URL", "https://gitlab.com")
    group_id = os.environ.get("GITLAB_GROUP_ID")

    if not token:
        print("Error: GITLAB_TOKEN environment variable required")
        sys.exit(1)
    if not group_id:
        print("Error: GITLAB_GROUP_ID environment variable required")
        sys.exit(1)

    report = generate_report(base_url, token, group_id)
    print_report(report)

    output = f"gitlab_devsecops_report_{datetime.utcnow().strftime('%Y%m%d')}.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    main()
