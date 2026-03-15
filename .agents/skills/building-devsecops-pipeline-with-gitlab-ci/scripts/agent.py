#!/usr/bin/env python3
"""DevSecOps Pipeline Builder Agent - Generates GitLab CI security scanning pipeline configurations."""

import json
import logging
import argparse
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SECURITY_STAGES = {
    "sast": {
        "template": "Security/SAST.gitlab-ci.yml",
        "description": "Static Application Security Testing",
        "tools": ["semgrep", "bandit", "eslint-security"],
    },
    "dast": {
        "template": "Security/DAST.gitlab-ci.yml",
        "description": "Dynamic Application Security Testing",
        "tools": ["zap"],
    },
    "dependency_scanning": {
        "template": "Security/Dependency-Scanning.gitlab-ci.yml",
        "description": "Dependency vulnerability scanning",
        "tools": ["gemnasium", "retire.js"],
    },
    "container_scanning": {
        "template": "Security/Container-Scanning.gitlab-ci.yml",
        "description": "Container image vulnerability scanning",
        "tools": ["trivy", "grype"],
    },
    "secret_detection": {
        "template": "Security/Secret-Detection.gitlab-ci.yml",
        "description": "Secret and credential detection",
        "tools": ["gitleaks"],
    },
    "license_scanning": {
        "template": "Jobs/License-Scanning.gitlab-ci.yml",
        "description": "License compliance scanning",
        "tools": ["license-finder"],
    },
    "iac_scanning": {
        "template": "Security/IaC-Scanning.gitlab-ci.yml",
        "description": "Infrastructure as Code scanning",
        "tools": ["kics"],
    },
}


def generate_gitlab_ci(stages, project_type="python", registry="$CI_REGISTRY"):
    """Generate .gitlab-ci.yml with security scanning stages."""
    ci_config = {
        "stages": ["build", "test", "security", "deploy"],
        "include": [],
        "variables": {
            "SECURE_LOG_LEVEL": "info",
            "SAST_EXCLUDED_ANALYZERS": "",
        },
    }
    for stage_name in stages:
        stage = SECURITY_STAGES.get(stage_name)
        if stage:
            ci_config["include"].append({"template": stage["template"]})

    if "container_scanning" in stages:
        ci_config["variables"]["CS_IMAGE"] = f"{registry}/$CI_PROJECT_PATH:$CI_COMMIT_SHA"

    if project_type == "python":
        ci_config["variables"]["SAST_DEFAULT_ANALYZERS"] = "semgrep,bandit"
    elif project_type == "javascript":
        ci_config["variables"]["SAST_DEFAULT_ANALYZERS"] = "semgrep,eslint"

    return ci_config


def validate_pipeline(gitlab_url, token, project_id, ci_content):
    """Validate CI configuration via GitLab API."""
    headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}
    data = {"content": json.dumps(ci_content)}
    try:
        resp = requests.post(f"{gitlab_url}/api/v4/projects/{project_id}/ci/lint", headers=headers, json=data, timeout=15)
        return resp.json()
    except requests.RequestException as e:
        return {"error": str(e)}


def assess_pipeline_coverage(stages):
    """Assess security coverage of the pipeline."""
    all_stages = set(SECURITY_STAGES.keys())
    covered = set(stages) & all_stages
    missing = all_stages - covered
    coverage = len(covered) / len(all_stages) * 100
    return {
        "coverage_percent": round(coverage, 1),
        "covered_stages": list(covered),
        "missing_stages": list(missing),
        "recommendation": "Add " + ", ".join(missing) if missing else "Full coverage",
    }


def generate_report(ci_config, coverage, stages):
    """Generate DevSecOps pipeline report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "stages_configured": stages,
        "security_coverage": coverage,
        "gitlab_ci_config": ci_config,
    }
    print(f"DEVSECOPS REPORT: {len(stages)} stages, {coverage['coverage_percent']}% coverage")
    return report


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Pipeline Builder Agent")
    parser.add_argument("--stages", nargs="*", choices=list(SECURITY_STAGES.keys()), default=list(SECURITY_STAGES.keys()))
    parser.add_argument("--project-type", choices=["python", "javascript", "java", "go"], default="python")
    parser.add_argument("--gitlab-url", help="GitLab URL for validation")
    parser.add_argument("--token", help="GitLab private token")
    parser.add_argument("--project-id", help="GitLab project ID")
    parser.add_argument("--output", default="devsecops_report.json")
    args = parser.parse_args()

    ci_config = generate_gitlab_ci(args.stages, args.project_type)
    coverage = assess_pipeline_coverage(args.stages)
    report = generate_report(ci_config, coverage, args.stages)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
