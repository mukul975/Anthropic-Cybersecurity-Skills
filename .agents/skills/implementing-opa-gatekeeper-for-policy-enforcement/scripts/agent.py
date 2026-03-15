#!/usr/bin/env python3
"""OPA Gatekeeper Policy Enforcement Agent - audits constraint templates and violation status."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def kubectl_json(args_list):
    cmd = ["kubectl"] + args_list + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.returncode == 0 else {}


def get_constraint_templates():
    return kubectl_json(["get", "constrainttemplates"])


def get_constraints():
    templates = get_constraint_templates()
    constraints = []
    for item in templates.get("items", []):
        kind = item.get("metadata", {}).get("name", "")
        result = kubectl_json(["get", kind])
        for c in result.get("items", []):
            constraints.append(c)
    return constraints


def audit_constraint_violations(constraints):
    violations = []
    for constraint in constraints:
        name = constraint.get("metadata", {}).get("name", "")
        kind = constraint.get("kind", "")
        status = constraint.get("status", {})
        total = status.get("totalViolations", 0)
        violation_list = status.get("violations", [])
        if total > 0:
            violations.append({
                "constraint": name, "kind": kind, "total_violations": total,
                "enforcement_action": constraint.get("spec", {}).get("enforcementAction", "deny"),
                "sample_violations": violation_list[:5],
            })
    return sorted(violations, key=lambda x: x["total_violations"], reverse=True)


def analyze_policy_coverage(constraints):
    categories = defaultdict(int)
    enforcement = defaultdict(int)
    for c in constraints:
        categories[c.get("kind", "unknown")] += 1
        enforcement[c.get("spec", {}).get("enforcementAction", "deny")] += 1
    return {"total_constraints": len(constraints), "by_template": dict(categories), "by_enforcement_action": dict(enforcement)}


def check_audit_status():
    cmd = ["kubectl", "get", "pods", "-n", "gatekeeper-system", "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    pods = json.loads(result.stdout) if result.returncode == 0 else {}
    pod_status = []
    for pod in pods.get("items", []):
        name = pod.get("metadata", {}).get("name", "")
        phase = pod.get("status", {}).get("phase", "")
        ready = all(c.get("ready", False) for c in pod.get("status", {}).get("containerStatuses", []))
        pod_status.append({"name": name, "phase": phase, "ready": ready})
    return pod_status


def generate_report(templates, constraints, violations, coverage, pod_status):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "constraint_templates": len(templates.get("items", [])),
        "active_constraints": len(constraints),
        "policy_coverage": coverage,
        "total_violations": sum(v["total_violations"] for v in violations),
        "constraints_with_violations": len(violations),
        "top_violations": violations[:15],
        "gatekeeper_pods": pod_status,
        "gatekeeper_healthy": all(p["ready"] for p in pod_status) if pod_status else False,
    }


def main():
    parser = argparse.ArgumentParser(description="OPA Gatekeeper Policy Enforcement Audit Agent")
    parser.add_argument("--output", default="gatekeeper_audit_report.json")
    args = parser.parse_args()

    templates = get_constraint_templates()
    constraints = get_constraints()
    violations = audit_constraint_violations(constraints)
    coverage = analyze_policy_coverage(constraints)
    pod_status = check_audit_status()
    report = generate_report(templates, constraints, violations, coverage, pod_status)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Gatekeeper: %d templates, %d constraints, %d violations",
                report["constraint_templates"], report["active_constraints"], report["total_violations"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
