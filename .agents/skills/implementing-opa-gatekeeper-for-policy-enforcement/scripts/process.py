#!/usr/bin/env python3
"""
OPA Gatekeeper Policy Manager - Generate ConstraintTemplates, audit
constraint violations, and manage policy lifecycle.
"""

import json
import subprocess
import sys
import argparse
import yaml


CONSTRAINT_TEMPLATES = {
    "required-labels": {
        "kind": "K8sRequiredLabels",
        "rego": """
package k8srequiredlabels

violation[{"msg": msg, "details": {"missing_labels": missing}}] {
  provided := {label | input.review.object.metadata.labels[label]}
  required := {label | label := input.parameters.labels[_]}
  missing := required - provided
  count(missing) > 0
  msg := sprintf("Missing required labels: %v", [missing])
}
""",
        "params_schema": {
            "type": "object",
            "properties": {
                "labels": {"type": "array", "items": {"type": "string"}}
            },
        },
    },
    "block-privileged": {
        "kind": "K8sBlockPrivileged",
        "rego": """
package k8sblockprivileged

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Privileged container not allowed: %v", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.initContainers[_]
  container.securityContext.privileged == true
  msg := sprintf("Privileged init container not allowed: %v", [container.name])
}
""",
        "params_schema": None,
    },
    "allowed-repos": {
        "kind": "K8sAllowedRepos",
        "rego": """
package k8sallowedrepos

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not image_matches(container.image)
  msg := sprintf("Image %v not from allowed registry. Allowed: %v", [container.image, input.parameters.repos])
}

image_matches(image) {
  repo := input.parameters.repos[_]
  startswith(image, repo)
}
""",
        "params_schema": {
            "type": "object",
            "properties": {
                "repos": {"type": "array", "items": {"type": "string"}}
            },
        },
    },
    "block-latest-tag": {
        "kind": "K8sBlockLatestTag",
        "rego": """
package k8sblocklatesttag

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %v uses ':latest' tag", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not contains(container.image, ":")
  msg := sprintf("Container %v has no tag (defaults to latest)", [container.name])
}
""",
        "params_schema": None,
    },
    "require-limits": {
        "kind": "K8sRequireLimits",
        "rego": """
package k8srequirelimits

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container %v has no CPU limit", [container.name])
}

violation[{"msg": msg}] {
  container := input.review.object.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container %v has no memory limit", [container.name])
}
""",
        "params_schema": None,
    },
}


def generate_constraint_template(template_name: str) -> str:
    """Generate a ConstraintTemplate YAML."""
    tmpl = CONSTRAINT_TEMPLATES.get(template_name)
    if not tmpl:
        print(f"Unknown template: {template_name}", file=sys.stderr)
        sys.exit(1)

    ct = {
        "apiVersion": "templates.gatekeeper.sh/v1",
        "kind": "ConstraintTemplate",
        "metadata": {"name": tmpl["kind"].lower()},
        "spec": {
            "crd": {
                "spec": {
                    "names": {"kind": tmpl["kind"]},
                }
            },
            "targets": [{
                "target": "admission.k8s.gatekeeper.sh",
                "rego": tmpl["rego"].strip(),
            }],
        },
    }

    if tmpl["params_schema"]:
        ct["spec"]["crd"]["spec"]["validation"] = {
            "openAPIV3Schema": tmpl["params_schema"]
        }

    return yaml.dump(ct, default_flow_style=False)


def audit_constraints() -> list:
    """Fetch all constraint violations from the cluster."""
    result = subprocess.run(
        ["kubectl", "get", "constraints", "-o", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Error: {result.stderr}", file=sys.stderr)
        return []

    data = json.loads(result.stdout)
    results = []
    for item in data.get("items", []):
        name = item["metadata"]["name"]
        kind = item["kind"]
        enforcement = item.get("spec", {}).get("enforcementAction", "deny")
        violations = item.get("status", {}).get("violations", [])
        total = item.get("status", {}).get("totalViolations", 0)
        results.append({
            "name": name,
            "kind": kind,
            "enforcement": enforcement,
            "violation_count": total,
            "violations": violations[:10],
        })
    return results


def print_audit_report(results: list):
    """Print audit report."""
    print("\n=== OPA Gatekeeper Audit Report ===\n")
    total_violations = sum(r["violation_count"] for r in results)
    print(f"Total Constraints: {len(results)}")
    print(f"Total Violations: {total_violations}\n")

    print(f"{'Constraint':<40} {'Kind':<25} {'Mode':<10} {'Violations'}")
    print("-" * 90)
    for r in sorted(results, key=lambda x: -x["violation_count"]):
        print(f"{r['name']:<40} {r['kind']:<25} {r['enforcement']:<10} {r['violation_count']}")

    if total_violations > 0:
        print("\n--- Top Violations ---")
        for r in results:
            for v in r["violations"][:3]:
                print(f"  [{r['name']}] {v.get('message', 'No message')}")


def main():
    parser = argparse.ArgumentParser(description="OPA Gatekeeper Policy Manager")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("generate", help="Generate ConstraintTemplate")
    gen.add_argument("--template", required=True,
                    choices=list(CONSTRAINT_TEMPLATES.keys()),
                    help="Template name")

    subparsers.add_parser("list-templates", help="List available templates")
    subparsers.add_parser("audit", help="Audit all constraint violations")

    args = parser.parse_args()

    if args.command == "generate":
        print(generate_constraint_template(args.template))

    elif args.command == "list-templates":
        print("Available ConstraintTemplates:")
        for name, tmpl in CONSTRAINT_TEMPLATES.items():
            print(f"  {name}: {tmpl['kind']}")

    elif args.command == "audit":
        results = audit_constraints()
        print_audit_report(results)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
