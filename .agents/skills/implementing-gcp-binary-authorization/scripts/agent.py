#!/usr/bin/env python3
"""Agent for auditing and managing GCP Binary Authorization policies."""

import json
import argparse
import subprocess
from datetime import datetime


def run_gcloud(args_list):
    """Run a gcloud command and return parsed JSON output."""
    cmd = ["gcloud"] + args_list + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()}


def get_binauthz_policy(project):
    """Retrieve the Binary Authorization policy for a project."""
    return run_gcloud(["container", "binauthz", "policy", "export",
                       "--project", project])


def list_attestors(project):
    """List all attestors in the project."""
    return run_gcloud(["container", "binauthz", "attestors", "list",
                       "--project", project])


def list_attestations(project, attestor):
    """List attestations for a given attestor."""
    return run_gcloud(["container", "binauthz", "attestations", "list",
                       "--attestor", attestor, "--attestor-project", project])


def verify_image_attested(project, attestor, image_url):
    """Check if a container image has a valid attestation."""
    result = run_gcloud(["container", "binauthz", "attestations", "list",
                         "--attestor", attestor, "--attestor-project", project,
                         "--artifact-url", image_url])
    if isinstance(result, list) and len(result) > 0:
        return {"image": image_url, "attested": True, "attestation_count": len(result)}
    return {"image": image_url, "attested": False, "attestation_count": 0}


def audit_policy(policy):
    """Audit a Binary Authorization policy for security issues."""
    findings = []
    if isinstance(policy, dict) and "error" in policy:
        return [{"issue": "Cannot retrieve policy", "severity": "CRITICAL",
                 "detail": policy["error"]}]

    default_rule = policy.get("defaultAdmissionRule", {})
    eval_mode = default_rule.get("evaluationMode", "")
    enforce_mode = default_rule.get("enforcementMode", "")

    if eval_mode == "ALWAYS_ALLOW":
        findings.append({"issue": "Default rule allows all images",
                         "severity": "CRITICAL",
                         "recommendation": "Set evaluationMode to REQUIRE_ATTESTATION"})

    if enforce_mode == "DRYRUN_AUDIT_LOG_ONLY":
        findings.append({"issue": "Default rule is dry-run only",
                         "severity": "HIGH",
                         "recommendation": "Set enforcementMode to ENFORCED_BLOCK_AND_AUDIT_LOG"})

    attestors = default_rule.get("requireAttestationsBy", [])
    if eval_mode == "REQUIRE_ATTESTATION" and not attestors:
        findings.append({"issue": "Attestation required but no attestors configured",
                         "severity": "CRITICAL"})

    global_eval = policy.get("globalPolicyEvaluationMode", "")
    if global_eval != "ENABLE":
        findings.append({"issue": "Global policy evaluation not enabled",
                         "severity": "MEDIUM",
                         "recommendation": "Set globalPolicyEvaluationMode to ENABLE"})

    whitelist = policy.get("admissionWhitelistPatterns", [])
    for pattern in whitelist:
        name = pattern.get("namePattern", "")
        if name.endswith("/**") or name.endswith("/*"):
            if not any(safe in name for safe in ["gcr.io/google", "k8s.gcr.io", "gke.gcr.io"]):
                findings.append({"issue": f"Broad whitelist pattern: {name}",
                                 "severity": "HIGH",
                                 "recommendation": "Restrict whitelist to specific images"})

    cluster_rules = policy.get("clusterAdmissionRules", {})
    for cluster, rule in cluster_rules.items():
        if rule.get("evaluationMode") == "ALWAYS_ALLOW":
            findings.append({"issue": f"Cluster {cluster} allows all images",
                             "severity": "HIGH"})

    if not findings:
        findings.append({"issue": "No issues found", "severity": "INFO"})

    return findings


def generate_policy(project, attestors, allowed_patterns=None):
    """Generate a Binary Authorization policy YAML."""
    whitelist = allowed_patterns or [
        "gcr.io/google_containers/*", "gcr.io/google-containers/*",
        "k8s.gcr.io/**", "gke.gcr.io/**", "gcr.io/stackdriver-agents/*",
    ]
    policy = {
        "admissionWhitelistPatterns": [{"namePattern": p} for p in whitelist],
        "defaultAdmissionRule": {
            "evaluationMode": "REQUIRE_ATTESTATION",
            "enforcementMode": "ENFORCED_BLOCK_AND_AUDIT_LOG",
            "requireAttestationsBy": [
                f"projects/{project}/attestors/{a}" for a in attestors
            ],
        },
        "globalPolicyEvaluationMode": "ENABLE",
    }
    return policy


def check_cv_status(project, cluster, zone):
    """Check continuous validation status on a GKE cluster."""
    result = run_gcloud(["container", "clusters", "describe", cluster,
                         "--zone", zone, "--project", project])
    if isinstance(result, dict):
        binauthz = result.get("binaryAuthorization", {})
        return {
            "cluster": cluster,
            "enabled": binauthz.get("enabled", False),
            "evaluation_mode": binauthz.get("evaluationMode", ""),
        }
    return {"cluster": cluster, "error": "Cannot retrieve cluster info"}


def main():
    parser = argparse.ArgumentParser(description="GCP Binary Authorization Agent")
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--action", choices=["audit", "list-attestors", "verify",
                                              "generate", "cv-status"],
                        default="audit")
    parser.add_argument("--attestor", help="Attestor name")
    parser.add_argument("--image", help="Container image URL for verification")
    parser.add_argument("--cluster", help="GKE cluster name")
    parser.add_argument("--zone", default="us-central1-a")
    parser.add_argument("--output", default="binauthz_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "project": args.project,
              "results": {}}

    if args.action == "audit":
        policy = get_binauthz_policy(args.project)
        findings = audit_policy(policy)
        report["results"]["policy"] = policy
        report["results"]["findings"] = findings
        for f in findings:
            print(f"[{f['severity']}] {f['issue']}")

    elif args.action == "list-attestors":
        attestors = list_attestors(args.project)
        report["results"]["attestors"] = attestors
        print(f"[+] Found {len(attestors) if isinstance(attestors, list) else 0} attestors")

    elif args.action == "verify" and args.attestor and args.image:
        result = verify_image_attested(args.project, args.attestor, args.image)
        report["results"]["verification"] = result
        status = "ATTESTED" if result["attested"] else "NOT ATTESTED"
        print(f"[+] {args.image}: {status}")

    elif args.action == "generate":
        attestors = [args.attestor] if args.attestor else ["prod-build-attestor"]
        policy = generate_policy(args.project, attestors)
        report["results"]["generated_policy"] = policy
        print("[+] Policy generated")

    elif args.action == "cv-status" and args.cluster:
        status = check_cv_status(args.project, args.cluster, args.zone)
        report["results"]["cv_status"] = status
        print(f"[+] CV enabled: {status.get('enabled', False)}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
