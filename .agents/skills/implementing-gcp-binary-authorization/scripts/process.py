#!/usr/bin/env python3
"""
GCP Binary Authorization Management Script

Automates attestor management, policy configuration, and attestation
creation for container image supply chain security.
"""

import json
import subprocess
import sys


def run_gcloud(args):
    """Execute gcloud command and return parsed output."""
    cmd = ["gcloud"] + args + ["--format=json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None, result.stderr
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}, None
    except json.JSONDecodeError:
        return result.stdout, None


def check_binauthz_status(project_id):
    """Check Binary Authorization configuration status."""
    print(f"[*] Checking Binary Authorization status for project: {project_id}")

    policy, err = run_gcloud([
        "container", "binauthz", "policy", "export",
        f"--project={project_id}"
    ])

    if err:
        print(f"[!] Error fetching policy: {err}")
        return None

    print(f"[+] Current policy retrieved")
    return policy


def list_attestors(project_id):
    """List all configured attestors."""
    attestors, err = run_gcloud([
        "container", "binauthz", "attestors", "list",
        f"--project={project_id}"
    ])

    if err:
        print(f"[!] Error listing attestors: {err}")
        return []

    if isinstance(attestors, list):
        print(f"[+] Found {len(attestors)} attestors:")
        for a in attestors:
            print(f"  - {a.get('name', 'unknown')}")
    return attestors or []


def verify_attestation(project_id, image_url, attestor):
    """Verify that an image has a valid attestation."""
    print(f"[*] Verifying attestation for: {image_url}")

    attestations, err = run_gcloud([
        "container", "binauthz", "attestations", "list",
        f"--attestor={attestor}",
        f"--attestor-project={project_id}",
        f"--artifact-url={image_url}"
    ])

    if err:
        print(f"[!] Error: {err}")
        return False

    if isinstance(attestations, list) and len(attestations) > 0:
        print(f"[+] Image has {len(attestations)} attestation(s)")
        return True
    else:
        print(f"[!] No attestations found for image")
        return False


def create_attestation(project_id, image_url, attestor, key_info):
    """Create an attestation for a container image."""
    print(f"[*] Creating attestation for: {image_url}")

    _, err = run_gcloud([
        "container", "binauthz", "attestations", "sign-and-create",
        f"--artifact-url={image_url}",
        f"--attestor={attestor}",
        f"--attestor-project={project_id}",
        f"--keyversion-project={key_info['project']}",
        f"--keyversion-location={key_info['location']}",
        f"--keyversion-keyring={key_info['keyring']}",
        f"--keyversion-key={key_info['key']}",
        f"--keyversion={key_info['version']}"
    ])

    if err:
        print(f"[!] Error creating attestation: {err}")
        return False

    print(f"[+] Attestation created successfully")
    return True


def audit_policy_compliance(project_id):
    """Audit Binary Authorization policy for security compliance."""
    policy, err = run_gcloud([
        "container", "binauthz", "policy", "export",
        f"--project={project_id}"
    ])

    if not policy:
        print("[!] Could not retrieve policy")
        return

    findings = []

    if isinstance(policy, str):
        import yaml
        policy = yaml.safe_load(policy)

    default_rule = policy.get("defaultAdmissionRule", {})
    if default_rule.get("evaluationMode") == "ALWAYS_ALLOW":
        findings.append({
            "severity": "HIGH",
            "finding": "Default admission rule allows all images",
            "recommendation": "Set to REQUIRE_ATTESTATION or ALWAYS_DENY"
        })

    if default_rule.get("enforcementMode") == "DRYRUN_AUDIT_LOG_ONLY":
        findings.append({
            "severity": "MEDIUM",
            "finding": "Default rule is in dry-run mode (not enforcing)",
            "recommendation": "Switch to ENFORCED_BLOCK_AND_AUDIT_LOG"
        })

    if not policy.get("globalPolicyEvaluationMode") == "ENABLE":
        findings.append({
            "severity": "LOW",
            "finding": "Global policy evaluation not explicitly enabled",
            "recommendation": "Enable globalPolicyEvaluationMode"
        })

    whitelist = policy.get("admissionWhitelistPatterns", [])
    for pattern in whitelist:
        name = pattern.get("namePattern", "")
        if name == "*" or name == "**":
            findings.append({
                "severity": "CRITICAL",
                "finding": f"Wildcard whitelist pattern: {name}",
                "recommendation": "Remove overly broad whitelist patterns"
            })

    print(f"\n[*] Policy Compliance Audit Results:")
    if findings:
        for f in findings:
            print(f"  [{f['severity']}] {f['finding']}")
            print(f"    Recommendation: {f['recommendation']}")
    else:
        print("  [OK] No issues found")

    return findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="GCP Binary Authorization Management")
    parser.add_argument("--project", required=True, help="GCP Project ID")
    parser.add_argument("--status", action="store_true", help="Check policy status")
    parser.add_argument("--list-attestors", action="store_true", help="List attestors")
    parser.add_argument("--verify", type=str, help="Verify attestation for image URL")
    parser.add_argument("--attestor", type=str, help="Attestor name")
    parser.add_argument("--audit", action="store_true", help="Audit policy compliance")
    args = parser.parse_args()

    if args.status:
        check_binauthz_status(args.project)
    if args.list_attestors:
        list_attestors(args.project)
    if args.verify and args.attestor:
        verify_attestation(args.project, args.verify, args.attestor)
    if args.audit:
        audit_policy_compliance(args.project)
