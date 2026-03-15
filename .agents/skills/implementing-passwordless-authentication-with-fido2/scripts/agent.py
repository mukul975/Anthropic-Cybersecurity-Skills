#!/usr/bin/env python3
"""FIDO2 Passwordless Auth Agent - audits FIDO2 deployment readiness and credential status."""

import json
import argparse
import logging
import subprocess
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def graph_api(token, endpoint):
    cmd = ["curl", "-s", "-H", f"Authorization: Bearer {token}",
           f"https://graph.microsoft.com/v1.0{endpoint}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def get_fido2_policy(token):
    return graph_api(token, "/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2")


def get_registrations(token):
    return graph_api(token, "/reports/authenticationMethods/userRegistrationDetails")


def audit_fido2_policy(policy):
    findings = []
    if policy.get("state") != "enabled":
        findings.append({"issue": f"FIDO2 policy state: {policy.get('state', 'unknown')}", "severity": "high"})
    if not policy.get("keyRestrictions", {}).get("aaGuids"):
        findings.append({"issue": "No AAGUID restrictions set", "severity": "medium"})
    if not policy.get("isAttestationEnforced"):
        findings.append({"issue": "Attestation not enforced", "severity": "medium"})
    return findings


def analyze_adoption(registrations):
    users = registrations.get("value", [])
    total = len(users)
    fido2 = sum(1 for u in users if "fido2" in str(u.get("methodsRegistered", [])).lower())
    passwordless = sum(1 for u in users if u.get("isPasswordlessCapable", False))
    return {
        "total_users": total, "fido2_registered": fido2, "passwordless_capable": passwordless,
        "fido2_adoption_rate": round(fido2 / max(total, 1) * 100, 1),
    }


def check_rp_config(rp_url):
    cmd = ["curl", "-s", f"{rp_url}/.well-known/webauthn"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    findings = []
    try:
        config = json.loads(result.stdout)
    except json.JSONDecodeError:
        config = {}
        findings.append({"issue": "WebAuthn well-known not configured", "severity": "high"})
    return {"config": config, "findings": findings}


def generate_report(policy, policy_findings, adoption, rp):
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "fido2_policy_state": policy.get("state", "unknown"),
        "policy_findings": policy_findings, "adoption_metrics": adoption,
        "rp_config": rp,
        "total_findings": len(policy_findings) + len(rp.get("findings", [])),
    }


def main():
    parser = argparse.ArgumentParser(description="FIDO2 Passwordless Authentication Audit Agent")
    parser.add_argument("--token", required=True, help="Graph API bearer token")
    parser.add_argument("--rp-url", help="WebAuthn relying party URL")
    parser.add_argument("--output", default="fido2_audit_report.json")
    args = parser.parse_args()
    policy = get_fido2_policy(args.token)
    policy_findings = audit_fido2_policy(policy)
    registrations = get_registrations(args.token)
    adoption = analyze_adoption(registrations)
    rp = check_rp_config(args.rp_url) if args.rp_url else {"config": {}, "findings": []}
    report = generate_report(policy, policy_findings, adoption, rp)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("FIDO2: adoption %.1f%%, %d findings", adoption["fido2_adoption_rate"], report["total_findings"])
    print(json.dumps(report, indent=2, default=str))

if __name__ == "__main__":
    main()
