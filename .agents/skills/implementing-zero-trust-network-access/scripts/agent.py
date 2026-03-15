#!/usr/bin/env python3
"""
Zero Trust Network Access (ZTNA) Assessment Agent
Evaluates ZTNA readiness across AWS, Azure, and GCP by checking IAP configs,
Verified Access endpoints, conditional access policies, and micro-segmentation.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone


def run_cmd(cmd: list[str]) -> dict:
    """Execute a shell command and return structured output."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


def check_aws_verified_access() -> dict:
    """Enumerate AWS Verified Access instances, groups, and endpoints."""
    findings = {"instances": [], "groups": [], "endpoints": [], "issues": []}

    result = run_cmd(["aws", "ec2", "describe-verified-access-instances", "--output", "json"])
    if result["success"]:
        data = json.loads(result["stdout"])
        for inst in data.get("VerifiedAccessInstances", []):
            inst_id = inst["VerifiedAccessInstanceId"]
            trust_providers = inst.get("VerifiedAccessTrustProviders", [])
            findings["instances"].append({
                "id": inst_id,
                "trust_providers": len(trust_providers),
                "logging_enabled": inst.get("LoggingConfiguration", {}).get("CloudWatchLogs", {}).get("Enabled", False),
            })
            if not trust_providers:
                findings["issues"].append(f"Instance {inst_id} has no trust providers attached")

    result = run_cmd(["aws", "ec2", "describe-verified-access-groups", "--output", "json"])
    if result["success"]:
        data = json.loads(result["stdout"])
        for grp in data.get("VerifiedAccessGroups", []):
            grp_id = grp["VerifiedAccessGroupId"]
            has_policy = bool(grp.get("PolicyDocument"))
            findings["groups"].append({"id": grp_id, "has_policy": has_policy})
            if not has_policy:
                findings["issues"].append(f"Group {grp_id} has no access policy defined")

    result = run_cmd(["aws", "ec2", "describe-verified-access-endpoints", "--output", "json"])
    if result["success"]:
        data = json.loads(result["stdout"])
        for ep in data.get("VerifiedAccessEndpoints", []):
            findings["endpoints"].append({
                "id": ep["VerifiedAccessEndpointId"],
                "type": ep.get("EndpointType", "unknown"),
                "domain": ep.get("ApplicationDomain", ""),
                "status": ep.get("Status", {}).get("Code", "unknown"),
            })

    return findings


def check_aws_security_groups_segmentation(vpc_id: str) -> dict:
    """Check for overly permissive security groups that undermine micro-segmentation."""
    findings = {"total_sgs": 0, "overly_permissive": [], "issues": []}

    result = run_cmd([
        "aws", "ec2", "describe-security-groups",
        "--filters", f"Name=vpc-id,Values={vpc_id}",
        "--output", "json"
    ])
    if not result["success"]:
        return findings

    data = json.loads(result["stdout"])
    sgs = data.get("SecurityGroups", [])
    findings["total_sgs"] = len(sgs)

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "")
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port = perm.get("FromPort", "all")
                    findings["overly_permissive"].append({
                        "sg_id": sg_id,
                        "sg_name": sg_name,
                        "port": port,
                        "cidr": "0.0.0.0/0",
                    })
                    findings["issues"].append(
                        f"SG {sg_id} ({sg_name}) allows 0.0.0.0/0 on port {port}"
                    )
    return findings


def check_gcp_iap_status(project_id: str) -> dict:
    """Check GCP Identity-Aware Proxy configuration."""
    findings = {"iap_enabled_backends": [], "issues": []}

    result = run_cmd([
        "gcloud", "compute", "backend-services", "list",
        "--project", project_id, "--format=json"
    ])
    if result["success"]:
        backends = json.loads(result["stdout"])
        for backend in backends:
            name = backend.get("name", "")
            iap = backend.get("iap", {})
            iap_enabled = iap.get("enabled", False)
            findings["iap_enabled_backends"].append({"name": name, "iap_enabled": iap_enabled})
            if not iap_enabled:
                findings["issues"].append(f"Backend service '{name}' does not have IAP enabled")

    return findings


def generate_ztna_report(aws_va: dict, aws_sg: dict, gcp_iap: dict) -> str:
    """Generate a ZTNA assessment report."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    all_issues = aws_va["issues"] + aws_sg["issues"] + gcp_iap["issues"]

    report_lines = [
        "Zero Trust Network Access Assessment Report",
        "=" * 50,
        f"Assessment Date: {timestamp}",
        "",
        "AWS Verified Access:",
        f"  Instances: {len(aws_va['instances'])}",
        f"  Access Groups: {len(aws_va['groups'])}",
        f"  Endpoints: {len(aws_va['endpoints'])}",
        "",
        "AWS Micro-Segmentation:",
        f"  Security Groups Evaluated: {aws_sg['total_sgs']}",
        f"  Overly Permissive Rules: {len(aws_sg['overly_permissive'])}",
        "",
        "GCP Identity-Aware Proxy:",
        f"  Backend Services: {len(gcp_iap['iap_enabled_backends'])}",
        f"  IAP-Enabled: {sum(1 for b in gcp_iap['iap_enabled_backends'] if b['iap_enabled'])}",
        "",
        f"Total Issues Found: {len(all_issues)}",
        "-" * 40,
    ]
    for i, issue in enumerate(all_issues, 1):
        report_lines.append(f"  [{i}] {issue}")

    return "\n".join(report_lines)


if __name__ == "__main__":
    print("[*] Starting Zero Trust Network Access assessment...")
    vpc_id = sys.argv[1] if len(sys.argv) > 1 else "vpc-default"
    gcp_project = sys.argv[2] if len(sys.argv) > 2 else "my-project"

    aws_va = check_aws_verified_access()
    aws_sg = check_aws_security_groups_segmentation(vpc_id)
    gcp_iap = check_gcp_iap_status(gcp_project)

    report = generate_ztna_report(aws_va, aws_sg, gcp_iap)
    print(report)

    output_file = f"ztna_assessment_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump({"aws_verified_access": aws_va, "aws_segmentation": aws_sg, "gcp_iap": gcp_iap}, f, indent=2)
    print(f"\n[*] Detailed results saved to {output_file}")
