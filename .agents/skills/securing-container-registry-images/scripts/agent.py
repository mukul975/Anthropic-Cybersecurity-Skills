#!/usr/bin/env python3
"""Agent for auditing container registry image security: scanning, signing, and SBOM."""

import boto3
import subprocess
import json
import sys
import os
import argparse
from datetime import datetime


def scan_image_trivy(image, severity="HIGH,CRITICAL", output_format="json"):
    """Scan a container image with Trivy for vulnerabilities."""
    print(f"[*] Scanning {image} with Trivy...")
    cmd = ["trivy", "image", "--severity", severity, "--format", output_format, image]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if output_format == "json" and result.stdout:
            data = json.loads(result.stdout)
            total_vulns = 0
            for target in data.get("Results", []):
                vulns = target.get("Vulnerabilities", [])
                total_vulns += len(vulns)
                if vulns:
                    print(f"  Target: {target.get('Target', 'unknown')}: {len(vulns)} vulnerabilities")
                    for v in vulns[:5]:
                        print(f"    [{v.get('Severity', '?')}] {v.get('VulnerabilityID', '?')} "
                              f"- {v.get('PkgName', '?')} {v.get('InstalledVersion', '?')}")
            print(f"[*] Total vulnerabilities found: {total_vulns}")
            return data
        else:
            print(result.stdout)
            return None
    except FileNotFoundError:
        print("  [-] Trivy not installed. Install: brew install trivy")
        return None
    except subprocess.TimeoutExpired:
        print("  [-] Scan timed out")
        return None


def generate_sbom(image, output_format="spdx-json", output_file="sbom.json"):
    """Generate SBOM using Syft for a container image."""
    print(f"\n[*] Generating SBOM for {image}...")
    cmd = ["syft", image, "-o", output_format]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.stdout:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            data = json.loads(result.stdout)
            packages = data.get("packages", [])
            print(f"  [+] SBOM generated: {len(packages)} packages")
            print(f"  [+] Saved to {output_file}")
            return data
        return None
    except FileNotFoundError:
        print("  [-] Syft not installed. Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh")
        return None


def verify_image_signature(image, key_file=None):
    """Verify image signature using Cosign."""
    print(f"\n[*] Verifying signature for {image}...")
    cmd = ["cosign", "verify"]
    if key_file:
        cmd.extend(["--key", key_file])
    cmd.append(image)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"  [+] Signature VALID for {image}")
            return True
        else:
            print(f"  [-] Signature verification FAILED: {result.stderr.strip()}")
            return False
    except FileNotFoundError:
        print("  [-] Cosign not installed")
        return None


def audit_ecr_repository(repo_name, region="us-east-1"):
    """Audit an ECR repository for security configuration."""
    ecr = boto3.client("ecr", region_name=region)
    findings = []
    try:
        scan_config = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
        repo_uri = scan_config["repositoryUri"]
        print(f"\n[*] Auditing ECR repository: {repo_name}")
        print(f"  URI: {repo_uri}")

        img_scan = scan_config.get("imageScanningConfiguration", {})
        if not img_scan.get("scanOnPush", False):
            findings.append({"check": "scan_on_push", "status": "FAIL", "detail": "Scan on push disabled"})
            print("  [!] Scan on push: DISABLED")
        else:
            print("  [+] Scan on push: ENABLED")

        mutability = scan_config.get("imageTagMutability", "MUTABLE")
        if mutability == "MUTABLE":
            findings.append({"check": "tag_immutability", "status": "FAIL", "detail": "Tags are mutable"})
            print("  [!] Tag immutability: MUTABLE (tags can be overwritten)")
        else:
            print("  [+] Tag immutability: IMMUTABLE")

        try:
            lifecycle = ecr.get_lifecycle_policy(repositoryName=repo_name)
            print("  [+] Lifecycle policy: CONFIGURED")
        except ecr.exceptions.LifecyclePolicyNotFoundException:
            findings.append({"check": "lifecycle_policy", "status": "FAIL", "detail": "No lifecycle policy"})
            print("  [!] Lifecycle policy: NOT CONFIGURED")

        images = ecr.list_images(repositoryName=repo_name, filter={"tagStatus": "UNTAGGED"})
        untagged = len(images.get("imageIds", []))
        if untagged > 0:
            print(f"  [!] Untagged images: {untagged}")

    except ecr.exceptions.RepositoryNotFoundException:
        print(f"  [-] Repository '{repo_name}' not found")
    return findings


def get_ecr_scan_findings(repo_name, tag="latest", region="us-east-1"):
    """Get vulnerability scan findings for an ECR image."""
    ecr = boto3.client("ecr", region_name=region)
    try:
        response = ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId={"imageTag": tag},
        )
        findings = response.get("imageScanFindings", {})
        severity_counts = findings.get("findingSeverityCounts", {})
        print(f"\n[*] ECR scan findings for {repo_name}:{tag}")
        for sev, count in sorted(severity_counts.items()):
            print(f"  [{sev}] {count}")
        vuln_findings = findings.get("findings", [])
        for v in vuln_findings[:10]:
            print(f"  - {v.get('name', '?')}: {v.get('description', '')[:100]}")
        return findings
    except Exception as e:
        print(f"  [-] Error: {e}")
        return {}


def full_audit(image, repo_name=None, region="us-east-1", output_dir="."):
    """Run complete container image security audit."""
    print("[*] Starting container image security audit...")
    os.makedirs(output_dir, exist_ok=True)
    report = {"audit_date": datetime.now().isoformat(), "image": image}

    scan_results = scan_image_trivy(image)
    report["trivy_scan"] = scan_results

    sbom_path = os.path.join(output_dir, "sbom.json")
    sbom = generate_sbom(image, output_file=sbom_path)
    report["sbom_packages"] = len(sbom.get("packages", [])) if sbom else 0

    sig_valid = verify_image_signature(image)
    report["signature_valid"] = sig_valid

    if repo_name:
        ecr_findings = audit_ecr_repository(repo_name, region)
        report["ecr_audit"] = ecr_findings

    report_path = os.path.join(output_dir, "container_security_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Full report saved to {report_path}")


def main():
    parser = argparse.ArgumentParser(description="Container Registry Image Security Agent")
    parser.add_argument("action", choices=["scan", "sbom", "verify", "ecr-audit", "ecr-findings", "full-audit"])
    parser.add_argument("--image", help="Container image reference")
    parser.add_argument("--repo", help="ECR repository name")
    parser.add_argument("--tag", default="latest", help="Image tag for ECR scan results")
    parser.add_argument("--key", help="Cosign public key file")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("-o", "--output", default=".")
    args = parser.parse_args()

    if args.action == "scan":
        scan_image_trivy(args.image)
    elif args.action == "sbom":
        generate_sbom(args.image)
    elif args.action == "verify":
        verify_image_signature(args.image, args.key)
    elif args.action == "ecr-audit":
        audit_ecr_repository(args.repo, args.region)
    elif args.action == "ecr-findings":
        get_ecr_scan_findings(args.repo, args.tag, args.region)
    elif args.action == "full-audit":
        full_audit(args.image, args.repo, args.region, args.output)


if __name__ == "__main__":
    main()
