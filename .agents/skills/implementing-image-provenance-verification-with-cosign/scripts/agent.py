#!/usr/bin/env python3
"""Agent for verifying container image provenance using Sigstore Cosign."""

import json
import argparse
import subprocess
from datetime import datetime


def run_cosign(args_list):
    """Run a cosign CLI command and return output."""
    cmd = ["cosign"] + args_list
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return {
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "returncode": result.returncode,
    }


def verify_image(image_ref, key=None, certificate_identity=None, certificate_oidc_issuer=None):
    """Verify a container image signature with Cosign."""
    args = ["verify"]
    if key:
        args.extend(["--key", key])
    elif certificate_identity and certificate_oidc_issuer:
        args.extend(["--certificate-identity", certificate_identity,
                      "--certificate-oidc-issuer", certificate_oidc_issuer])
    args.append(image_ref)
    result = run_cosign(args)
    verified = result["returncode"] == 0
    attestations = []
    if verified and result["stdout"]:
        try:
            attestations = json.loads(result["stdout"])
        except json.JSONDecodeError:
            pass
    return {
        "image": image_ref,
        "verified": verified,
        "attestations": attestations if isinstance(attestations, list) else [attestations],
        "error": result["stderr"] if not verified else None,
    }


def verify_attestation(image_ref, predicate_type, key=None):
    """Verify an in-toto attestation attached to an image."""
    args = ["verify-attestation", "--type", predicate_type]
    if key:
        args.extend(["--key", key])
    args.append(image_ref)
    result = run_cosign(args)
    return {
        "image": image_ref,
        "predicate_type": predicate_type,
        "verified": result["returncode"] == 0,
        "output": result["stdout"][:500] if result["stdout"] else None,
        "error": result["stderr"] if result["returncode"] != 0 else None,
    }


def sign_image(image_ref, key=None, keyless=False):
    """Sign a container image with Cosign."""
    args = ["sign"]
    if key:
        args.extend(["--key", key])
    elif keyless:
        args.append("--yes")
    args.append(image_ref)
    result = run_cosign(args)
    return {
        "image": image_ref,
        "signed": result["returncode"] == 0,
        "error": result["stderr"] if result["returncode"] != 0 else None,
    }


def triangulate_image(image_ref):
    """Get the signature and attestation image references."""
    result = run_cosign(["triangulate", image_ref])
    return {
        "image": image_ref,
        "signature_ref": result["stdout"] if result["returncode"] == 0 else None,
    }


def audit_registry_images(images_list, key=None, identity=None, issuer=None):
    """Audit multiple container images for valid signatures."""
    results = []
    for image in images_list:
        result = verify_image(image, key=key, certificate_identity=identity,
                              certificate_oidc_issuer=issuer)
        result["severity"] = "INFO" if result["verified"] else "HIGH"
        results.append(result)
    signed = sum(1 for r in results if r["verified"])
    return {
        "total_images": len(results),
        "signed": signed,
        "unsigned": len(results) - signed,
        "signing_rate": round(signed / len(results) * 100, 1) if results else 0,
        "details": results,
    }


def generate_kyverno_policy(image_patterns, key=None, identity=None, issuer=None):
    """Generate Kyverno ClusterPolicy for image verification."""
    policy = {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {"name": "verify-image-signatures"},
        "spec": {
            "validationFailureAction": "Enforce",
            "webhookTimeoutSeconds": 30,
            "rules": [{
                "name": "verify-cosign-signature",
                "match": {"any": [{"resources": {"kinds": ["Pod"]}}]},
                "verifyImages": [{
                    "imageReferences": image_patterns,
                    "attestors": [{
                        "entries": [{
                            "keyless": {
                                "subject": identity or "*",
                                "issuer": issuer or "https://token.actions.githubusercontent.com",
                            }
                        }] if not key else [{"keys": {"publicKeys": key}}]
                    }],
                }],
            }],
        },
    }
    return policy


def generate_cosign_ci_workflow(image_ref, registry):
    """Generate GitHub Actions workflow for Cosign signing."""
    return f"""name: Sign Container Image
on:
  push:
    branches: [main]
jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: sigstore/cosign-installer@v3
      - name: Login to registry
        uses: docker/login-action@v3
        with:
          registry: {registry}
      - name: Build and push
        run: |
          docker build -t {image_ref} .
          docker push {image_ref}
      - name: Sign image (keyless)
        run: cosign sign --yes {image_ref}
      - name: Verify signature
        run: cosign verify --certificate-identity-regexp=".*" --certificate-oidc-issuer="https://token.actions.githubusercontent.com" {image_ref}
"""


def main():
    parser = argparse.ArgumentParser(description="Cosign Image Provenance Agent")
    parser.add_argument("--verify", help="Image to verify")
    parser.add_argument("--sign", help="Image to sign")
    parser.add_argument("--audit", nargs="+", help="Images to audit for signatures")
    parser.add_argument("--key", help="Cosign public key for verification")
    parser.add_argument("--identity", help="Certificate identity for keyless verification")
    parser.add_argument("--issuer", help="OIDC issuer for keyless verification")
    parser.add_argument("--gen-policy", nargs="+", help="Image patterns for Kyverno policy")
    parser.add_argument("--gen-workflow", help="Image ref for CI workflow generation")
    parser.add_argument("--output", default="cosign_provenance_report.json")
    args = parser.parse_args()

    report = {"generated_at": datetime.utcnow().isoformat(), "results": {}}

    if args.verify:
        result = verify_image(args.verify, key=args.key,
                              certificate_identity=args.identity,
                              certificate_oidc_issuer=args.issuer)
        report["results"]["verification"] = result
        status = "VERIFIED" if result["verified"] else "FAILED"
        print(f"[+] {args.verify}: {status}")

    if args.audit:
        result = audit_registry_images(args.audit, key=args.key,
                                       identity=args.identity, issuer=args.issuer)
        report["results"]["audit"] = result
        print(f"[+] Audit: {result['signed']}/{result['total_images']} signed")

    if args.gen_policy:
        policy = generate_kyverno_policy(args.gen_policy, key=args.key,
                                          identity=args.identity, issuer=args.issuer)
        report["results"]["kyverno_policy"] = policy
        print("[+] Kyverno policy generated")

    if args.gen_workflow:
        workflow = generate_cosign_ci_workflow(args.gen_workflow, "ghcr.io")
        report["results"]["workflow"] = workflow
        print("[+] CI workflow generated")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
