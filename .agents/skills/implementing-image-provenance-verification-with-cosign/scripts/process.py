#!/usr/bin/env python3
"""
Cosign Image Provenance Manager - Sign, verify, and audit container
image signatures using Sigstore Cosign.
"""

import json
import subprocess
import sys
import argparse
from pathlib import Path


def run_cosign(args: list) -> dict:
    """Execute cosign command and return output."""
    cmd = ["cosign"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }


def sign_image(image: str, key: str = None, annotations: dict = None, keyless: bool = False) -> bool:
    """Sign a container image."""
    args = ["sign"]
    if key:
        args.extend(["--key", key])
    if keyless:
        args.append("--yes")
    if annotations:
        for k, v in annotations.items():
            args.extend(["-a", f"{k}={v}"])
    args.append(image)

    result = run_cosign(args)
    if result["returncode"] == 0:
        print(f"Successfully signed: {image}")
        return True
    else:
        print(f"Failed to sign: {result['stderr']}", file=sys.stderr)
        return False


def verify_image(image: str, key: str = None, identity: str = None,
                 issuer: str = None) -> dict:
    """Verify a container image signature."""
    args = ["verify"]
    if key:
        args.extend(["--key", key])
    if identity:
        args.extend(["--certificate-identity", identity])
    if issuer:
        args.extend(["--certificate-oidc-issuer", issuer])
    args.append(image)

    result = run_cosign(args)
    verified = result["returncode"] == 0

    signatures = []
    if verified and result["stdout"].strip():
        try:
            signatures = json.loads(result["stdout"])
        except json.JSONDecodeError:
            pass

    return {
        "image": image,
        "verified": verified,
        "signatures": signatures,
        "error": result["stderr"] if not verified else None,
    }


def verify_attestation(image: str, att_type: str, key: str = None,
                       identity: str = None, issuer: str = None) -> dict:
    """Verify an attestation on a container image."""
    args = ["verify-attestation", "--type", att_type]
    if key:
        args.extend(["--key", key])
    if identity:
        args.extend(["--certificate-identity", identity])
    if issuer:
        args.extend(["--certificate-oidc-issuer", issuer])
    args.append(image)

    result = run_cosign(args)
    return {
        "image": image,
        "type": att_type,
        "verified": result["returncode"] == 0,
        "output": result["stdout"],
        "error": result["stderr"] if result["returncode"] != 0 else None,
    }


def audit_images(images: list, key: str = None, identity: str = None,
                 issuer: str = None) -> list:
    """Audit multiple images for valid signatures."""
    results = []
    for image in images:
        result = verify_image(image, key=key, identity=identity, issuer=issuer)
        results.append(result)
    return results


def generate_report(audit_results: list) -> str:
    """Generate markdown audit report."""
    signed = sum(1 for r in audit_results if r["verified"])
    total = len(audit_results)

    report = f"""# Image Signature Audit Report

**Total Images:** {total}
**Signed:** {signed}
**Unsigned:** {total - signed}

## Results

| Image | Signed | Signatures | Error |
|-------|--------|------------|-------|
"""
    for r in audit_results:
        status = "YES" if r["verified"] else "NO"
        sig_count = len(r.get("signatures", []))
        error = r.get("error", "")[:50] if r.get("error") else "-"
        report += f"| `{r['image']}` | {status} | {sig_count} | {error} |\n"

    return report


def main():
    parser = argparse.ArgumentParser(description="Cosign Image Provenance Manager")
    subparsers = parser.add_subparsers(dest="command")

    sign_cmd = subparsers.add_parser("sign", help="Sign an image")
    sign_cmd.add_argument("image", help="Image reference")
    sign_cmd.add_argument("--key", help="Signing key path")
    sign_cmd.add_argument("--keyless", action="store_true", help="Use keyless signing")
    sign_cmd.add_argument("--annotation", "-a", action="append", help="key=value annotations")

    verify_cmd = subparsers.add_parser("verify", help="Verify image signature")
    verify_cmd.add_argument("image", help="Image reference")
    verify_cmd.add_argument("--key", help="Public key path")
    verify_cmd.add_argument("--identity", help="Certificate identity")
    verify_cmd.add_argument("--issuer", help="OIDC issuer")

    audit_cmd = subparsers.add_parser("audit", help="Audit multiple images")
    audit_cmd.add_argument("--images-file", required=True, help="File with image refs (one per line)")
    audit_cmd.add_argument("--key", help="Public key path")
    audit_cmd.add_argument("--identity", help="Certificate identity")
    audit_cmd.add_argument("--issuer", help="OIDC issuer")
    audit_cmd.add_argument("--report", help="Output report path")

    args = parser.parse_args()

    if args.command == "sign":
        annotations = {}
        if args.annotation:
            for a in args.annotation:
                k, v = a.split("=", 1)
                annotations[k] = v
        sign_image(args.image, key=args.key, annotations=annotations,
                  keyless=args.keyless)

    elif args.command == "verify":
        result = verify_image(args.image, key=args.key,
                            identity=args.identity, issuer=args.issuer)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["verified"] else 1)

    elif args.command == "audit":
        images = Path(args.images_file).read_text().strip().split("\n")
        results = audit_images(images, key=args.key,
                             identity=args.identity, issuer=args.issuer)
        report = generate_report(results)
        if args.report:
            Path(args.report).write_text(report)
            print(f"Report written to {args.report}")
        else:
            print(report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
