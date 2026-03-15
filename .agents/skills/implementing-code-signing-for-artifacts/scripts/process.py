#!/usr/bin/env python3
"""
Artifact Code Signing Pipeline Script

Signs build artifacts using GPG and/or Sigstore cosign,
generates checksums, and produces a signing report.

Usage:
    python process.py --artifacts-dir ./dist --method gpg --gpg-key ci-signing@company.com
    python process.py --artifacts-dir ./dist --method sigstore --output signing-report.json
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class SigningResult:
    artifact: str
    sha256: str
    gpg_signature: str = ""
    gpg_verified: bool = False
    sigstore_signature: str = ""
    sigstore_certificate: str = ""
    sigstore_log_index: str = ""
    error: str = ""


def compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def sign_with_gpg(file_path: str, gpg_key: str) -> dict:
    """Sign a file with GPG detached signature."""
    sig_path = f"{file_path}.asc"
    cmd = [
        "gpg", "--batch", "--yes",
        "--detach-sign", "--armor",
        "--local-user", gpg_key,
        "--output", sig_path,
        file_path
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return {"signature": sig_path, "error": ""}
        return {"signature": "", "error": proc.stderr[:200]}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"signature": "", "error": str(e)}


def sign_with_cosign(file_path: str) -> dict:
    """Sign a file with Sigstore cosign keyless signing."""
    sig_path = f"{file_path}.sig"
    cert_path = f"{file_path}.cert"

    cmd = [
        "cosign", "sign-blob", file_path,
        "--output-signature", sig_path,
        "--output-certificate", cert_path,
        "--yes"
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode == 0:
            log_index = ""
            for line in proc.stderr.split("\n"):
                if "tlog entry" in line.lower() or "log index" in line.lower():
                    parts = line.split(":")
                    if len(parts) > 1:
                        log_index = parts[-1].strip()
            return {
                "signature": sig_path,
                "certificate": cert_path,
                "log_index": log_index,
                "error": ""
            }
        return {"signature": "", "certificate": "", "log_index": "", "error": proc.stderr[:200]}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"signature": "", "certificate": "", "log_index": "", "error": str(e)}


def verify_gpg_signature(file_path: str, sig_path: str) -> bool:
    """Verify a GPG detached signature."""
    cmd = ["gpg", "--verify", sig_path, file_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def generate_checksums(artifacts_dir: str, artifacts: list) -> str:
    """Generate checksums file for all artifacts."""
    checksums_path = os.path.join(artifacts_dir, "checksums.sha256")
    lines = []
    for result in artifacts:
        filename = os.path.basename(result.artifact)
        lines.append(f"{result.sha256}  {filename}")

    with open(checksums_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return checksums_path


def main():
    parser = argparse.ArgumentParser(description="Artifact Code Signing Pipeline")
    parser.add_argument("--artifacts-dir", required=True, help="Directory containing artifacts to sign")
    parser.add_argument("--method", default="both", choices=["gpg", "sigstore", "both"])
    parser.add_argument("--gpg-key", default=None, help="GPG key identity for signing")
    parser.add_argument("--output", default="signing-report.json")
    parser.add_argument("--extensions", nargs="*", default=[".tar.gz", ".zip", ".whl", ".deb", ".rpm"],
                        help="File extensions to sign")
    args = parser.parse_args()

    artifacts_dir = os.path.abspath(args.artifacts_dir)
    results = []

    files_to_sign = []
    for f in sorted(Path(artifacts_dir).iterdir()):
        if f.is_file() and any(str(f).endswith(ext) for ext in args.extensions):
            files_to_sign.append(str(f))

    if not files_to_sign:
        print(f"[WARN] No artifacts found matching extensions: {args.extensions}")
        sys.exit(0)

    print(f"[*] Signing {len(files_to_sign)} artifacts in {artifacts_dir}")

    for file_path in files_to_sign:
        filename = os.path.basename(file_path)
        result = SigningResult(artifact=file_path, sha256=compute_sha256(file_path))

        if args.method in ("gpg", "both") and args.gpg_key:
            gpg_result = sign_with_gpg(file_path, args.gpg_key)
            result.gpg_signature = gpg_result["signature"]
            if gpg_result["signature"]:
                result.gpg_verified = verify_gpg_signature(file_path, gpg_result["signature"])
                print(f"  [GPG] {filename}: {'OK' if result.gpg_verified else 'FAILED'}")
            else:
                print(f"  [GPG] {filename}: ERROR - {gpg_result['error']}")

        if args.method in ("sigstore", "both"):
            cosign_result = sign_with_cosign(file_path)
            result.sigstore_signature = cosign_result.get("signature", "")
            result.sigstore_certificate = cosign_result.get("certificate", "")
            result.sigstore_log_index = cosign_result.get("log_index", "")
            if result.sigstore_signature:
                print(f"  [Sigstore] {filename}: OK (log: {result.sigstore_log_index})")
            else:
                print(f"  [Sigstore] {filename}: ERROR - {cosign_result.get('error', 'unknown')}")
                result.error = cosign_result.get("error", "")

        results.append(result)

    checksums_path = generate_checksums(artifacts_dir, results)
    print(f"\n[*] Checksums: {checksums_path}")

    report = {
        "metadata": {
            "signing_date": datetime.now(timezone.utc).isoformat(),
            "method": args.method,
            "artifacts_count": len(results)
        },
        "artifacts": [
            {
                "file": os.path.basename(r.artifact),
                "sha256": r.sha256,
                "gpg_signed": bool(r.gpg_signature),
                "gpg_verified": r.gpg_verified,
                "sigstore_signed": bool(r.sigstore_signature),
                "sigstore_log_index": r.sigstore_log_index
            }
            for r in results
        ]
    }

    output_path = os.path.abspath(args.output)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Report: {output_path}")

    all_signed = all(
        (r.gpg_verified or args.method == "sigstore") and
        (bool(r.sigstore_signature) or args.method == "gpg")
        for r in results
    )
    print(f"\n[{'PASS' if all_signed else 'FAIL'}] All artifacts signed: {all_signed}")
    if not all_signed:
        sys.exit(1)


if __name__ == "__main__":
    main()
