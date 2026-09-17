#!/usr/bin/env python3
"""Sigstore Software Signing Agent - Automates cosign keyless signing, Rekor
transparency log verification, and Fulcio certificate inspection for container
images and software artifacts."""

import json
import logging
import argparse
import subprocess
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

REKOR_PUBLIC_URL = "https://rekor.sigstore.dev"
FULCIO_PUBLIC_URL = "https://fulcio.sigstore.dev"


def compute_sha256(filepath):
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def run_cosign(args, capture=True):
    """Execute a cosign CLI command and return the result."""
    cmd = ["cosign"] + args
    logger.info("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=capture, text=True, timeout=120)
    if result.returncode != 0:
        logger.error("cosign failed (exit %d): %s", result.returncode, result.stderr)
    return result


def check_cosign_installed():
    """Verify cosign CLI is available and return version info."""
    result = run_cosign(["version"])
    if result.returncode != 0:
        logger.error("cosign is not installed or not in PATH")
        return None
    version_line = ""
    for line in result.stdout.splitlines():
        if "cosign" in line.lower() or "GitVersion" in line:
            version_line = line.strip()
            break
    return version_line or result.stdout.strip()


def sign_blob_keyless(filepath, bundle_path=None):
    """Sign a file blob using cosign keyless signing with Fulcio and Rekor.

    This triggers an OIDC authentication flow. In CI, set SIGSTORE_ID_TOKEN
    environment variable to provide the identity token non-interactively.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        return {"error": f"File not found: {filepath}", "signed": False}

    if bundle_path is None:
        bundle_path = str(filepath) + ".sigstore.json"

    args = ["sign-blob", str(filepath), "--bundle", bundle_path, "--yes"]
    result = run_cosign(args)

    if result.returncode == 0:
        logger.info("Blob signed successfully: %s", filepath)
        bundle_data = {}
        try:
            with open(bundle_path, "r") as f:
                bundle_data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            pass
        return {
            "signed": True,
            "file": str(filepath),
            "bundle": bundle_path,
            "sha256": compute_sha256(filepath),
            "has_rekor_entry": "rekorBundle" in bundle_data
            or "verificationMaterial" in bundle_data,
        }
    return {"signed": False, "file": str(filepath), "error": result.stderr.strip()}


def verify_blob_keyless(filepath, bundle_path, cert_identity, cert_oidc_issuer):
    """Verify a signed blob against expected identity and OIDC issuer."""
    filepath = Path(filepath)
    if not filepath.exists():
        return {"error": f"File not found: {filepath}", "verified": False}

    args = [
        "verify-blob",
        str(filepath),
        "--bundle",
        bundle_path,
        "--certificate-identity",
        cert_identity,
        "--certificate-oidc-issuer",
        cert_oidc_issuer,
    ]
    result = run_cosign(args)

    return {
        "verified": result.returncode == 0,
        "file": str(filepath),
        "certificate_identity": cert_identity,
        "certificate_oidc_issuer": cert_oidc_issuer,
        "output": result.stdout.strip() if result.returncode == 0 else result.stderr.strip(),
    }


def sign_container_keyless(image_uri):
    """Sign a container image using cosign keyless signing.

    The image_uri should include the digest (e.g., registry/image@sha256:abc...).
    Signing by tag instead of digest is unreliable because tags are mutable.
    """
    args = ["sign", image_uri, "--yes"]
    result = run_cosign(args)

    return {
        "signed": result.returncode == 0,
        "image": image_uri,
        "output": result.stdout.strip() if result.returncode == 0 else result.stderr.strip(),
    }


def verify_container_keyless(image_uri, cert_identity, cert_oidc_issuer):
    """Verify a container image signature against expected identity and issuer."""
    args = [
        "verify",
        image_uri,
        "--certificate-identity",
        cert_identity,
        "--certificate-oidc-issuer",
        cert_oidc_issuer,
    ]
    result = run_cosign(args)

    verification_details = []
    if result.returncode == 0:
        try:
            verification_details = json.loads(result.stdout)
        except json.JSONDecodeError:
            verification_details = [{"raw_output": result.stdout.strip()}]

    return {
        "verified": result.returncode == 0,
        "image": image_uri,
        "certificate_identity": cert_identity,
        "certificate_oidc_issuer": cert_oidc_issuer,
        "signatures": verification_details,
    }


def search_rekor_by_hash(artifact_hash, rekor_url=None):
    """Search the Rekor transparency log for entries matching an artifact hash.

    Queries the Rekor REST API /api/v1/index/retrieve endpoint.
    """
    base = rekor_url or REKOR_PUBLIC_URL
    url = f"{base}/api/v1/index/retrieve"
    payload = {"hash": f"sha256:{artifact_hash}"}

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        uuids = resp.json()
        logger.info("Found %d Rekor entries for hash %s", len(uuids), artifact_hash[:16])
        return {"hash": artifact_hash, "entry_uuids": uuids, "count": len(uuids)}
    except requests.RequestException as e:
        logger.error("Rekor search failed: %s", e)
        return {"hash": artifact_hash, "entry_uuids": [], "error": str(e)}


def search_rekor_by_email(email, rekor_url=None):
    """Search the Rekor transparency log for entries matching an email identity."""
    base = rekor_url or REKOR_PUBLIC_URL
    url = f"{base}/api/v1/index/retrieve"
    payload = {"email": email}

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
        uuids = resp.json()
        logger.info("Found %d Rekor entries for email %s", len(uuids), email)
        return {"email": email, "entry_uuids": uuids, "count": len(uuids)}
    except requests.RequestException as e:
        logger.error("Rekor search failed: %s", e)
        return {"email": email, "entry_uuids": [], "error": str(e)}


def get_rekor_entry(uuid, rekor_url=None):
    """Retrieve a specific entry from the Rekor transparency log by UUID."""
    base = rekor_url or REKOR_PUBLIC_URL
    url = f"{base}/api/v1/log/entries/{uuid}"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        entry_data = resp.json()

        parsed = {"uuid": uuid, "raw": entry_data}
        for entry_uuid, entry_body in entry_data.items():
            parsed["log_index"] = entry_body.get("logIndex")
            parsed["integrated_time"] = entry_body.get("integratedTime")
            if parsed["integrated_time"]:
                parsed["integrated_time_iso"] = datetime.fromtimestamp(
                    parsed["integrated_time"], tz=timezone.utc
                ).isoformat()
            verification = entry_body.get("verification", {})
            parsed["has_inclusion_proof"] = "inclusionProof" in verification
            parsed["has_signed_entry_timestamp"] = "signedEntryTimestamp" in verification
            break

        return parsed
    except requests.RequestException as e:
        logger.error("Failed to retrieve Rekor entry %s: %s", uuid, e)
        return {"uuid": uuid, "error": str(e)}


def verify_rekor_entry(uuid, rekor_url=None):
    """Verify a Rekor entry's inclusion proof using the rekor-cli."""
    result = run_cosign(["env"])  # Check if rekor-cli is better
    rekor_result = subprocess.run(
        ["rekor-cli", "verify", "--rekor_server", rekor_url or REKOR_PUBLIC_URL,
         "--entry-uuid", uuid],
        capture_output=True, text=True, timeout=60,
    )
    return {
        "uuid": uuid,
        "inclusion_verified": rekor_result.returncode == 0,
        "output": rekor_result.stdout.strip() if rekor_result.returncode == 0
        else rekor_result.stderr.strip(),
    }


def get_rekor_log_info(rekor_url=None):
    """Retrieve the current Rekor transparency log state (tree size, root hash)."""
    base = rekor_url or REKOR_PUBLIC_URL
    url = f"{base}/api/v1/log"

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        log_info = resp.json()
        return {
            "tree_size": log_info.get("treeSize"),
            "root_hash": log_info.get("rootHash"),
            "signed_tree_head": log_info.get("signedTreeHead"),
            "tree_id": log_info.get("treeID"),
        }
    except requests.RequestException as e:
        logger.error("Failed to get Rekor log info: %s", e)
        return {"error": str(e)}


def audit_signing_event(filepath=None, image_uri=None, cert_identity=None,
                        cert_oidc_issuer=None, rekor_url=None):
    """Perform a complete audit of a signing event: verify the artifact and
    cross-reference against the Rekor transparency log."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifact": filepath or image_uri,
        "checks": [],
    }

    # Get Rekor log state
    log_info = get_rekor_log_info(rekor_url)
    report["rekor_log_state"] = log_info

    if filepath:
        artifact_hash = compute_sha256(filepath)
        report["artifact_sha256"] = artifact_hash

        # Search Rekor for this artifact
        rekor_search = search_rekor_by_hash(artifact_hash, rekor_url)
        report["rekor_entries"] = rekor_search
        report["checks"].append({
            "check": "rekor_entry_exists",
            "passed": rekor_search.get("count", 0) > 0,
            "detail": f"Found {rekor_search.get('count', 0)} Rekor entries",
        })

        # Retrieve entry details if found
        if rekor_search.get("entry_uuids"):
            first_uuid = rekor_search["entry_uuids"][0]
            entry_detail = get_rekor_entry(first_uuid, rekor_url)
            report["rekor_entry_detail"] = entry_detail
            report["checks"].append({
                "check": "inclusion_proof_present",
                "passed": entry_detail.get("has_inclusion_proof", False),
                "detail": "Inclusion proof found in Rekor entry"
                if entry_detail.get("has_inclusion_proof")
                else "No inclusion proof in Rekor entry",
            })

        # Verify blob if bundle and identity provided
        bundle_path = str(filepath) + ".sigstore.json"
        if Path(bundle_path).exists() and cert_identity and cert_oidc_issuer:
            verify_result = verify_blob_keyless(
                filepath, bundle_path, cert_identity, cert_oidc_issuer
            )
            report["verification"] = verify_result
            report["checks"].append({
                "check": "signature_verification",
                "passed": verify_result.get("verified", False),
                "detail": "Signature verified against identity and issuer"
                if verify_result.get("verified")
                else verify_result.get("output", "Verification failed"),
            })

    elif image_uri and cert_identity and cert_oidc_issuer:
        verify_result = verify_container_keyless(
            image_uri, cert_identity, cert_oidc_issuer
        )
        report["verification"] = verify_result
        report["checks"].append({
            "check": "container_signature_verification",
            "passed": verify_result.get("verified", False),
            "detail": f"Found {len(verify_result.get('signatures', []))} valid signatures"
            if verify_result.get("verified")
            else "Container signature verification failed",
        })

    # Summary
    passed = sum(1 for c in report["checks"] if c["passed"])
    total = len(report["checks"])
    report["summary"] = {
        "checks_passed": passed,
        "checks_total": total,
        "overall_status": "PASSED" if passed == total and total > 0 else "FAILED",
    }

    return report


def generate_report(results, output_path):
    """Write audit results to a JSON report file."""
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    logger.info("Report written to %s", output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Sigstore Software Signing Agent - Keyless signing, "
        "Rekor verification, and Fulcio certificate inspection"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # sign-blob
    sign_blob_p = sub.add_parser("sign-blob", help="Sign a file blob with keyless signing")
    sign_blob_p.add_argument("file", help="Path to file to sign")
    sign_blob_p.add_argument("--bundle", help="Output bundle path (default: <file>.sigstore.json)")

    # verify-blob
    verify_blob_p = sub.add_parser("verify-blob", help="Verify a signed blob")
    verify_blob_p.add_argument("file", help="Path to signed file")
    verify_blob_p.add_argument("--bundle", required=True, help="Path to sigstore bundle")
    verify_blob_p.add_argument("--cert-identity", required=True, help="Expected certificate identity")
    verify_blob_p.add_argument("--cert-oidc-issuer", required=True, help="Expected OIDC issuer URL")

    # sign-container
    sign_cont_p = sub.add_parser("sign-container", help="Sign a container image")
    sign_cont_p.add_argument("image", help="Container image URI (use digest, not tag)")

    # verify-container
    verify_cont_p = sub.add_parser("verify-container", help="Verify a container image signature")
    verify_cont_p.add_argument("image", help="Container image URI")
    verify_cont_p.add_argument("--cert-identity", required=True, help="Expected certificate identity")
    verify_cont_p.add_argument("--cert-oidc-issuer", required=True, help="Expected OIDC issuer URL")

    # search-rekor
    search_p = sub.add_parser("search-rekor", help="Search Rekor transparency log")
    search_group = search_p.add_mutually_exclusive_group(required=True)
    search_group.add_argument("--hash", help="SHA-256 hash of artifact to search")
    search_group.add_argument("--email", help="Email identity to search")
    search_group.add_argument("--file", help="File to compute hash and search")
    search_p.add_argument("--rekor-url", help="Custom Rekor server URL")

    # get-rekor-entry
    entry_p = sub.add_parser("get-rekor-entry", help="Retrieve a Rekor log entry")
    entry_p.add_argument("uuid", help="Rekor entry UUID")
    entry_p.add_argument("--rekor-url", help="Custom Rekor server URL")

    # log-info
    log_p = sub.add_parser("log-info", help="Get Rekor transparency log state")
    log_p.add_argument("--rekor-url", help="Custom Rekor server URL")

    # audit
    audit_p = sub.add_parser("audit", help="Full audit of a signing event")
    audit_group = audit_p.add_mutually_exclusive_group(required=True)
    audit_group.add_argument("--file", help="Path to signed file")
    audit_group.add_argument("--image", help="Container image URI")
    audit_p.add_argument("--cert-identity", help="Expected certificate identity")
    audit_p.add_argument("--cert-oidc-issuer", help="Expected OIDC issuer URL")
    audit_p.add_argument("--rekor-url", help="Custom Rekor server URL")

    # check
    sub.add_parser("check", help="Verify cosign is installed and reachable")

    parser.add_argument("--output", default="sigstore_report.json", help="Output report path")
    args = parser.parse_args()

    result = {}

    if args.command == "check":
        version = check_cosign_installed()
        log_info = get_rekor_log_info()
        result = {
            "cosign_installed": version is not None,
            "cosign_version": version,
            "rekor_reachable": "error" not in log_info,
            "rekor_tree_size": log_info.get("tree_size"),
        }

    elif args.command == "sign-blob":
        result = sign_blob_keyless(args.file, args.bundle)

    elif args.command == "verify-blob":
        result = verify_blob_keyless(
            args.file, args.bundle, args.cert_identity, args.cert_oidc_issuer
        )

    elif args.command == "sign-container":
        result = sign_container_keyless(args.image)

    elif args.command == "verify-container":
        result = verify_container_keyless(
            args.image, args.cert_identity, args.cert_oidc_issuer
        )

    elif args.command == "search-rekor":
        rekor_url = getattr(args, "rekor_url", None)
        if args.hash:
            result = search_rekor_by_hash(args.hash, rekor_url)
        elif args.email:
            result = search_rekor_by_email(args.email, rekor_url)
        elif args.file:
            file_hash = compute_sha256(args.file)
            result = search_rekor_by_hash(file_hash, rekor_url)
            result["file"] = args.file
            result["computed_hash"] = file_hash

    elif args.command == "get-rekor-entry":
        result = get_rekor_entry(args.uuid, getattr(args, "rekor_url", None))

    elif args.command == "log-info":
        result = get_rekor_log_info(getattr(args, "rekor_url", None))

    elif args.command == "audit":
        result = audit_signing_event(
            filepath=getattr(args, "file", None),
            image_uri=getattr(args, "image", None),
            cert_identity=getattr(args, "cert_identity", None),
            cert_oidc_issuer=getattr(args, "cert_oidc_issuer", None),
            rekor_url=getattr(args, "rekor_url", None),
        )

    print(json.dumps(result, indent=2, default=str))
    generate_report(result, args.output)


if __name__ == "__main__":
    main()
