#!/usr/bin/env python3
"""
in-toto Supply Chain Verification Tool

Verifies container image supply chain integrity by checking
in-toto link metadata against the defined layout policy.
"""

import json
import subprocess
import sys
import argparse
import hashlib
from pathlib import Path
from datetime import datetime


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute the hash of a file."""
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def find_link_files(link_dir: str) -> list[dict]:
    """Find and parse all in-toto link metadata files."""
    link_path = Path(link_dir)
    if not link_path.exists():
        print(f"[ERROR] Link directory not found: {link_dir}")
        return []

    links = []
    for link_file in link_path.glob("*.link"):
        try:
            with open(link_file) as f:
                data = json.load(f)
            links.append({
                "file": str(link_file),
                "step_name": data.get("signed", {}).get("name", "unknown"),
                "materials": data.get("signed", {}).get("materials", {}),
                "products": data.get("signed", {}).get("products", {}),
                "command": data.get("signed", {}).get("command", []),
                "byproducts": data.get("signed", {}).get("byproducts", {}),
                "signatures": data.get("signatures", []),
            })
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[WARN] Failed to parse {link_file}: {e}")

    return links


def verify_artifact_chain(links: list[dict]) -> list[dict]:
    """Verify that artifact hashes chain correctly between steps."""
    findings = []
    products_by_step = {}

    for link in sorted(links, key=lambda x: x["step_name"]):
        products_by_step[link["step_name"]] = link["products"]

    for link in links:
        for material_path, material_hashes in link["materials"].items():
            found = False
            for step_name, products in products_by_step.items():
                if step_name == link["step_name"]:
                    continue
                if material_path in products:
                    product_hashes = products[material_path]
                    for algo, expected_hash in material_hashes.items():
                        actual_hash = product_hashes.get(algo, "")
                        if actual_hash and actual_hash != expected_hash:
                            findings.append({
                                "severity": "CRITICAL",
                                "type": "hash_mismatch",
                                "step": link["step_name"],
                                "artifact": material_path,
                                "expected": expected_hash[:16] + "...",
                                "actual": actual_hash[:16] + "...",
                                "description": f"Artifact {material_path} hash mismatch between steps"
                            })
                        elif actual_hash:
                            found = True
            if not found and link["materials"]:
                findings.append({
                    "severity": "WARNING",
                    "type": "untracked_material",
                    "step": link["step_name"],
                    "artifact": material_path,
                    "description": f"Material {material_path} not found in any prior step products"
                })

    return findings


def verify_signatures(links: list[dict], trusted_keys: list[str]) -> list[dict]:
    """Verify that all link signatures come from trusted keys."""
    findings = []
    for link in links:
        if not link["signatures"]:
            findings.append({
                "severity": "CRITICAL",
                "type": "missing_signature",
                "step": link["step_name"],
                "description": f"Step {link['step_name']} has no signatures"
            })
            continue

        for sig in link["signatures"]:
            keyid = sig.get("keyid", "")
            if trusted_keys and keyid not in trusted_keys:
                findings.append({
                    "severity": "HIGH",
                    "type": "untrusted_key",
                    "step": link["step_name"],
                    "keyid": keyid[:16] + "...",
                    "description": f"Step {link['step_name']} signed by untrusted key"
                })

    return findings


def check_required_steps(links: list[dict], required_steps: list[str]) -> list[dict]:
    """Check that all required pipeline steps have link metadata."""
    findings = []
    observed_steps = {link["step_name"] for link in links}

    for step in required_steps:
        if step not in observed_steps:
            findings.append({
                "severity": "CRITICAL",
                "type": "missing_step",
                "step": step,
                "description": f"Required step '{step}' has no link metadata"
            })

    return findings


def run_in_toto_verify(layout_path: str, layout_key: str, link_dir: str) -> dict:
    """Run the official in-toto-verify command."""
    try:
        result = subprocess.run(
            [
                "in-toto-verify",
                "--layout", layout_path,
                "--layout-key", layout_key,
                "--link-dir", link_dir,
            ],
            capture_output=True, text=True, timeout=60
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode
        }
    except FileNotFoundError:
        return {"success": False, "error": "in-toto-verify not found in PATH"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Verification timed out"}


def generate_report(links: list[dict], chain_findings: list[dict],
                    sig_findings: list[dict], step_findings: list[dict],
                    verify_result: dict, output_format: str = "text") -> str:
    """Generate a comprehensive verification report."""
    all_findings = chain_findings + sig_findings + step_findings
    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")

    if output_format == "json":
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "verification_passed": verify_result.get("success", False) and critical_count == 0,
            "steps_found": len(links),
            "findings": {
                "critical": critical_count,
                "high": high_count,
                "total": len(all_findings),
                "details": all_findings
            },
            "in_toto_verify": verify_result,
            "steps": [{"name": l["step_name"], "command": l["command"],
                       "materials": len(l["materials"]), "products": len(l["products"])}
                      for l in links]
        }
        return json.dumps(report, indent=2)

    lines = []
    lines.append("=" * 70)
    lines.append("IN-TOTO SUPPLY CHAIN VERIFICATION REPORT")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}")
    lines.append("=" * 70)

    passed = verify_result.get("success", False) and critical_count == 0
    lines.append(f"\nVerification Result: {'PASSED' if passed else 'FAILED'}")
    lines.append(f"Steps Found: {len(links)}")

    lines.append("\n## Pipeline Steps")
    for link in sorted(links, key=lambda x: x["step_name"]):
        lines.append(f"  Step: {link['step_name']}")
        lines.append(f"    Command: {' '.join(link['command'])}")
        lines.append(f"    Materials: {len(link['materials'])} | Products: {len(link['products'])}")
        lines.append(f"    Signatures: {len(link['signatures'])}")

    if all_findings:
        lines.append(f"\n## Findings ({len(all_findings)} total)")
        for f in sorted(all_findings, key=lambda x: x["severity"]):
            lines.append(f"  [{f['severity']}] {f['description']}")

    if verify_result.get("error"):
        lines.append(f"\n## in-toto-verify Error")
        lines.append(f"  {verify_result['error']}")

    lines.append("\n" + "=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="in-toto Supply Chain Verification Tool")
    parser.add_argument("--layout", help="Path to in-toto layout file")
    parser.add_argument("--layout-key", help="Path to layout signing public key")
    parser.add_argument("--link-dir", required=True, help="Directory containing link metadata")
    parser.add_argument("--required-steps", nargs="+", default=["checkout", "build", "scan"],
                        help="Required pipeline steps")
    parser.add_argument("--trusted-keys", nargs="+", default=[], help="Trusted key IDs")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    links = find_link_files(args.link_dir)
    if not links:
        print("[ERROR] No link metadata found")
        sys.exit(1)

    chain_findings = verify_artifact_chain(links)
    sig_findings = verify_signatures(links, args.trusted_keys)
    step_findings = check_required_steps(links, args.required_steps)

    verify_result = {}
    if args.layout and args.layout_key:
        verify_result = run_in_toto_verify(args.layout, args.layout_key, args.link_dir)
    else:
        verify_result = {"success": None, "note": "Layout verification skipped (no --layout provided)"}

    report = generate_report(links, chain_findings, sig_findings, step_findings, verify_result, args.format)
    print(report)

    critical_count = sum(1 for f in chain_findings + sig_findings + step_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()
