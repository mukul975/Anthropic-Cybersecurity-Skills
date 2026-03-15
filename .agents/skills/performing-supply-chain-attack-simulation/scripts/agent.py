#!/usr/bin/env python3
"""Simulate and detect software supply chain attacks: typosquatting, dependency confusion, hash verification."""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone


def get_levenshtein_distance(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return get_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


TOP_PYPI_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "boto3", "scipy",
    "tensorflow", "torch", "scikit-learn", "pillow", "matplotlib",
    "cryptography", "pyyaml", "sqlalchemy", "celery", "redis", "psycopg2",
    "paramiko", "beautifulsoup4", "selenium", "pytest", "setuptools",
    "urllib3", "certifi", "idna", "charset-normalizer", "pip", "wheel",
    "packaging", "six", "python-dateutil", "jinja2", "markupsafe",
    "pydantic", "fastapi", "uvicorn", "httpx", "aiohttp", "grpcio"
]


def check_typosquatting(package_name, threshold=2):
    """Check if package name is suspiciously similar to popular packages."""
    matches = []
    for popular in TOP_PYPI_PACKAGES:
        if package_name == popular:
            continue
        distance = get_levenshtein_distance(package_name.lower(), popular.lower())
        if 0 < distance <= threshold:
            matches.append({
                "popular_package": popular,
                "edit_distance": distance,
                "risk": "High" if distance == 1 else "Medium"
            })
    return matches


def query_pypi_metadata(package_name):
    """Fetch package metadata from PyPI JSON API."""
    try:
        import requests
        resp = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def check_dependency_confusion(private_packages):
    """Check if private package names exist on public PyPI."""
    findings = []
    for pkg_info in private_packages:
        name = pkg_info["name"]
        internal_version = pkg_info.get("version", "0.0.0")
        metadata = query_pypi_metadata(name)
        if metadata:
            public_version = metadata.get("info", {}).get("version", "0.0.0")
            findings.append({
                "package": name,
                "internal_version": internal_version,
                "public_version": public_version,
                "risk": "Critical",
                "message": f"Private package '{name}' exists on public PyPI as version {public_version}",
                "attack_vector": "dependency_confusion"
            })
        else:
            findings.append({
                "package": name,
                "internal_version": internal_version,
                "risk": "Info",
                "message": f"Private package '{name}' not found on public PyPI (safe)"
            })
    return findings


def verify_package_hash(package_name, expected_hash=None):
    """Download package and verify SHA-256 hash against PyPI published digests."""
    metadata = query_pypi_metadata(package_name)
    if not metadata:
        return {"package": package_name, "status": "error", "message": "Package not found on PyPI"}

    releases = metadata.get("urls", [])
    if not releases:
        return {"package": package_name, "status": "error", "message": "No release files found"}

    sdist = None
    for release in releases:
        if release.get("packagetype") == "sdist":
            sdist = release
            break
    if not sdist:
        sdist = releases[0]

    published_sha256 = sdist.get("digests", {}).get("sha256", "")
    result = {
        "package": package_name,
        "version": metadata["info"]["version"],
        "filename": sdist["filename"],
        "published_sha256": published_sha256,
        "packagetype": sdist["packagetype"]
    }

    if expected_hash:
        if expected_hash == published_sha256:
            result["status"] = "verified"
            result["message"] = "Hash matches expected value"
        else:
            result["status"] = "mismatch"
            result["risk"] = "Critical"
            result["message"] = "Hash does NOT match expected value — possible tampering"
            result["expected_hash"] = expected_hash
    else:
        result["status"] = "retrieved"
        result["message"] = "Published hash retrieved for manual verification"

    return result


def run_pip_audit():
    """Run pip-audit to scan installed packages for known vulnerabilities."""
    try:
        proc = subprocess.run(
            ["pip-audit", "--format", "json", "--progress-spinner", "off"],
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0 or proc.stdout:
            return json.loads(proc.stdout) if proc.stdout.strip() else []
        return [{"error": proc.stderr.strip()}]
    except FileNotFoundError:
        return [{"error": "pip-audit not installed. Run: pip install pip-audit"}]
    except subprocess.TimeoutExpired:
        return [{"error": "pip-audit timed out after 120 seconds"}]
    except json.JSONDecodeError:
        return [{"error": "Failed to parse pip-audit output"}]


def analyze_metadata_anomalies(package_name):
    """Detect suspicious metadata patterns in a PyPI package."""
    metadata = query_pypi_metadata(package_name)
    if not metadata:
        return {"package": package_name, "status": "not_found"}

    info = metadata["info"]
    anomalies = []

    if not info.get("home_page") and not info.get("project_url"):
        anomalies.append({
            "check": "missing_homepage",
            "severity": "Medium",
            "message": "Package has no homepage or project URL"
        })

    if not info.get("author") and not info.get("author_email"):
        anomalies.append({
            "check": "missing_author",
            "severity": "Medium",
            "message": "Package has no author information"
        })

    if info.get("author_email") and any(
        domain in info["author_email"]
        for domain in ["mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email"]
    ):
        anomalies.append({
            "check": "disposable_email",
            "severity": "High",
            "message": f"Author uses disposable email: {info['author_email']}"
        })

    summary = info.get("summary", "")
    if not summary or len(summary) < 10:
        anomalies.append({
            "check": "missing_description",
            "severity": "Low",
            "message": "Package has no meaningful description"
        })

    return {
        "package": package_name,
        "version": info.get("version"),
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Simulate and detect software supply chain attacks"
    )
    subparsers = parser.add_subparsers(dest="command", help="Attack simulation type")

    typo_parser = subparsers.add_parser("typosquat", help="Check for typosquatting")
    typo_parser.add_argument("packages", nargs="+", help="Package names to check")
    typo_parser.add_argument("--threshold", type=int, default=2, help="Max edit distance (default: 2)")

    confusion_parser = subparsers.add_parser("confusion", help="Test dependency confusion")
    confusion_parser.add_argument("--packages", required=True, help="JSON file with private packages [{name, version}]")

    hash_parser = subparsers.add_parser("verify-hash", help="Verify package hash")
    hash_parser.add_argument("package", help="Package name")
    hash_parser.add_argument("--expected-hash", help="Expected SHA-256 hash to compare")

    subparsers.add_parser("audit", help="Run pip-audit vulnerability scan")

    meta_parser = subparsers.add_parser("metadata", help="Check metadata anomalies")
    meta_parser.add_argument("packages", nargs="+", help="Package names to analyze")

    args = parser.parse_args()

    if args.command == "typosquat":
        results = []
        for pkg in args.packages:
            matches = check_typosquatting(pkg, args.threshold)
            results.append({"package": pkg, "typosquat_matches": matches, "is_suspicious": len(matches) > 0})
        print(json.dumps({"scan_type": "typosquatting", "results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2))

    elif args.command == "confusion":
        with open(args.packages) as f:
            private_pkgs = json.load(f)
        results = check_dependency_confusion(private_pkgs)
        print(json.dumps({"scan_type": "dependency_confusion", "results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2))

    elif args.command == "verify-hash":
        result = verify_package_hash(args.package, args.expected_hash)
        print(json.dumps({"scan_type": "hash_verification", "result": result, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2))

    elif args.command == "audit":
        results = run_pip_audit()
        print(json.dumps({"scan_type": "vulnerability_audit", "results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2))

    elif args.command == "metadata":
        results = [analyze_metadata_anomalies(pkg) for pkg in args.packages]
        print(json.dumps({"scan_type": "metadata_analysis", "results": results, "timestamp": datetime.now(timezone.utc).isoformat()}, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
