#!/usr/bin/env python3
"""AWS credential exposure detection agent using TruffleHog and AWS APIs."""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path


AWS_KEY_PATTERN = re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}')
AWS_SECRET_PATTERN = re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])')


def scan_repo_trufflehog(repo_path, json_output=True):
    """Run TruffleHog against a local git repository."""
    cmd = ["trufflehog", "git", f"file://{repo_path}", "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            try:
                finding = json.loads(line)
                findings.append({
                    "detector": finding.get("DetectorName", finding.get("SourceMetadata", {}).get("DetectorName")),
                    "verified": finding.get("Verified", False),
                    "raw": finding.get("Raw", "")[:50] + "..." if finding.get("Raw") else None,
                    "source": finding.get("SourceMetadata", {}),
                })
            except json.JSONDecodeError:
                continue
        return {"scan_type": "git_repo", "path": repo_path, "findings_count": len(findings), "findings": findings}
    except FileNotFoundError:
        return {"error": "TruffleHog not installed. Install with: pip install trufflehog"}
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 300s"}


def scan_github_org(org_name):
    """Scan an entire GitHub organization with TruffleHog."""
    cmd = ["trufflehog", "github", "--org", org_name, "--json"]
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        cmd.extend(["--token", token])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"scan_type": "github_org", "org": org_name, "findings_count": len(findings), "findings": findings[:50]}
    except FileNotFoundError:
        return {"error": "TruffleHog not installed"}
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 600s"}


def scan_file_for_aws_keys(file_path):
    """Scan a single file for AWS access key patterns."""
    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except Exception as e:
        return {"error": str(e)}

    access_keys = AWS_KEY_PATTERN.findall(content)
    secrets = AWS_SECRET_PATTERN.findall(content)

    return {
        "file": file_path,
        "access_keys_found": len(access_keys),
        "potential_secrets_found": len(secrets),
        "access_keys": access_keys,
    }


def scan_directory_recursive(directory):
    """Scan all files in a directory for AWS credentials."""
    findings = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
    skip_extensions = {".pyc", ".so", ".dll", ".exe", ".bin", ".jpg", ".png", ".gif", ".zip", ".tar", ".gz"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if Path(fname).suffix.lower() in skip_extensions:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read(1024 * 1024)
                keys = AWS_KEY_PATTERN.findall(content)
                if keys:
                    findings.append({
                        "file": fpath,
                        "access_keys": keys,
                        "line_numbers": [
                            i + 1 for i, line in enumerate(content.splitlines())
                            if AWS_KEY_PATTERN.search(line)
                        ],
                    })
            except Exception:
                continue

    return {"directory": directory, "files_with_keys": len(findings), "findings": findings}


def check_aws_key_status(access_key_id):
    """Check if an AWS access key is active using AWS CLI."""
    cmd = [
        "aws", "iam", "get-access-key-last-used",
        "--access-key-id", access_key_id,
        "--output", "json",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return {
                "access_key": access_key_id,
                "status": "active",
                "username": data.get("UserName", "unknown"),
                "last_used": data.get("AccessKeyLastUsed", {}),
            }
        return {"access_key": access_key_id, "status": "error", "message": result.stderr.strip()}
    except Exception as e:
        return {"access_key": access_key_id, "status": "error", "message": str(e)}


def deactivate_exposed_key(access_key_id, username):
    """Deactivate an exposed AWS access key."""
    cmd = [
        "aws", "iam", "update-access-key",
        "--access-key-id", access_key_id,
        "--user-name", username,
        "--status", "Inactive",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return {
            "action": "deactivate_key",
            "access_key": access_key_id,
            "success": result.returncode == 0,
            "error": result.stderr.strip() if result.returncode != 0 else None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        return {"action": "deactivate_key", "success": False, "error": str(e)}


def setup_git_secrets():
    """Install git-secrets hooks for the current repository."""
    commands = [
        ["git", "secrets", "--install"],
        ["git", "secrets", "--register-aws"],
    ]
    results = []
    for cmd in commands:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            results.append({"cmd": " ".join(cmd), "success": r.returncode == 0, "output": r.stdout.strip()})
        except Exception as e:
            results.append({"cmd": " ".join(cmd), "success": False, "error": str(e)})
    return results


def generate_report(target):
    """Generate a credential exposure scan report."""
    if os.path.isdir(os.path.join(target, ".git")):
        scan = scan_repo_trufflehog(target)
    elif os.path.isdir(target):
        scan = scan_directory_recursive(target)
    else:
        scan = scan_file_for_aws_keys(target)

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "target": target,
        "scan_results": scan,
    }


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "help"
    if action == "scan" and len(sys.argv) > 2:
        print(json.dumps(generate_report(sys.argv[2]), indent=2, default=str))
    elif action == "scan-org" and len(sys.argv) > 2:
        print(json.dumps(scan_github_org(sys.argv[2]), indent=2, default=str))
    elif action == "check-key" and len(sys.argv) > 2:
        print(json.dumps(check_aws_key_status(sys.argv[2]), indent=2))
    elif action == "deactivate" and len(sys.argv) > 3:
        print(json.dumps(deactivate_exposed_key(sys.argv[2], sys.argv[3]), indent=2))
    elif action == "git-secrets":
        print(json.dumps(setup_git_secrets(), indent=2))
    else:
        print("Usage: agent.py [scan <path>|scan-org <org>|check-key <key_id>|deactivate <key_id> <user>|git-secrets]")
