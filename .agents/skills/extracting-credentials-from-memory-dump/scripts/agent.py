#!/usr/bin/env python3
"""Memory dump credential extraction agent using volatility3 subprocess and pypykatz."""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

CLOUD_KEY_PATTERNS = [
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key"),
    (r"ASIA[A-Z0-9]{16}", "AWS Temp Key"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT/Azure Token"),
]

AUTH_STRING_PATTERNS = [
    r"(?i)bearer\s+[A-Za-z0-9_\-\.]+",
    r"(?i)authorization:\s*\S+",
    r"(?i)api[_-]key[=:]\s*\S+",
    r"(?i)password[=:]\s*\S+",
]


def verify_dump(dump_path: str) -> dict:
    """Verify memory dump exists and compute hash."""
    if not os.path.isfile(dump_path):
        logger.error("Memory dump not found: %s", dump_path)
        return {"valid": False}
    size = os.path.getsize(dump_path)
    with open(dump_path, "rb") as f:
        sha256 = hashlib.sha256(f.read(1024 * 1024)).hexdigest()
    return {"valid": True, "size_bytes": size, "sha256_1mb": sha256}


def run_vol3(dump_path: str, plugin: str, extra_args: Optional[List[str]] = None) -> str:
    """Run a volatility3 plugin and return stdout."""
    cmd = ["vol", "-f", dump_path, plugin]
    if extra_args:
        cmd.extend(extra_args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0 and result.stderr:
            logger.warning("vol3 %s stderr: %s", plugin, result.stderr[:200])
        return result.stdout
    except FileNotFoundError:
        logger.error("volatility3 (vol) not found in PATH")
        return ""
    except subprocess.TimeoutExpired:
        logger.error("vol3 %s timed out", plugin)
        return ""


def get_os_info(dump_path: str) -> dict:
    """Identify OS version from memory dump."""
    output = run_vol3(dump_path, "windows.info")
    info = {}
    for line in output.splitlines():
        if "\t" in line:
            parts = line.split("\t", 1)
            if len(parts) == 2:
                info[parts[0].strip()] = parts[1].strip()
    return info


def find_lsass_pid(dump_path: str) -> Optional[int]:
    """Find LSASS process PID from process list."""
    output = run_vol3(dump_path, "windows.pslist")
    for line in output.splitlines():
        if "lsass.exe" in line.lower():
            parts = line.split()
            for p in parts:
                if p.isdigit():
                    return int(p)
    return None


def extract_hashdump(dump_path: str) -> List[dict]:
    """Extract SAM hashes using windows.hashdump."""
    output = run_vol3(dump_path, "windows.hashdump")
    results = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1].isdigit():
            results.append({
                "user": parts[0], "rid": int(parts[1]),
                "lm_hash": parts[2], "ntlm_hash": parts[3],
            })
    logger.info("Extracted %d SAM hashes", len(results))
    return results


def extract_lsadump(dump_path: str) -> List[dict]:
    """Extract LSA secrets using windows.lsadump."""
    output = run_vol3(dump_path, "windows.lsadump")
    results = []
    for line in output.splitlines():
        line = line.strip()
        if line and not line.startswith("Offset") and not line.startswith("-"):
            results.append({"raw": line})
    logger.info("Extracted %d LSA secret entries", len(results))
    return results


def extract_cachedump(dump_path: str) -> List[dict]:
    """Extract cached domain credentials using windows.cachedump."""
    output = run_vol3(dump_path, "windows.cachedump")
    results = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] not in ("User", "---"):
            results.append({"user": parts[0], "domain": parts[1], "dcc2_hash": parts[2] if len(parts) > 2 else ""})
    logger.info("Extracted %d cached domain credentials", len(results))
    return results


def run_pypykatz(dump_path: str, output_dir: str) -> dict:
    """Run pypykatz against LSASS minidump or full memory for credential extraction."""
    lsass_dmp = os.path.join(output_dir, "lsass.dmp")
    target = lsass_dmp if os.path.isfile(lsass_dmp) else dump_path
    mode = "minidump" if target == lsass_dmp else "rekall"
    cmd = ["pypykatz", "lsa", mode, target, "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.stdout:
            return json.loads(result.stdout)
    except FileNotFoundError:
        logger.warning("pypykatz not found; skipping LSASS credential extraction")
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        logger.warning("pypykatz error: %s", exc)
    return {}


def parse_pypykatz_creds(pypykatz_data: dict) -> List[dict]:
    """Parse pypykatz JSON output into structured credential list."""
    creds = []
    for session_key, session in pypykatz_data.get("logon_sessions", {}).items():
        username = session.get("username", "")
        domain = session.get("domainname", "")
        if not username or username == "(null)":
            continue
        entry = {"user": f"{domain}\\{username}", "sid": session.get("sid", ""),
                 "logon_server": session.get("logon_server", ""),
                 "logon_time": session.get("logon_time", ""), "cred_types": []}
        for msv in session.get("msv_creds", []):
            if msv.get("NThash"):
                entry["cred_types"].append({"type": "NTLM", "hash": msv["NThash"]})
        for kerb in session.get("kerberos_creds", []):
            if kerb.get("password"):
                entry["cred_types"].append({"type": "Kerberos_password", "value": kerb["password"]})
            for ticket in kerb.get("tickets", []):
                entry["cred_types"].append({"type": "Kerberos_ticket",
                                            "server": ticket.get("server", ""), "enc_type": ticket.get("enc_type", "")})
        for wd in session.get("wdigest_creds", []):
            if wd.get("password"):
                entry["cred_types"].append({"type": "WDigest", "value": wd["password"]})
        for dpapi in session.get("dpapi_creds", []):
            if dpapi.get("masterkey"):
                entry["cred_types"].append({"type": "DPAPI_masterkey", "key": dpapi["masterkey"][:40]})
        if entry["cred_types"]:
            creds.append(entry)
    return creds


def search_cloud_keys(dump_path: str) -> List[dict]:
    """Search memory strings for cloud credentials and auth tokens."""
    output = run_vol3(dump_path, "windows.strings", ["--pid", "0"])
    findings = []
    for pattern, label in CLOUD_KEY_PATTERNS:
        for match in re.findall(pattern, output):
            findings.append({"type": label, "value": match[:30] + "..."})
    for pattern in AUTH_STRING_PATTERNS:
        for match in re.findall(pattern, output):
            findings.append({"type": "auth_string", "value": match[:60]})
    logger.info("Found %d cloud/auth credential fragments", len(findings))
    return findings[:50]


def generate_report(dump_path: str, output_dir: str) -> dict:
    """Generate full credential extraction report."""
    os.makedirs(output_dir, exist_ok=True)
    report = {"analysis_date": datetime.utcnow().isoformat(), "source": dump_path}

    report["dump_info"] = verify_dump(dump_path)
    if not report["dump_info"].get("valid"):
        return report

    report["os_info"] = get_os_info(dump_path)
    report["lsass_pid"] = find_lsass_pid(dump_path)
    report["sam_hashes"] = extract_hashdump(dump_path)
    report["lsa_secrets"] = extract_lsadump(dump_path)
    report["cached_creds"] = extract_cachedump(dump_path)

    pypykatz_data = run_pypykatz(dump_path, output_dir)
    report["lsass_creds"] = parse_pypykatz_creds(pypykatz_data)
    report["cloud_keys"] = search_cloud_keys(dump_path)

    summary = {
        "sam_hashes": len(report["sam_hashes"]),
        "lsa_secrets": len(report["lsa_secrets"]),
        "cached_creds": len(report["cached_creds"]),
        "lsass_creds": len(report["lsass_creds"]),
        "cloud_keys": len(report["cloud_keys"]),
    }
    report["summary"] = summary
    report["actions"] = []
    if summary["sam_hashes"] > 0:
        report["actions"].append("Reset passwords for all local accounts with extracted NTLM hashes")
    if summary["lsass_creds"] > 0:
        report["actions"].append("Reset domain account passwords and perform double krbtgt rotation")
    if summary["cloud_keys"] > 0:
        report["actions"].append("Rotate all discovered cloud access keys and revoke active sessions")

    logger.info("Report complete: %s", json.dumps(summary))
    return report


def main():
    parser = argparse.ArgumentParser(description="Memory Dump Credential Extraction Agent")
    parser.add_argument("--dump", required=True, help="Path to memory dump file")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--output", default="credential_report.json")
    args = parser.parse_args()

    report = generate_report(args.dump, args.output_dir)
    out_path = os.path.join(args.output_dir, args.output)
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("Report saved to %s", out_path)
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
