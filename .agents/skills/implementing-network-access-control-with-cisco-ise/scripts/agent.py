#!/usr/bin/env python3
"""Cisco ISE NAC Agent - audits ISE policies, endpoint posture, and 802.1X configuration."""

import json
import argparse
import logging
import subprocess
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def ise_request(base_url, username, password, endpoint):
    """Execute Cisco ISE ERS API request."""
    cmd = ["curl", "-s", "-k", "-u", f"{username}:{password}",
           "-H", "Accept: application/json",
           f"{base_url}/ers/config{endpoint}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def get_network_devices(base_url, user, pw):
    return ise_request(base_url, user, pw, "/networkdevice?size=100")


def get_endpoint_groups(base_url, user, pw):
    return ise_request(base_url, user, pw, "/endpointgroup")


def get_authorization_policies(base_url, user, pw):
    return ise_request(base_url, user, pw, "/authorizationprofile?size=100")


def get_active_sessions(base_url, user, pw):
    """Get active RADIUS sessions via MnT API."""
    cmd = ["curl", "-s", "-k", "-u", f"{user}:{pw}",
           "-H", "Accept: application/json",
           f"{base_url}/admin/API/mnt/Session/ActiveList"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout else {}


def audit_authorization_profiles(profiles):
    """Audit authorization profiles for security best practices."""
    findings = []
    for profile in profiles.get("SearchResult", {}).get("resources", []):
        name = profile.get("name", "")
        if "permit" in name.lower() and "all" in name.lower():
            findings.append({"profile": name, "issue": "overly_permissive_profile", "severity": "high"})
    return findings


def analyze_session_data(sessions):
    """Analyze active session posture and authentication methods."""
    auth_methods = defaultdict(int)
    posture_status = defaultdict(int)
    failed_auths = 0
    for session in sessions:
        method = session.get("authentication_method", "unknown")
        auth_methods[method] += 1
        posture = session.get("posture_status", "unknown")
        posture_status[posture] += 1
        if session.get("authentication_status") == "failed":
            failed_auths += 1
    return {
        "total_sessions": len(sessions),
        "auth_methods": dict(auth_methods),
        "posture_distribution": dict(posture_status),
        "failed_authentications": failed_auths,
    }


def check_dot1x_compliance(devices):
    """Check 802.1X deployment across network devices."""
    device_list = devices.get("SearchResult", {}).get("resources", [])
    dot1x_enabled = sum(1 for d in device_list if d.get("NetworkDeviceIPList"))
    return {
        "total_devices": len(device_list),
        "dot1x_capable": dot1x_enabled,
        "coverage_percent": round(dot1x_enabled / max(len(device_list), 1) * 100, 1),
    }


def generate_report(devices, profiles, sessions, base_url):
    profile_audit = audit_authorization_profiles(profiles)
    session_analysis = analyze_session_data(sessions)
    dot1x = check_dot1x_compliance(devices)
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "ise_url": base_url,
        "dot1x_deployment": dot1x,
        "session_analysis": session_analysis,
        "authorization_profile_findings": profile_audit,
        "total_findings": len(profile_audit),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Cisco ISE NAC Audit Agent")
    parser.add_argument("--ise-url", required=True, help="ISE admin URL (https://ise.example.com:9060)")
    parser.add_argument("--username", required=True, help="ISE ERS API username")
    parser.add_argument("--password", required=True, help="ISE ERS API password")
    parser.add_argument("--output", default="ise_nac_report.json")
    args = parser.parse_args()

    devices = get_network_devices(args.ise_url, args.username, args.password)
    profiles = get_authorization_policies(args.ise_url, args.username, args.password)
    sessions = get_active_sessions(args.ise_url, args.username, args.password)
    report = generate_report(devices, profiles, sessions, args.ise_url)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    logger.info("ISE audit: 802.1X coverage %.1f%%, %d active sessions, %d findings",
                report["dot1x_deployment"]["coverage_percent"],
                report["session_analysis"]["total_sessions"], report["total_findings"])
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
