---
name: fleet-hunting-with-velociraptor
description: Deploy a Velociraptor server and agents, then author VQL (Velociraptor Query Language) artifacts and run them as fleet-wide hunts, on-demand forensic collections, or standalone offline collectors. Use when hunting a TTP across hundreds or thousands of endpoints, collecting forensic artifacts during incident response without re-imaging, or generating collectors for unmanaged/air-gapped hosts. Do not use for standing up Velociraptor for IR evidence collection - use implementing-velociraptor-for-ir-collection.
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- velociraptor
- vql
- dfir
- endpoint-visibility
- incident-response
- fleet-collection
- digital-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- DE.CM-01
mitre_attack:
- T1059
---
# Fleet Hunting with Velociraptor

> **Authorized Use Only:** Velociraptor agents provide deep endpoint visibility and remote collection. Deploy only on assets you own or are authorized to monitor, in accordance with your monitoring policy and applicable law.

## Overview

Velociraptor is an open-source endpoint visibility and digital-forensics platform from Rapid7/Velocidex. A single Go binary acts as server, client (agent), and CLI depending on how it is invoked and configured. Its power comes from **VQL (Velociraptor Query Language)** — an SQL-like language whose plugins query the live state of an endpoint (processes, files, registry, event logs, WMI, network connections, prefetch, etc.). VQL queries are packaged into reusable **Artifacts**, and Artifacts are run at scale as **Hunts** that fan out across every connected client and stream results back to the server as structured rows.

This makes Velociraptor ideal for fleet-wide threat hunting: a hypothesis ("are any hosts running suspicious PowerShell?") becomes a VQL artifact, deployed as a hunt, with results aggregated centrally in minutes. It also supports offline collectors (standalone executables that collect and bundle artifacts on air-gapped or unmanaged hosts) and live forensic notebooks.

## When to Use

- Hunting for a TTP across hundreds or thousands of endpoints from a single console.
- Collecting forensic artifacts on demand during incident response without re-imaging.
- Continuously monitoring for an indicator using client-side event artifacts.
- Generating standalone offline collectors for hosts you cannot enroll.

## Prerequisites

- A Linux or Windows host for the server (Linux recommended for production).
- The Velociraptor binary from the official release page: https://github.com/Velocidex/velociraptor/releases
- Outbound/inbound connectivity from clients to the server frontend port (default 8000) and admin GUI (default 8889).
- Make the binary executable on Linux:
  ```bash
  chmod +x velociraptor-v0.*-linux-amd64
  sudo mv velociraptor-v0.*-linux-amd64 /usr/local/bin/velociraptor
  ```

## Objectives

- Generate server and client configurations.
- Run the server frontend and admin GUI.
- Enroll clients across the fleet.
- Author and test VQL hunts.
- Launch a fleet-wide hunt and collect results.
- Produce an offline collector for unmanaged hosts.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1059 | Command and Scripting Interpreter | A primary hunt target — VQL artifacts surface anomalous interpreter execution (PowerShell, cmd, wscript) across the fleet for detection and triage. |

Velociraptor is a defensive hunting platform; the mapping reflects the adversary behavior the hunts are designed to detect.

## Workflow

### 1. Generate the server configuration
The interactive generator writes a server config (TLS, datastore paths, GUI users, frontend URL). Use `config generate` for a self-signed lab build or the interactive `-i` wizard for production.
```bash
# Non-interactive: dump a default server config
velociraptor config generate > server.config.yaml

# Interactive wizard (recommended for production deployments)
velociraptor config generate -i
```

### 2. Add a GUI admin user
Create at least one administrator to log into the console.
```bash
velociraptor --config server.config.yaml user add admin --role administrator
```

### 3. Start the server frontend and GUI
The frontend accepts client connections; the GUI is served per the config (default https://127.0.0.1:8889).
```bash
velociraptor --config server.config.yaml frontend -v
```
For a quick all-in-one local lab (server + frontend + a local client in one process):
```bash
velociraptor gui
```

### 4. Generate the client configuration and deploy agents
Derive the client config from the server config and run it as the client on each endpoint.
```bash
# Produce the client config (embeds server URL + CA)
velociraptor --config server.config.yaml config client > client.config.yaml

# On a Linux endpoint, run as a client (or install as a service)
velociraptor --config client.config.yaml client -v
```
On Windows, build an MSI/service installer from the GUI ("Server Artifacts" > deployment) or run:
```cmd
velociraptor.exe --config client.config.yaml service install
```

### 5. Test VQL interactively before hunting
Validate a query locally with `query` (`-q`) before deploying it fleet-wide. VQL is SQL-like: `SELECT ... FROM plugin(...) WHERE ...`.
```bash
# List running processes with their command lines
velociraptor query "SELECT Pid, Name, CommandLine FROM pslist()"

# Hunt for suspicious PowerShell command lines
velociraptor query "
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE Name =~ 'powershell'
  AND CommandLine =~ '(?i)(-enc|frombase64string|downloadstring|-w hidden|iex)'
"
```

### 6. List and run a built-in artifact
Artifacts wrap VQL into reusable, parameterized collections.
```bash
# Show available artifacts
velociraptor artifacts list

# Collect a built-in artifact and write results to a directory
velociraptor artifacts collect Windows.System.Pslist --output results.zip
```

### 7. Launch a fleet-wide hunt (GUI workflow)
In the GUI: **Hunt Manager** > **New Hunt** > select the artifact (e.g. `Windows.Detection.Powershell` or a custom one) and parameters > **Launch**. The hunt fans out to every matching client; results stream into the hunt's results table and can be exported as CSV/JSON. Equivalent server-side VQL:
```sql
-- Create a hunt programmatically via a server VQL notebook
SELECT hunt(
    description="Suspicious PowerShell fleet sweep",
    artifacts="Windows.Detection.Powershell"
) FROM scope()
```

### 8. Build a custom artifact
Custom artifacts are YAML documents containing parameters and VQL `sources`. Save in the GUI's Artifact editor or import via `artifacts`:
```yaml
name: Custom.Hunt.SuspiciousPowershell
description: Find encoded / download-cradle PowerShell across the fleet.
parameters:
  - name: regex
    default: "(?i)(-enc|frombase64string|downloadstring|-w hidden|iex)"
sources:
  - query: |
      SELECT Pid, Name, CommandLine, timestamp(epoch=now()) AS Collected
      FROM pslist()
      WHERE Name =~ "powershell" AND CommandLine =~ regex
```

### 9. Generate an offline collector
For unmanaged/air-gapped hosts, build a standalone collector from the GUI ("Server Artifacts" > `Server.Utils.CreateCollector`) or via VQL; it produces a single executable that collects chosen artifacts into a ZIP for later import.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Velociraptor releases | Official binaries | https://github.com/Velocidex/velociraptor/releases |
| Documentation | Deployment, VQL, artifacts | https://docs.velociraptor.app/ |
| VQL reference | Plugin/function reference | https://docs.velociraptor.app/vql_reference/ |
| Artifact Exchange | Community artifacts | https://docs.velociraptor.app/exchange/ |
| Source | GitHub repository | https://github.com/Velocidex/velociraptor |

## Key Commands

| Command | Purpose |
|---------|---------|
| `config generate [-i]` | Create server config (interactive optional) |
| `config client` | Derive client config from server config |
| `user add <name> --role administrator` | Add a GUI admin |
| `frontend -v` | Start server frontend (client comms + GUI) |
| `gui` | All-in-one local lab instance |
| `client -v` | Run as an endpoint agent |
| `service install` | Install the agent as a service |
| `query "<VQL>"` | Run VQL ad hoc |
| `artifacts list` | List available artifacts |
| `artifacts collect <name> --output <zip>` | Collect an artifact locally |

## Validation Criteria

- [ ] Server config generated and GUI admin created
- [ ] Frontend running and GUI reachable over TLS
- [ ] Client config generated and at least one agent enrolled
- [ ] VQL query validated locally with `query`
- [ ] Built-in artifact collected successfully
- [ ] Fleet-wide hunt launched and results aggregated
- [ ] Custom VQL artifact authored and tested
- [ ] Offline collector produced for unmanaged hosts where needed
