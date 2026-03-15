---
name: implementing-velociraptor-for-ir-collection
description: Deploy and configure Velociraptor for scalable endpoint forensic artifact collection during incident response using VQL queries, hunts, and pre-built artifact packs across Windows, Linux, and macOS environments.
domain: cybersecurity
subdomain: incident-response
tags: [velociraptor, dfir, endpoint-collection, vql, forensic-artifacts, rapid7, threat-hunting, incident-response]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Velociraptor for IR Collection

## Overview

Velociraptor is an advanced open-source endpoint monitoring, digital forensics, and incident response platform developed by Rapid7. It uses the Velociraptor Query Language (VQL) to create custom artifacts that collect, query, and monitor almost any aspect of an endpoint. Velociraptor enables incident response teams to rapidly collect and examine forensic artifacts from across a network, supporting large-scale deployments with minimal performance impact. The client-server architecture with Fleetspeak communication enables real-time data collection from thousands of endpoints simultaneously, with offline endpoints picking up hunts when they reconnect.

## Architecture

### Components
- **Velociraptor Server**: Central management console with web UI and API
- **Velociraptor Client (Agent)**: Lightweight agent deployed to endpoints
- **Fleetspeak**: Communication framework between client and server
- **VQL Engine**: Query language engine for artifact collection
- **Filestore**: Server-side storage for collected artifacts
- **Datastore**: Metadata storage for hunts, flows, and client information

### Supported Platforms
- Windows (7+, Server 2008R2+)
- Linux (Debian, Ubuntu, CentOS, RHEL)
- macOS (10.13+)

## Deployment

### Server Installation
```bash
# Download latest release
wget https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-linux-amd64

# Generate server configuration
./velociraptor-linux-amd64 config generate -i

# Start the server
./velociraptor-linux-amd64 --config server.config.yaml frontend

# Or run as systemd service
sudo cp velociraptor-linux-amd64 /usr/local/bin/velociraptor
sudo velociraptor --config /etc/velociraptor/server.config.yaml service install
```

### Client Deployment
```bash
# Repack client MSI for Windows deployment
velociraptor --config server.config.yaml config client > client.config.yaml
velociraptor config repack --msi velociraptor-windows-amd64.msi client.config.yaml output.msi

# Deploy via Group Policy, SCCM, or Intune
# Client runs as a Windows service: "Velociraptor"

# Linux client deployment
velociraptor --config client.config.yaml client -v

# macOS client deployment
velociraptor --config client.config.yaml client -v
```

### Docker Deployment
```bash
docker run --name velociraptor \
  -v /opt/velociraptor:/velociraptor/data \
  -p 8000:8000 -p 8001:8001 -p 8889:8889 \
  velocidex/velociraptor
```

## Core IR Artifact Collection

### Windows Forensic Artifacts

```sql
-- Collect Windows Event Logs
SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(
  EvtxGlob="C:/Windows/System32/winevt/Logs/*.evtx",
  IDRegex="4624|4625|4648|4672|4688|4698|4769|7045"
)

-- Collect Prefetch files for execution evidence
SELECT * FROM Artifact.Windows.Forensics.Prefetch()

-- Collect Shimcache entries
SELECT * FROM Artifact.Windows.Registry.AppCompatCache()

-- Collect Amcache entries
SELECT * FROM Artifact.Windows.Forensics.Amcache()

-- Collect UserAssist data
SELECT * FROM Artifact.Windows.Forensics.UserAssist()

-- Collect NTFS MFT timestamps
SELECT * FROM Artifact.Windows.NTFS.MFT(
  MFTFilename="C:/$MFT",
  FileRegex=".(exe|dll|ps1|bat|cmd)$"
)

-- Collect scheduled tasks
SELECT * FROM Artifact.Windows.System.TaskScheduler()

-- Collect running processes with hashes
SELECT * FROM Artifact.Windows.System.Pslist()

-- Collect network connections
SELECT * FROM Artifact.Windows.Network.Netstat()

-- Collect DNS cache
SELECT * FROM Artifact.Windows.Network.DNSCache()

-- Collect browser history
SELECT * FROM Artifact.Windows.Applications.Chrome.History()

-- Collect PowerShell history
SELECT * FROM Artifact.Windows.Forensics.PowerShellHistory()

-- Collect autoruns/persistence
SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()
SELECT * FROM Artifact.Windows.System.Services()
SELECT * FROM Artifact.Windows.System.StartupItems()
```

### Linux Forensic Artifacts

```sql
-- Collect auth logs
SELECT * FROM Artifact.Linux.Sys.AuthLogs()

-- Collect bash history
SELECT * FROM Artifact.Linux.Forensics.BashHistory()

-- Collect crontab entries
SELECT * FROM Artifact.Linux.Sys.Crontab()

-- Collect running processes
SELECT * FROM Artifact.Linux.Sys.Pslist()

-- Collect network connections
SELECT * FROM Artifact.Linux.Network.Netstat()

-- Collect SSH authorized keys
SELECT * FROM Artifact.Linux.Ssh.AuthorizedKeys()

-- Collect systemd services
SELECT * FROM Artifact.Linux.Services()
```

### Triage Collection (All-in-One)

```sql
-- Windows Triage Collection artifact
-- Collects event logs, prefetch, registry, browser data, and more
SELECT * FROM Artifact.Windows.KapeFiles.Targets(
  Device="C:",
  _AllFiles=FALSE,
  _EventLogs=TRUE,
  _Prefetch=TRUE,
  _RegistryHives=TRUE,
  _WebBrowsers=TRUE,
  _WindowsTimeline=TRUE
)
```

## Hunt Operations

### Creating a Hunt
```
1. Navigate to Hunt Manager in Velociraptor Web UI
2. Click "New Hunt"
3. Configure:
   - Description: "IR Triage - Case 2025-001"
   - Include/Exclude labels for targeting
   - Artifact selection (e.g., Windows.Forensics.Prefetch)
   - Resource limits (CPU, IOPS, timeout)
4. Launch hunt
5. Monitor progress in real-time
```

### VQL Hunt Examples

```sql
-- Hunt for specific file hash across all endpoints
SELECT * FROM Artifact.Generic.Detection.HashHunter(
  Hashes="e99a18c428cb38d5f260853678922e03"
)

-- Hunt for YARA signatures in memory
SELECT * FROM Artifact.Windows.Detection.Yara.Process(
  YaraRule='rule malware { strings: $s1 = "malicious_string" condition: $s1 }'
)

-- Hunt for Sigma rule matches in event logs
SELECT * FROM Artifact.Server.Import.SigmaRules()

-- Hunt for suspicious scheduled tasks
SELECT * FROM Artifact.Windows.System.TaskScheduler()
WHERE Command =~ "powershell|cmd|wscript|mshta|rundll32"

-- Hunt for processes with network connections to suspicious IPs
SELECT * FROM Artifact.Windows.Network.Netstat()
WHERE RemoteAddr =~ "10\\.13\\.37\\."
```

## Real-Time Monitoring

```sql
-- Monitor for new process creation
SELECT * FROM watch_etw(guid="{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}")
WHERE EventData.ImageName =~ "powershell|cmd|wscript"

-- Monitor file system changes
SELECT * FROM watch_directory(path="C:/Windows/Temp/")

-- Monitor registry changes
SELECT * FROM watch_registry(key="HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/**")
```

## Integration with SIEM/SOAR

### Splunk Integration
```
Velociraptor Server --> Elastic/OpenSearch --> Splunk HEC
                   --> Direct syslog forwarding
                   --> Velociraptor API --> Custom scripts --> Splunk
```

### Elastic Stack Integration
```yaml
# Velociraptor server config for Elastic output
Monitoring:
  elastic:
    addresses:
      - https://elastic.local:9200
    username: velociraptor
    password: secure_password
    index: velociraptor
```

## MITRE ATT&CK Mapping

| Technique | VQL Artifact |
|-----------|-------------|
| T1059 - Command Scripting | Windows.EventLogs.EvtxHunter (4104, 4688) |
| T1053 - Scheduled Task | Windows.System.TaskScheduler |
| T1547 - Boot/Logon Autostart | Windows.Persistence.PermanentWMIEvents |
| T1003 - OS Credential Dumping | Windows.Detection.Yara.Process |
| T1021 - Remote Services | Windows.EventLogs.EvtxHunter (4624 Type 3/10) |
| T1070 - Indicator Removal | Windows.EventLogs.Cleared |

## References

- [Velociraptor Official Documentation](https://docs.velociraptor.app/)
- [Rapid7 Velociraptor Product Page](https://www.rapid7.com/products/velociraptor/)
- [CISA Velociraptor Resource](https://www.cisa.gov/resources-tools/services/velociraptor)
- [Velociraptor GitHub Repository](https://github.com/Velocidex/velociraptor)
- [Pen Test Partners: Large-Scale Velociraptor](https://www.pentestpartners.com/security-blog/using-velociraptor-for-large-scale-endpoint-visibility-and-rapid-threat-hunting/)
