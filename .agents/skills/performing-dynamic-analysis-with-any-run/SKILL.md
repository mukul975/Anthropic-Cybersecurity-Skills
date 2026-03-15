---
name: performing-dynamic-analysis-with-any-run
description: >
  Performs interactive dynamic malware analysis using the ANY.RUN cloud sandbox to observe
  real-time execution behavior, interact with malware prompts, and capture process trees,
  network traffic, and system changes. Activates for requests involving interactive sandbox
  analysis, cloud-based malware detonation, real-time behavioral observation, or ANY.RUN usage.
domain: cybersecurity
subdomain: malware-analysis
tags: [malware, dynamic-analysis, sandbox, ANY.RUN, interactive-analysis]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Performing Dynamic Analysis with ANY.RUN

## When to Use

- Interactive malware analysis is needed where the analyst must click dialogs, enter credentials, or navigate installer screens
- Rapid cloud-based sandbox analysis without maintaining local sandbox infrastructure
- Malware requires user interaction to proceed past anti-sandbox checks (document macros requiring "Enable Content")
- Sharing analysis results with team members via public or private task URLs
- Comparing behavior across different OS versions (Windows 7, 10, 11) available in ANY.RUN

**Do not use** for highly sensitive samples that cannot be uploaded to cloud services; use an on-premises sandbox like Cuckoo instead.

## Prerequisites

- ANY.RUN account (free community tier or paid subscription at https://any.run)
- Modern web browser with WebSocket support for interactive session streaming
- Sample file ready for upload (max 100 MB for free tier, 256 MB for paid)
- Understanding of the sample type to select appropriate execution environment
- VPN or secure network for accessing ANY.RUN portal during analysis sessions

## Workflow

### Step 1: Configure Analysis Environment

Set up the ANY.RUN task with appropriate parameters:

```
ANY.RUN Task Configuration:
━━━━━━━━━━━━━━━━━━━━━━━━━━
OS Selection:        Windows 10 x64 (recommended default)
                     Windows 7 x64 (for legacy malware)
                     Windows 11 x64 (for modern samples)
Execution Time:      60 seconds (default) / 120-300 for slow-acting malware
Network:             Connected (captures real C2 traffic)
                     Residential Proxy (bypasses geo-blocking)
Privacy:             Public (free tier) / Private (paid - not indexed)
MITM Proxy:          Enable for HTTPS traffic decryption
Fake Net:            Enable to simulate internet services if sample checks connectivity
```

**API-based submission (paid tier):**
```bash
# Submit file via ANY.RUN API
curl -X POST "https://api.any.run/v1/analysis" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -F "file=@suspect.exe" \
  -F "env_os=windows" \
  -F "env_version=10" \
  -F "env_bitness=64" \
  -F "opt_timeout=120" \
  -F "opt_network_connect=true" \
  -F "opt_privacy_type=bylink"

# Check task status
curl "https://api.any.run/v1/analysis/$TASK_ID" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" | jq '.data.status'
```

### Step 2: Interact with Malware During Execution

Use the interactive session to trigger malware behavior:

```
Interactive Actions During Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Document Macros:   Click "Enable Content" / "Enable Editing" when prompted
2. Installer Screens: Click through installation dialogs
3. UAC Prompts:       Click "Yes" to allow elevation (observe privilege escalation)
4. Credential Harvests: Enter fake credentials to observe phishing behavior
5. Browser Redirects:  Navigate to URLs if malware opens browser windows
6. File Dialogs:       Select target files if malware presents file picker
7. Timeout Extension:  Extend analysis time if malware has delayed execution
```

### Step 3: Analyze Process Tree

Review the complete process execution chain:

```
Process Tree Analysis Points:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parent-Child Relationships:
  - WINWORD.EXE -> cmd.exe -> powershell.exe (macro execution chain)
  - explorer.exe -> suspect.exe -> svchost.exe (process injection)

Process Events to Note:
  - Process creation with suspicious command-line arguments
  - PowerShell with encoded commands (-enc / -encodedcommand)
  - cmd.exe executing script files (.bat, .vbs, .js)
  - Legitimate processes spawned from unusual parents
  - Process termination (self-deletion behavior)
```

### Step 4: Review Network Activity

Examine DNS, HTTP/HTTPS, and TCP/UDP connections:

```
ANY.RUN Network Panel Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DNS Requests:
  - Domain resolutions with threat intelligence tags
  - Fast-flux or DGA domain patterns
  - DNS over HTTPS (DoH) detection

HTTP/HTTPS Traffic (with MITM enabled):
  - Full request/response bodies for HTTP
  - Decrypted HTTPS traffic showing C2 commands
  - Downloaded payloads and their content types
  - POST data containing exfiltrated information

Connection Map:
  - Geographic visualization of C2 server locations
  - Connection timeline showing beacon patterns
  - Suricata alerts triggered on network traffic
```

### Step 5: Examine IOCs and Threat Intelligence

Extract indicators and map to known threats:

```
ANY.RUN IOC Categories:
━━━━━━━━━━━━━━━━━━━━━━
Files:       Dropped files with hashes, YARA matches, VirusTotal results
Network:     IPs, domains, URLs contacted during execution
Registry:    Keys created/modified for persistence
Processes:   Suspicious process names and command lines
Mutex:       Named mutexes created (used for single-instance checking)
Signatures:  Suricata rules triggered, behavioral signatures matched

MITRE ATT&CK Mapping:
  - ANY.RUN automatically maps observed behaviors to ATT&CK techniques
  - Review the ATT&CK matrix tab for technique coverage
  - Export ATT&CK Navigator layer for reporting
```

### Step 6: Export Analysis Results

Download comprehensive reports and artifacts:

```bash
# Download report via API
curl "https://api.any.run/v1/analysis/$TASK_ID/report" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o report.json

# Download PCAP
curl "https://api.any.run/v1/analysis/$TASK_ID/pcap" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o capture.pcap

# Download dropped files
curl "https://api.any.run/v1/analysis/$TASK_ID/files" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o dropped_files.zip

# Available exports from ANY.RUN web interface:
# - HTML Report (shareable standalone page)
# - PCAP file (network traffic capture)
# - Process dump (memory dumps of processes)
# - Dropped files (all files created during execution)
# - MITRE ATT&CK Navigator JSON
# - IOC export (STIX/JSON/CSV format)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Interactive Sandbox** | Analysis environment allowing real-time analyst interaction with the executing sample, enabling triggering of user-dependent behaviors |
| **MITM Proxy** | Man-in-the-middle TLS interception in ANY.RUN that decrypts HTTPS traffic for visibility into encrypted C2 communications |
| **Residential Proxy** | ANY.RUN feature routing malware traffic through residential IP addresses to bypass geo-IP and datacenter-IP evasion checks |
| **Suricata Alerts** | Network IDS signatures triggered during execution, providing immediate identification of known malicious traffic patterns |
| **Process Tree** | Hierarchical visualization of parent-child process relationships showing the complete execution chain from initial sample to final payloads |
| **Behavioral Tags** | ANY.RUN classification labels automatically applied based on observed behavior (e.g., "trojan", "stealer", "ransomware") |

## Tools & Systems

- **ANY.RUN**: Cloud-based interactive malware sandbox providing real-time execution monitoring, process trees, network capture, and MITRE ATT&CK mapping
- **ANY.RUN API**: REST API for programmatic sample submission, status checking, and report/artifact retrieval
- **Suricata**: Integrated network IDS within ANY.RUN providing signature-based detection of malicious network traffic
- **MITRE ATT&CK Navigator**: Framework integration mapping observed malware behaviors to adversary techniques and tactics
- **VirusTotal Integration**: Automatic hash lookup of sample and dropped files against VirusTotal detection results

## Common Scenarios

### Scenario: Analyzing a Macro-Enabled Document Requiring User Interaction

**Context**: Phishing email contains a .docm file that requires clicking "Enable Content" to trigger the macro payload. Traditional non-interactive sandboxes fail to trigger the malicious behavior.

**Approach**:
1. Upload .docm to ANY.RUN with Windows 10 environment and Microsoft Office installed
2. When Word opens and displays the security banner, click "Enable Content" interactively
3. Observe the macro execution in the process tree (Word -> cmd.exe -> powershell.exe)
4. Monitor network panel for PowerShell downloading second-stage payload
5. If a UAC prompt appears, click "Yes" to allow the payload to observe full behavior chain
6. Review Suricata alerts for known malware signatures on the downloaded payload
7. Export IOCs (download URLs, dropped file hashes, C2 domains) for blocking

**Pitfalls**:
- Forgetting to enable MITM proxy, resulting in encrypted HTTPS traffic without visibility
- Using too short an execution timeout for malware with delayed execution or sleep timers
- Uploading to public analysis when the sample contains sensitive organizational data
- Not clicking through all prompts; some malware requires multiple user interactions to fully execute

## Output Format

```
ANY.RUN ANALYSIS REPORT
=========================
Task URL:         https://app.any.run/tasks/<task_id>
Sample:           invoice_q3.docm
SHA-256:          e3b0c44298fc1c149afbf4c8996fb924...
Verdict:          MALICIOUS (Score: 95/100)
Family:           Emotet
Tags:             [trojan, banker, spam, macro]

PROCESS TREE
WINWORD.EXE (PID: 2184)
  └── cmd.exe (PID: 3456) "/c powershell -enc JABXAG..."
      └── powershell.exe (PID: 4012)
          └── rundll32.exe (PID: 4568) "C:\Users\...\payload.dll,Control_RunDLL"

NETWORK INDICATORS
DNS:    update.emotet-c2[.]com -> 185.220.101.42
HTTPS:  POST hxxps://185.220.101[.]42/wp-content/gate/ (C2 beacon)
HTTP:   GET hxxp://compromised-site[.]com/invoice.dll (payload download)

SURICATA ALERTS
[1:2028401] ET MALWARE Emotet CnC Beacon
[1:2028402] ET MALWARE Win32/Emotet Activity

MITRE ATT&CK TECHNIQUES
T1566.001  Phishing: Spearphishing Attachment
T1204.002  User Execution: Malicious File
T1059.001  Command and Scripting Interpreter: PowerShell
T1218.011  Rundll32 Execution
T1071.001  Application Layer Protocol: Web Protocols

DROPPED FILES
payload.dll  SHA-256: abc123... Detection: 48/72 (VirusTotal)
config.dat   SHA-256: def456... (encrypted configuration)
```
