# API Reference: Detecting Lateral Movement with Splunk

## Key Lateral Movement Techniques

| Technique | MITRE ID | Event Source |
|-----------|----------|-------------|
| Pass-the-Hash | T1550.002 | Event 4624 Logon_Type=3 NTLM |
| PSExec | T1569.002 | Sysmon Event 1 (PSEXESVC.exe) |
| WMI Remote Exec | T1047 | Sysmon Event 1 (wmiprvse.exe) |
| RDP Pivoting | T1021.001 | Event 4624 Logon_Type=10 |
| SMB/Admin Share | T1021.002 | Network logs dest_port=445 |
| WinRM | T1021.006 | Sysmon Event 1 (wsmprovhost.exe) |

## Splunk SPL Syntax

```spl
# Pass-the-Hash detection
index=wineventlog EventCode=4624 Logon_Type=3
| where Authentication_Package="NTLM"
| stats dc(Computer) as targets by Source_Network_Address
| where targets > 3

# PSExec detection
index=sysmon EventCode=1
| where ParentImage="*\\services.exe" AND Image="*\\PSEXESVC.exe"
```

## splunklib Python SDK

```python
import splunklib.client as client
import splunklib.results as results

service = client.connect(host="splunk", port=8089, token="...")
job = service.jobs.create("search index=wineventlog EventCode=4624")
for result in results.JSONResultsReader(job.results(output_mode="json")):
    print(result)
```

## Windows Logon Types

| Type | Description |
|------|-------------|
| 2 | Interactive (console) |
| 3 | Network (SMB, PSExec) |
| 7 | Unlock |
| 10 | RemoteInteractive (RDP) |

## CLI Usage

```bash
python agent.py --generate-queries
python agent.py --generate-queries --techniques pass_the_hash psexec_execution
python agent.py --parse-results splunk_output.json
```
