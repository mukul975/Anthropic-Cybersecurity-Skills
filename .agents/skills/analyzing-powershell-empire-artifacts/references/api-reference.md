# PowerShell Empire Artifact Detection Reference

## Enable Script Block Logging (GPO)

```
Computer Configuration > Administrative Templates > Windows Components >
Windows PowerShell > Turn on PowerShell Script Block Logging: Enabled
```

Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
- `EnableScriptBlockLogging` = 1

## Enable Module Logging (GPO)

```
Computer Configuration > Administrative Templates > Windows Components >
Windows PowerShell > Turn on Module Logging: Enabled
Module Names: *
```

## Key Event IDs

| Event ID | Log | Description |
|----------|-----|-------------|
| 4104 | Microsoft-Windows-PowerShell/Operational | Script Block Logging — captures executed script text |
| 4103 | Microsoft-Windows-PowerShell/Operational | Module Logging — captures pipeline execution details |
| 4688 | Security | Process Creation — captures command line arguments |
| 800 | Windows PowerShell | Pipeline execution (legacy) |

## Default Empire Launcher Pattern

```
powershell -noP -sta -w 1 -enc <Base64-payload>
```

### Launcher Flags

| Flag | Meaning |
|------|---------|
| `-noP` | No profile — skips PowerShell profile scripts |
| `-sta` | Single-threaded apartment |
| `-w 1` | Window style hidden |
| `-enc` | Encoded command (Base64 UTF-16LE) |

## Empire Stager IOC Patterns

| Pattern | Context |
|---------|---------|
| `System.Net.WebClient` | Downloads stager payload from listener |
| `.DownloadString()` | Fetches PowerShell script from C2 |
| `.DownloadData()` | Fetches binary data from C2 |
| `[System.Convert]::FromBase64String` | Decodes embedded payload |
| `IEX()` / `Invoke-Expression` | Executes downloaded script |
| `New-Object System.Net.WebClient` | Creates web client for download |

## Empire Module Signatures

| Module | MITRE | Description |
|--------|-------|-------------|
| `Invoke-Mimikatz` | T1003.001 | Credential dumping via Mimikatz |
| `Invoke-Kerberoast` | T1558.003 | Service ticket requests for offline cracking |
| `Invoke-TokenManipulation` | T1134 | Access token manipulation |
| `Invoke-PSInject` | T1055.012 | Process hollowing injection |
| `Invoke-DCOM` | T1021.003 | Lateral movement via DCOM |
| `Invoke-SMBExec` | T1021.002 | SMB-based lateral movement |
| `Invoke-WMIExec` | T1047 | WMI-based execution |
| `Invoke-RunAs` | T1134.002 | Create process with alternate token |
| `Invoke-SessionGopher` | T1552.001 | Extract saved session credentials |
| `Install-SSP` | T1547.005 | Security Support Provider persistence |
| `New-GPOImmediateTask` | T1484.001 | GPO abuse for execution |

## Default Empire Staging URIs

```
/login/process.php
/admin/get.php
/admin/news.php
/news.php
/login/process.jsp
```

## Splunk Detection Query

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)system\.net\.webclient") AND match(ScriptBlockText, "(?i)frombase64string")
| stats count by Computer, UserID, ScriptBlockText
```

## Elastic KQL Detection

```
event.code: "4104" AND powershell.file.script_block_text: (*System.Net.WebClient* AND *FromBase64String*)
```

## MITRE ATT&CK Mapping

- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1027** — Obfuscated Files or Information
- **T1105** — Ingress Tool Transfer
