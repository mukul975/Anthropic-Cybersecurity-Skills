# API Reference: Suspicious PowerShell Execution Detection

## Windows PowerShell Event Logs

### Event IDs
| Event ID | Log | Description |
|----------|-----|-------------|
| 4104 | PowerShell/Operational | Script block logging |
| 4103 | PowerShell/Operational | Module logging |
| 800 | PowerShell | Pipeline execution details |
| 400 | PowerShell | Engine lifecycle (start) |
| 403 | PowerShell | Engine lifecycle (stop) |

### Script Block Logging Query
```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} -MaxEvents 100
```

### Event 4104 Properties
| Index | Field | Description |
|-------|-------|-------------|
| 0 | MessageNumber | Block sequence number |
| 1 | MessageTotal | Total blocks in script |
| 2 | ScriptBlockText | Actual script content |
| 3 | ScriptBlockId | Unique script ID |
| 4 | Path | Script file path |

## Suspicious PowerShell Patterns

### Execution Policy Bypass
```powershell
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -nop -w hidden -enc <base64>
```

### Common Obfuscation Techniques
| Technique | Example |
|-----------|---------|
| Concatenation | `"Inv"+"oke-Ex"+"pression"` |
| Variable substitution | `${I`nv`oke-`Ex`pression}` |
| Encoded commands | `-enc SQBuAHYAbwBrAGUALQA...` |
| Char array | `[char[]]@(73,69,88) -join ''` |

## Sigma Detection Rules

### Suspicious PowerShell Command Line
```yaml
title: Suspicious PowerShell Invocation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'FromBase64String'
            - 'DownloadString'
            - 'Invoke-Expression'
    condition: selection
level: high
```

## AMSI (Antimalware Scan Interface)

### AMSI Scan Functions
```c
HRESULT AmsiScanBuffer(
    HAMSICONTEXT amsiContext,
    PVOID buffer,
    ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT *result
);
```

### AMSI Results
| Value | Meaning |
|-------|---------|
| 0 | Clean |
| 1 | Not Detected |
| 16384 | Blocked by admin |
| 32768 | Detected (malware) |

## Microsoft Defender ATP API

### Advanced Hunting Query
```http
POST https://api.security.microsoft.com/api/advancedqueries/run
Authorization: Bearer {token}

{
  "Query": "DeviceProcessEvents | where FileName == 'powershell.exe' | where ProcessCommandLine has_any('encodedcommand','downloadstring','invoke-expression') | project Timestamp, DeviceName, ProcessCommandLine | take 100"
}
```
