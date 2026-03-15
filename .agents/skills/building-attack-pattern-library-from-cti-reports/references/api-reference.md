# API Reference: Attack Pattern Library from CTI Reports

## Technique Extraction Patterns
| Technique | Regex Pattern |
|-----------|--------------|
| T1566.001 | `spearphish.*attach` |
| T1059.001 | `powershell`, `invoke-expression` |
| T1053.005 | `scheduled task`, `schtasks` |
| T1547.001 | `registry run key`, `CurrentVersion\\Run` |
| T1003.001 | `lsass`, `credential dump`, `mimikatz` |
| T1486 | `ransomware encrypt` |
| T1048 | `exfiltration`, `data theft` |

## IOC Extraction Regex
| IOC Type | Pattern |
|----------|---------|
| IPv4 | `\b(?:\d{1,3}\.){3}\d{1,3}\b` |
| Domain | `[a-zA-Z0-9-]+\.(?:com\|net\|org)` |
| MD5 | `[a-fA-F0-9]{32}` |
| SHA-256 | `[a-fA-F0-9]{64}` |
| Defanged URL | `hxxps?://[^\s]+` |
| Explicit technique | `T\d{4}(?:\.\d{3})?` |

## STIX Attack Pattern
```json
{
  "type": "attack-pattern",
  "name": "Spearphishing Attachment",
  "external_references": [
    {"source_name": "mitre-attack", "external_id": "T1566.001"}
  ],
  "kill_chain_phases": [
    {"phase_name": "initial-access"}
  ]
}
```

## Library Output Structure
| Field | Description |
|-------|-------------|
| `technique_frequency` | Count per technique across reports |
| `technique_report_map` | Which reports mention each technique |
| `total_unique_techniques` | Distinct techniques found |

## MITRE ATT&CK STIX Data
```
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```
