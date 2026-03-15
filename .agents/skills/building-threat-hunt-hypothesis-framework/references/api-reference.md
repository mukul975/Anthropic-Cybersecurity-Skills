# API Reference: Threat Hunt Hypothesis Framework

## Hypothesis Structure
| Field | Description |
|-------|------------|
| hypothesis_id | Unique identifier (HYP-XXXXXXXX) |
| technique_id | MITRE ATT&CK technique (e.g. T1059.001) |
| hypothesis_statement | Natural language hypothesis |
| data_sources | Required log sources |
| priority | high / medium / low |
| status | planned / in_progress / completed |

## MITRE ATT&CK Data Sources
```bash
# Download ATT&CK STIX bundle
curl -O https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

# Filter attack-pattern objects for technique data sources
python3 -c "
import json
bundle = json.load(open('enterprise-attack.json'))
for obj in bundle['objects']:
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
        eid = obj['external_references'][0]['external_id']
        ds = [d['source_name'] for d in obj.get('x_mitre_data_sources', [])]
        print(f'{eid}: {ds}')
"
```

## Hunt Maturity Model (HMM)
| Level | Name | Description |
|-------|------|------------|
| HM0 | Initial | Ad hoc, no documented procedures |
| HM1 | Minimal | Basic procedures, limited data sources |
| HM2 | Procedural | Documented hypotheses, repeatable hunts |
| HM3 | Innovative | Custom analytics, TI-driven hypotheses |
| HM4 | Leading | Automated, ML-assisted, continuous hunting |

## Key Windows Event IDs for Hunting
| Event ID | Source | Use Case |
|----------|--------|----------|
| 4104 | PowerShell | Script block logging |
| 4688 | Security | Process creation |
| 4624/4625 | Security | Logon success/failure |
| 4698 | Security | Scheduled task created |
| 1 (Sysmon) | Sysmon | Process create with hashes |
| 3 (Sysmon) | Sysmon | Network connection |
| 10 (Sysmon) | Sysmon | Process access (LSASS) |
| 11 (Sysmon) | Sysmon | File create |

## Sigma Rule Integration
```yaml
title: Suspicious PowerShell Execution
status: experimental
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Invoke-Mimikatz'
            - 'Invoke-Expression'
    condition: selection
level: high
```
