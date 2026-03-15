# API Reference: Threat Actor Profiling from OSINT

## MITRE ATT&CK STIX Data
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### STIX Object Types
| Type | Description |
|------|-------------|
| `intrusion-set` | Threat actor groups |
| `attack-pattern` | Techniques/sub-techniques |
| `malware` | Malware families |
| `tool` | Legitimate tools abused |
| `relationship` | Links (group "uses" technique) |

## AlienVault OTX API
```
GET https://otx.alienvault.com/api/v1/pulses/search?q={group_name}&limit=10
X-OTX-API-KEY: $OTX_API_KEY
```

### OTX Pulse Fields
| Field | Description |
|-------|-------------|
| `name` | Pulse title |
| `created` | Publication date |
| `tags` | Topic tags |
| `indicators` | IOCs (IPs, domains, hashes) |

## MITRE ATT&CK Navigator Layer
```json
{
  "name": "APT29 Techniques",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1566.001", "score": 100, "color": "#ff6666"}
  ]
}
```

## ATT&CK Tactic IDs
| Tactic | ID |
|--------|-----|
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Exfiltration | TA0010 |
| Command and Control | TA0011 |
| Impact | TA0040 |

## MALPEDIA API
```
GET https://malpedia.caad.fkie.fraunhofer.de/api/list/actors
Authorization: apitoken $MALPEDIA_API_KEY
```

## Threat Actor Profiling Fields
| Field | Source |
|-------|--------|
| Aliases | ATT&CK intrusion-set |
| TTPs | ATT&CK relationships |
| Malware | ATT&CK malware objects |
| IOCs | OTX pulse indicators |
| Reports | OTX, MITRE references |
