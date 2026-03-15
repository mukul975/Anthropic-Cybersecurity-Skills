# API Reference: Threat Actor TTP Analysis with MITRE ATT&CK

## ATT&CK STIX Data

### Download
```bash
curl -o enterprise-attack.json   https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### STIX Object Types
| Type | Description |
|------|-------------|
| `attack-pattern` | Techniques and sub-techniques |
| `intrusion-set` | Threat actor groups |
| `relationship` | Links (group "uses" technique) |
| `malware` | Malware families |
| `tool` | Legitimate tools abused |

## mitreattack-python

### Installation
```bash
pip install mitreattack-python
```

### Query Techniques
```python
from mitreattack.stix20 import MitreAttackData
attack = MitreAttackData("enterprise-attack.json")

# Get all techniques
techniques = attack.get_techniques()

# Get group techniques
group = attack.get_group_by_alias("APT29")
techs = attack.get_techniques_used_by_group(group.id)
```

### Get Technique Mitigations
```python
mitigations = attack.get_mitigations_mitigating_technique(technique.id)
for m in mitigations:
    print(m.name, m.description)
```

## ATT&CK Navigator Layer Format

### Technique Entry
```json
{
  "techniqueID": "T1566.001",
  "tactic": "initial-access",
  "color": "#ff6666",
  "score": 100,
  "comment": "Spearphishing Attachment",
  "enabled": true
}
```

## ATT&CK Tactic IDs

| Tactic | ID |
|--------|----|
| Reconnaissance | TA0043 |
| Resource Development | TA0042 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defense Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

## TAXII Server Access
```python
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

collection = Collection(
    "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/"
)
src = TAXIICollectionSource(collection)
groups = src.query([Filter("type", "=", "intrusion-set")])
```
