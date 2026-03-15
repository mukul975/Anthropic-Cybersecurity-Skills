# API Reference: MITRE ATT&CK Navigator APT Analysis

## ATT&CK Navigator Layer Format

### Layer JSON Structure
```json
{
  "name": "APT29 - TTPs",
  "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1566.001",
      "tactic": "initial-access",
      "color": "#ff6666",
      "score": 100,
      "comment": "Used by APT29",
      "enabled": true
    }
  ],
  "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100}
}
```

## ATT&CK STIX Data Access

### Download Enterprise ATT&CK Bundle
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

### STIX Object Types
| Type | Description |
|------|-------------|
| `intrusion-set` | APT groups / threat actors |
| `attack-pattern` | Techniques and sub-techniques |
| `relationship` | Links groups to techniques (`uses`) |
| `malware` | Malware families |
| `tool` | Legitimate tools used by adversaries |

## mitreattack-python Library

### Installation
```bash
pip install mitreattack-python
```

### Query Group Techniques
```python
from mitreattack.stix20 import MitreAttackData

attack = MitreAttackData("enterprise-attack.json")
groups = attack.get_groups()
for g in groups:
    techs = attack.get_techniques_used_by_group(g)
    print(f"{g.name}: {len(techs)} techniques")
```

### Get Technique Details
```python
technique = attack.get_object_by_attack_id("T1566.001", "attack-pattern")
print(technique.name)          # Spearphishing Attachment
print(technique.x_mitre_platforms)  # ['Windows', 'macOS', 'Linux']
```

## Navigator CLI (attack-navigator)

### Export Layer to SVG
```bash
npx attack-navigator-export \
  --layer layer.json \
  --output output.svg \
  --theme dark
```

## ATT&CK API (TAXII)
```python
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

collection = Collection(
    "https://cti-taxii.mitre.org/stix/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e/"
)
tc_source = TAXIICollectionSource(collection)
groups = tc_source.query([Filter("type", "=", "intrusion-set")])
```

## Key APT Groups Reference
| ID | Name | Known Aliases |
|----|------|--------------|
| G0016 | APT29 | Cozy Bear, The Dukes, NOBELIUM |
| G0007 | APT28 | Fancy Bear, Sofacy, Strontium |
| G0022 | APT3 | Gothic Panda, UPS |
| G0032 | Lazarus Group | HIDDEN COBRA, Zinc |
| G0074 | Dragonfly 2.0 | Energetic Bear, Berserk Bear |
| G0010 | Turla | Waterbug, Venomous Bear |
