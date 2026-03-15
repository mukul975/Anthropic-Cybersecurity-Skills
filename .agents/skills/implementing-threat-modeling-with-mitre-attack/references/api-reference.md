# API Reference: Implementing Threat Modeling with MITRE ATT&CK

## Libraries

### attackcti (MITRE ATT&CK CTI)
- **Install**: `pip install attackcti`
- **Docs**: https://attackcti.readthedocs.io/
- `attack_client()` -- Initialize ATT&CK client
- `get_groups()` -- All threat actor groups
- `get_techniques()` -- All techniques (Enterprise, Mobile, ICS)
- `get_techniques_used_by_group(group)` -- Techniques per group
- `get_mitigations()` -- Defensive mitigations
- `get_software()` -- Malware and tools catalog

### mitreattack-python
- **Install**: `pip install mitreattack-python`
- **Docs**: https://mitreattack-python.readthedocs.io/
- `MitreAttackData(stix_filepath)` -- Load STIX bundle
- `get_groups_using_technique(technique_stix_id)` -- Groups per technique
- `get_datacomponents_detecting_technique()` -- Detection data sources

## ATT&CK Navigator Layer Format

| Field | Description |
|-------|-------------|
| `name` | Layer display name |
| `domain` | `enterprise-attack`, `mobile-attack`, `ics-attack` |
| `techniques[]` | List of technique annotations |
| `techniques[].techniqueID` | ATT&CK ID (e.g., T1059) |
| `techniques[].score` | Numeric score for heat map |
| `techniques[].color` | Hex color override |
| `gradient` | Color scale definition |

## Threat Modeling Workflow
1. Identify industry-relevant threat actors
2. Map actor TTPs to ATT&CK techniques
3. Assess current detection coverage
4. Identify coverage gaps
5. Prioritize defensive investments
6. Export Navigator layer for visualization

## Industry Threat Actor Mapping
- Financial: APT38, FIN7, Carbanak, Lazarus
- Healthcare: APT41, FIN12, Wizard Spider
- Government: APT28, APT29, Turla, Sandworm
- Technology: APT41, APT10, Hafnium
- Energy: Sandworm, Dragonfly, APT33

## Priority Scoring
- **CRITICAL**: Technique used by 3+ relevant threat actors
- **HIGH**: Technique used by 2 relevant threat actors
- **MEDIUM**: Technique used by 1 relevant threat actor

## External References
- ATT&CK Groups: https://attack.mitre.org/groups/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- CTID Center: https://ctid.mitre-engenuity.org/
- ATT&CK STIX Data: https://github.com/mitre/cti
- Threat Modeling Manifesto: https://www.threatmodelingmanifesto.org/
