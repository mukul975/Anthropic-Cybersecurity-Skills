# API Reference: Mapping MITRE ATT&CK Techniques

## mitreattack-python Library

| Method | Description |
|--------|-------------|
| `MitreAttackData(stix_filepath=path)` | Load ATT&CK STIX 2.0 data bundle from file |
| `get_techniques(remove_revoked_deprecated=False)` | Returns `list[AttackPattern]` STIX objects |
| `get_groups(remove_revoked_deprecated=False)` | Returns `list[IntrusionSet]` STIX objects |
| `get_techniques_used_by_group(group_stix_id)` | Returns `list[dict]` with `t["object"]` as AttackPattern |
| `get_attack_id(stix_id=id)` | Resolve STIX ID to ATT&CK ID (e.g., T1059) |
| `get_mitigations(remove_revoked_deprecated=False)` | Returns `list[CourseOfAction]` |
| `get_software(remove_revoked_deprecated=False)` | Returns `list[Malware or Tool]` |

## ATT&CK Navigator API (Layer Format)

| Field | Type | Description |
|-------|------|-------------|
| `techniques[].techniqueID` | string | ATT&CK technique ID (e.g., T1059) |
| `techniques[].score` | number | Coverage score (0=gap, 1=detected) |
| `techniques[].color` | string | Hex color for heatmap visualization |
| `domain` | string | ATT&CK domain: enterprise-attack, mobile-attack, ics-attack |

## MITRE ATT&CK TAXII Server

| Endpoint | Description |
|----------|-------------|
| `cti-taxii.mitre.org/stix/collections/` | List available STIX collections |
| `cti-taxii.mitre.org/stix/collections/{id}/objects/` | Download STIX objects |

## Sigma Rules (Detection Engineering)

| Field | Description |
|-------|-------------|
| `tags` | ATT&CK mapping (e.g., `attack.t1059.001`) |
| `logsource.product` | Target log source (windows, linux, aws) |
| `detection` | Search logic with conditions |

## Key Libraries

- **mitreattack-python** (`pip install mitreattack-python`): Official MITRE ATT&CK Python library
- **stix2**: Parse and create STIX 2.1 objects
- **taxii2-client**: Download ATT&CK data from TAXII server
- **pySigma**: Parse and convert Sigma detection rules

## Configuration

| Variable | Description |
|----------|-------------|
| `ATTACK_STIX_PATH` | Path to local enterprise-attack.json STIX bundle |
| `NAVIGATOR_URL` | ATT&CK Navigator instance URL |

## Data Sources

| Source | URL | Description |
|--------|-----|-------------|
| ATT&CK STIX | `github.com/mitre/cti` | Official STIX bundles |
| ATT&CK Navigator | `github.com/mitre-attack/attack-navigator` | Layer visualization tool |
| Sigma Rules | `github.com/SigmaHQ/sigma` | Community detection rules |

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [mitreattack-python Docs](https://mitreattack-python.readthedocs.io/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [D3FEND](https://d3fend.mitre.org/)
