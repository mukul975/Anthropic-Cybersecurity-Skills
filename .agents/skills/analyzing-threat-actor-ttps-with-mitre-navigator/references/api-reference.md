# Analyzing Threat Actor TTPs with MITRE Navigator — API Reference

## attackcti Python Library

| Method | Description |
|--------|-------------|
| `attack_client()` | Initialize STIX/TAXII client for ATT&CK data |
| `client.get_groups()` | Retrieve all threat groups from ATT&CK |
| `client.get_techniques()` | Retrieve all techniques from ATT&CK |
| `client.get_techniques_used_by_group(group)` | Get techniques linked to a specific group |
| `client.get_software()` | Retrieve all software/tools from ATT&CK |
| `client.get_software_used_by_group(group)` | Get software used by a specific group |
| `client.get_mitigations()` | Retrieve all mitigations from ATT&CK |
| `client.get_data_sources()` | Retrieve all data sources from ATT&CK |

## STIX 2.1 Group Object Fields

| Field | Description |
|-------|-------------|
| `id` | STIX object ID (e.g., `intrusion-set--abc123`) |
| `name` | Group name (e.g., APT29) |
| `aliases` | Alternative names for the group |
| `description` | Group description and background |
| `external_references` | List of references including ATT&CK ID |
| `created` | Object creation timestamp |
| `modified` | Last modification timestamp |

## STIX 2.1 Technique Object Fields

| Field | Description |
|-------|-------------|
| `name` | Technique name (e.g., Spearphishing Attachment) |
| `external_references[].external_id` | ATT&CK technique ID (e.g., T1566.001) |
| `x_mitre_platforms` | Target platforms (Windows, Linux, macOS) |
| `kill_chain_phases` | Associated tactics in the kill chain |
| `x_mitre_detection` | Detection guidance for the technique |
| `x_mitre_is_subtechnique` | Whether this is a sub-technique |

## ATT&CK Navigator Layer JSON Schema

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Layer display name |
| `versions.attack` | string | ATT&CK version (e.g., "15") |
| `versions.navigator` | string | Navigator version (e.g., "5.0") |
| `versions.layer` | string | Layer format version (e.g., "4.5") |
| `domain` | string | `enterprise-attack`, `mobile-attack`, or `ics-attack` |
| `techniques[].techniqueID` | string | ATT&CK technique ID |
| `techniques[].score` | integer | Numeric score for coloring (0-100) |
| `techniques[].color` | string | Hex color override (e.g., `#ff6666`) |
| `techniques[].comment` | string | Annotation text for the technique |
| `techniques[].enabled` | boolean | Whether technique cell is enabled |
| `gradient.colors` | array | Color gradient from min to max score |
| `gradient.minValue` | integer | Minimum score value |
| `gradient.maxValue` | integer | Maximum score value |
| `filters.platforms` | array | Platforms to display in the matrix |
| `legendItems[].label` | string | Legend entry label |
| `legendItems[].color` | string | Legend entry color |

## CLI Usage

```bash
# List all ATT&CK threat groups
python agent.py --list-groups

# Analyze a specific group
python agent.py --group "APT29"

# Generate Navigator layer file
python agent.py --group "APT29" --layer-output apt29_layer.json

# Compare multiple groups
python agent.py --compare "APT29" "APT28" "Lazarus Group"

# Save full report as JSON
python agent.py --group "APT29" --layer-output apt29.json --output report.json
```

## External References

- [ATT&CK Navigator GitHub](https://github.com/mitre-attack/attack-navigator)
- [attackcti Documentation](https://attackcti.readthedocs.io/)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
