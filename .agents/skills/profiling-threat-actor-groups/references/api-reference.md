# API Reference: Threat Actor Profiling Agent

## Overview

Builds threat actor profiles from MITRE ATT&CK STIX data using the stix2 MemoryStore. Queries intrusion-set objects for TTPs, software, and relationships, enabling group comparison and tactic mapping.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| stix2 | >= 3.0 | STIX 2.1 object store and filtering |
| requests | >= 2.28 | ATT&CK STIX data download |

## Data Source

MITRE ATT&CK Enterprise STIX bundle from `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`. Cached locally at `/tmp/enterprise-attack.json`.

## Core Functions

### `load_attack_data(cache_path)`
Downloads and caches ATT&CK STIX data into a stix2 MemoryStore.
- **Returns**: `MemoryStore` instance

### `list_threat_groups(src)`
Lists all intrusion-set objects with name, aliases, and description.
- **Returns**: `list[dict]` sorted by name

### `get_group_profile(src, group_name)`
Full profile: description, aliases, techniques with ATT&CK IDs, software (malware/tools), external references.
- **Search**: Exact match on name, then fuzzy match on name and aliases
- **Returns**: `dict` with techniques, software, references

### `get_group_techniques_by_tactic(src, group_name)`
Organizes a group's techniques by ATT&CK tactic (kill chain phase).
- **Returns**: `dict` with tactics mapped to technique lists

### `compare_groups(src, group_names)`
Compares multiple groups: shared techniques, technique counts, software counts.
- **Returns**: `dict` with `shared_techniques` and per-group statistics

## STIX Object Types Queried

| Type | ATT&CK Concept |
|------|----------------|
| intrusion-set | Threat actor group |
| attack-pattern | ATT&CK technique |
| malware | Malware family |
| tool | Legitimate tool used by attacker |
| relationship | Links between groups, techniques, software |

## Usage

```bash
python agent.py APT29
python agent.py "Lazarus Group"
```

## Example Output Fields

```json
{
  "name": "APT29",
  "aliases": ["NOBELIUM", "Cozy Bear", "The Dukes"],
  "techniques": [{"name": "Phishing", "technique_id": "T1566"}],
  "software": [{"name": "Cobalt Strike", "type": "tool"}]
}
```
