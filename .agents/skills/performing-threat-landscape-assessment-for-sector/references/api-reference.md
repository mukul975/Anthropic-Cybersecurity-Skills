# API Reference: Threat Landscape Assessment for Sector

## attackcti Library (MITRE ATT&CK Python Client)

| Method | Description |
|--------|-------------|
| `attack_client()` | Initialize ATT&CK STIX client |
| `client.get_groups()` | Get all threat groups |
| `client.get_techniques_used_by_group(group_id)` | Get techniques for a group |
| `client.get_techniques()` | Get all techniques |
| `client.get_mitigations()` | Get all mitigations |
| `client.get_software()` | Get all tools/malware |

## Group Object Fields

| Field | Description |
|-------|-------------|
| `name` | Primary group name |
| `aliases` | Alternative group names |
| `description` | Group overview |
| `external_references` | ATT&CK ID, URLs |
| `created` | First catalogued date |

## Sector ISACs

| ISAC | Sector | URL |
|------|--------|-----|
| FS-ISAC | Financial Services | https://www.fsisac.com/ |
| H-ISAC | Healthcare | https://h-isac.org/ |
| E-ISAC | Energy | https://www.eisac.com/ |
| IT-ISAC | Technology | https://www.it-isac.org/ |
| MS-ISAC | State/Local Gov | https://www.cisecurity.org/ms-isac |

## Sector Threat Reports

| Report | Publisher | URL |
|--------|-----------|-----|
| Verizon DBIR | Verizon | https://www.verizon.com/business/resources/reports/dbir/ |
| Global Threat Report | CrowdStrike | https://www.crowdstrike.com/global-threat-report/ |
| M-Trends | Mandiant | https://www.mandiant.com/m-trends |
| X-Force Threat Index | IBM | https://www.ibm.com/reports/threat-intelligence |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `attackcti` | >=0.4 | Query MITRE ATT&CK STIX data |
| `collections` | stdlib | Technique frequency counting |
| `json` | stdlib | Report generation |

## References

- MITRE ATT&CK Groups: https://attack.mitre.org/groups/
- attackcti PyPI: https://pypi.org/project/attackcti/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- STIX/TAXII: https://oasis-open.github.io/cti-documentation/
