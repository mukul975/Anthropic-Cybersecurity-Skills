# API Reference: Hunting Advanced Persistent Threats

## Libraries

### attackcti (MITRE ATT&CK CTI Library)
- **Install**: `pip install attackcti`
- **Docs**: https://attackcti.readthedocs.io/
- `attack_client()` -- Initialize the ATT&CK STIX/TAXII client
- `get_groups()` -- Retrieve all threat actor groups from ATT&CK
- `get_techniques_used_by_group(group)` -- Get techniques mapped to a specific group
- `get_techniques()` -- List all ATT&CK techniques
- `get_mitigations()` -- List all mitigations

### mitreattack-python (ATT&CK STIX Data)
- **Install**: `pip install mitreattack-python`
- **Docs**: https://mitreattack-python.readthedocs.io/
- `MitreAttackData(stix_filepath)` -- Load ATT&CK STIX bundle
- `get_groups()` -- All threat groups
- `get_techniques_used_by_group(group_stix_id)` -- Techniques per group
- `get_attack_campaigns()` -- Known campaigns

### osquery
- **Docs**: https://osquery.readthedocs.io/
- `scheduled_tasks` -- Windows scheduled tasks table
- `processes` -- Running process information
- `process_open_sockets` -- Network connections per process
- `autoexec` -- Auto-start execution points
- `file` -- File metadata queries

## Key ATT&CK Technique IDs

| ID | Name | Relevance |
|----|------|-----------|
| T1059 | Command and Scripting Interpreter | Process-based hunting |
| T1053 | Scheduled Task/Job | Persistence detection |
| T1071 | Application Layer Protocol | C2 communication |
| T1055 | Process Injection | In-memory threats |
| T1003 | OS Credential Dumping | Credential theft |
| T1566 | Phishing | Initial access vector |
| T1218 | Signed Binary Proxy Execution | Defense evasion |

## Sigma Rule Format
- **Spec**: https://sigmahq.io/docs/basics/rules.html
- Fields: `title`, `status`, `logsource`, `detection`, `level`
- Converters: `sigma-cli` converts to Splunk SPL, Elastic EQL, Sentinel KQL

## External References
- MITRE ATT&CK Groups: https://attack.mitre.org/groups/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- Velociraptor VQL: https://docs.velociraptor.app/docs/vql/
- Zeek Documentation: https://docs.zeek.org/en/current/
