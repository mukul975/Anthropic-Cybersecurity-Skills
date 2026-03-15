# Standards and Frameworks Reference

## STIX 2.1 Standard (OASIS)

### Core Concepts
- **STIX Bundle**: Top-level container for STIX objects (type: "bundle")
- **STIX ID Format**: `type--uuid` (e.g., `indicator--a1b2c3d4-...`)
- **Versioning**: Objects use `modified` timestamp for version tracking
- **Confidence**: 0-100 scale for reliability assessment

### STIX Domain Objects (SDOs)
| Type | Purpose | Key Properties |
|------|---------|---------------|
| attack-pattern | ATT&CK technique | name, kill_chain_phases |
| campaign | Related intrusion activity | name, first_seen, objective |
| identity | Individuals/orgs | name, identity_class, sectors |
| indicator | Detection pattern | pattern, pattern_type, valid_from |
| infrastructure | Adversary systems | name, infrastructure_types |
| intrusion-set | Threat group | name, aliases, goals |
| malware | Malware family | name, malware_types, is_family |
| note | Analyst annotation | content, object_refs |
| report | CTI document | name, published, object_refs |
| threat-actor | Human adversary | name, threat_actor_types, roles |
| tool | Legitimate software | name, tool_types |
| vulnerability | CVE/weakness | name, external_references |

### STIX Patterning Language
```
[file:hashes.'SHA-256' = 'abc...']
[ipv4-addr:value = '198.51.100.1']
[domain-name:value = 'malware.example.com']
[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_port = 443]
[process:name = 'cmd.exe' AND process:command_line MATCHES '.*powershell.*']
```

## TAXII 2.1 Standard (OASIS)

### Endpoints
| Endpoint | Method | Purpose |
|----------|--------|---------|
| /taxii2/ | GET | Server discovery |
| /{api-root}/ | GET | API root information |
| /{api-root}/collections/ | GET | List collections |
| /{api-root}/collections/{id}/ | GET | Collection details |
| /{api-root}/collections/{id}/objects/ | GET/POST | Get/add objects |
| /{api-root}/collections/{id}/manifest/ | GET | Object manifest |
| /{api-root}/status/{id}/ | GET | Status of add operation |

### HTTP Headers
- Content-Type: `application/stix+json;version=2.1`
- Accept: `application/taxii+json;version=2.1`

### Pagination Parameters
- `limit`: Maximum number of objects per response
- `next`: Cursor for next page
- `added_after`: Filter objects by timestamp

## Marking Definitions (TLP)
```json
{"definition_type": "tlp", "definition": {"tlp": "clear"}}
{"definition_type": "tlp", "definition": {"tlp": "green"}}
{"definition_type": "tlp", "definition": {"tlp": "amber"}}
{"definition_type": "tlp", "definition": {"tlp": "amber+strict"}}
{"definition_type": "tlp", "definition": {"tlp": "red"}}
```

## References
- [STIX 2.1 Spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [TAXII 2.1 Spec](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)
- [CTI Documentation](https://oasis-open.github.io/cti-documentation/)
