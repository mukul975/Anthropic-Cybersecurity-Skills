# API Reference: STIX/TAXII Feed Processing Agent

## Overview

Discovers TAXII 2.1 servers, fetches STIX 2.1 bundles with pagination, parses and validates objects by type, extracts IOCs from indicator patterns, and builds relationship graphs.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| taxii2-client | >= 2.3 | TAXII 2.1 server discovery and collection fetching |
| stix2 | >= 3.0 | STIX 2.1 object parsing and validation |

## Core Functions

### `discover_server(taxii_url, user, password)`
Discovers TAXII server API roots and their collections.
- **Returns**: `dict` with `api_roots` containing collection metadata

### `fetch_collection(taxii_url, collection_id, user, password, added_after, limit)`
Fetches all STIX objects from a collection with pagination via `as_pages`.
- **Parameters**: `added_after` (str) - ISO timestamp for incremental fetch
- **Returns**: `dict` with `total_objects` and `objects` list

### `parse_stix_bundle(bundle_data)`
Parses and categorizes STIX objects: indicators, malware, threat-actors, attack-patterns, campaigns, relationships, identities.
- **Returns**: `dict` with `categories` and `parse_errors`

### `extract_iocs(parsed_bundle)`
Extracts actionable IOCs from STIX indicator patterns using regex.
- **IOC types**: IPv4, IPv6, domain, URL, MD5, SHA-1, SHA-256, email
- **Returns**: `dict[str, list[str]]` - deduplicated IOC lists

### `build_relationship_graph(parsed_bundle)`
Maps STIX relationship objects into a graph of source -> [{relationship, target}].
- **Returns**: `dict[str, list[dict]]`

## STIX Object Types Handled

| Type | Fields Extracted |
|------|-----------------|
| indicator | id, name, pattern, pattern_type, valid_from, labels |
| malware | id, name, is_family, malware_types |
| threat-actor | id, name, threat_actor_types, aliases |
| attack-pattern | id, name, external_references (ATT&CK IDs) |
| campaign | id, name, first_seen |
| relationship | id, relationship_type, source_ref, target_ref |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TAXII_USER` | No | TAXII server username |
| `TAXII_PASSWORD` | No | TAXII server password |

## Usage

```bash
python agent.py https://cti.example.com/taxii/
```
