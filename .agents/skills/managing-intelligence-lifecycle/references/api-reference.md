# API Reference: Managing Intelligence Lifecycle

## MITRE ATT&CK STIX/TAXII

| Endpoint | Description |
|----------|-------------|
| `cti-taxii.mitre.org/stix/collections/` | TAXII server for ATT&CK STIX bundles |
| `attack.mitre.org/versions/` | ATT&CK version history and changelogs |

## Recorded Future API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v2/alert/search` | GET | Search intelligence alerts by rule and priority |
| `/v2/entity/search` | GET | Search threat actors, malware, and vulnerabilities |
| `/v2/indicator/search` | GET | Search IOCs with risk scores |

## MISP REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/events` | GET/POST | List or create threat intelligence events |
| `/attributes/restSearch` | POST | Search for IOCs across all events |
| `/feeds` | GET | List configured intelligence feeds |

## OpenCTI GraphQL API

| Query | Description |
|-------|-------------|
| `stixCoreObjects` | Query threat actors, malware, and campaigns |
| `reports` | List intelligence reports with confidence scores |
| `indicators` | Query IOCs with STIX pattern matching |

## Key Libraries

- **stix2**: Create and parse STIX 2.1 threat intelligence objects
- **taxii2-client**: Connect to TAXII 2.1 servers for ATT&CK data
- **pymisp**: Python client for MISP threat intelligence platform
- **requests**: HTTP client for Recorded Future and custom feed APIs

## Configuration

| Variable | Description |
|----------|-------------|
| `MISP_URL` | MISP instance URL |
| `MISP_API_KEY` | MISP API authentication key |
| `RF_API_TOKEN` | Recorded Future API token |
| `OPENCTI_URL` | OpenCTI platform URL |
| `OPENCTI_TOKEN` | OpenCTI API bearer token |

## References

- [NIST SP 800-150: Guide to CTI Sharing](https://csrc.nist.gov/publications/detail/sp/800-150/final)
- [FIRST CTI-SIG Maturity Model](https://www.first.org/global/sigs/cti/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [STIX/TAXII Documentation](https://oasis-open.github.io/cti-documentation/)
