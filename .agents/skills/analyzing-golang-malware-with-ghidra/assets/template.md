# Go Malware Analysis Report

## Sample Information
| Field | Value |
|-------|-------|
| SHA-256 | |
| File Size | |
| Go Version | |
| Architecture | amd64 / arm64 / 386 |
| Stripped | Yes / No |
| Obfuscated | Yes (garble) / No |

## Recovered Functions
| Category | Count | Key Functions |
|----------|-------|---------------|
| main | | |
| networking | | |
| crypto | | |
| os/exec | | |
| third-party | | |

## Dependencies
| Module | Purpose |
|--------|---------|
| | |

## C2 Infrastructure
| Indicator | Type | Value |
|-----------|------|-------|
| | URL / IP / Domain | |

## Recommendations
1. Block identified C2 infrastructure
2. Create YARA rule for unique Go function signatures
3. Monitor for similar Go binary compilation artifacts
