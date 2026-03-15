# API Reference: Investigating Ransomware Attack Artifacts

## VirusTotal API v3

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v3/files/{hash}` | GET | Look up ransomware sample by MD5/SHA-256 |
| `/api/v3/files` | POST | Upload ransomware sample for analysis |
| `/api/v3/files/{id}/behaviour_summary` | GET | Retrieve behavioral analysis results |

## ID Ransomware

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://id-ransomware.malwarehunterteam.com/` | POST | Upload ransom note or encrypted sample for variant ID |

## No More Ransom Project

| Resource | Description |
|----------|-------------|
| `https://www.nomoreransom.org/crypto-sheriff.php` | Check if free decryptor is available for identified variant |

## MalwareBazaar API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `https://mb-api.abuse.ch/api/v1/` | POST | Query ransomware samples by hash, tag, or signature |

## Key Libraries

- **requests**: HTTP client for VirusTotal and ID Ransomware API calls
- **hashlib** (stdlib): Calculate MD5/SHA-256 hashes of ransomware samples and notes
- **re** (stdlib): Extract Bitcoin addresses, Tor .onion sites, and emails from notes
- **csv** (stdlib): Parse exported Windows Event Log data
- **pathlib** (stdlib): Recursive file system traversal for artifact discovery

## Ransomware IOC Patterns

| Pattern | Regex | Description |
|---------|-------|-------------|
| Bitcoin | `[13][a-km-zA-HJ-NP-Z1-9]{25,34}` | Legacy Bitcoin addresses |
| Bitcoin Bech32 | `bc1[a-z0-9]{39,59}` | SegWit Bitcoin addresses |
| Monero | `4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}` | Monero wallet addresses |
| Tor Sites | `[a-z2-7]{16,56}\.onion` | Tor hidden service domains |

## Configuration

| Variable | Description |
|----------|-------------|
| `VT_API_KEY` | VirusTotal API key for hash lookups and sample submission |

## References

- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [CISA Stop Ransomware](https://www.cisa.gov/stopransomware)
- [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
