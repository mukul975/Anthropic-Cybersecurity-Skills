# API Reference: Monitoring Dark Web Sources

## Have I Been Pwned API v3

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v3/breaches` | GET | List all known data breaches |
| `/api/v3/breach/{name}` | GET | Get details of a specific breach |
| `/api/v3/pasteaccount/{email}` | GET | Search paste site archives for an email |
| `/api/v3/breachedaccount/{email}` | GET | Check if email appears in breaches |

## Dehashed API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/search?query=domain:example.com` | GET | Search exposed credentials by domain |
| `/search?query=email:user@example.com` | GET | Search by specific email address |

## Ransomware.live API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/recentvictims` | GET | List recent ransomware leak site victims |
| `/groups` | GET | List tracked ransomware groups |
| `/group/{name}` | GET | Get details for a specific ransomware group |

## Recorded Future Dark Web Module

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v2/darkweb/search` | GET | Search dark web mentions by keyword |
| `/v2/credentials/search` | GET | Search exposed credentials |

## Key Libraries

- **requests**: HTTP client for HIBP, Dehashed, and ransomware.live APIs
- **spiderfoot** (CLI): OSINT automation including dark web module `sfp_darkweb`
- **theHarvester**: Domain reconnaissance including breach data sources

## Configuration

| Variable | Description |
|----------|-------------|
| `HIBP_API_KEY` | Have I Been Pwned API key (paid tier for domain search) |
| `DEHASHED_API_KEY` | Dehashed API key for credential exposure search |
| `DEHASHED_EMAIL` | Dehashed account email for API authentication |
| `RF_API_TOKEN` | Recorded Future API token for dark web module |

## Rate Limits

| API | Rate Limit |
|-----|------------|
| HIBP | 10 requests/minute (paid key) |
| Dehashed | 5 requests/second |
| Ransomware.live | No published limit (be respectful) |

## References

- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [Dehashed API Docs](https://www.dehashed.com/docs)
- [Ransomware.live](https://www.ransomware.live/)
- [SpiderFoot OSINT](https://github.com/smicallef/spiderfoot)
