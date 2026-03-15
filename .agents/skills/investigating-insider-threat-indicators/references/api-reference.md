# API Reference: Investigating Insider Threat Indicators

## Splunk REST API (SIEM Queries)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/services/search/jobs` | POST | Submit SPL search for user activity timeline |
| `/services/search/jobs/{sid}/results` | GET | Retrieve search results for DLP and access data |
| `/services/saved/searches` | GET | List saved insider threat correlation searches |

## Microsoft Purview DLP API (Graph)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/security/alerts_v2` | GET | Retrieve DLP policy violation alerts |
| `/security/incidents` | GET | List incidents with insider threat classification |
| `/compliance/ediscovery/cases` | POST | Create eDiscovery case for evidence preservation |

## Microsoft Graph (O365 Activity)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auditLogs/signIns` | GET | Query user sign-in logs with location and device |
| `/auditLogs/directoryAudits` | GET | Directory change audit (role assignments, group changes) |
| `/users/{id}/mailFolders/{id}/messages` | GET | Search mailbox for exfiltration via email |

## Key Libraries

- **splunk-sdk**: Python SDK for submitting SPL queries and retrieving results
- **msgraph-sdk**: Microsoft Graph API for O365 audit logs and DLP alerts
- **hashlib** (stdlib): SHA-256 hashing for chain-of-custody evidence integrity
- **csv** (stdlib): Parse exported DLP alert data and access logs

## Evidence Handling

| Function | Purpose |
|----------|---------|
| `hashlib.sha256()` | Generate file hash for chain-of-custody log |
| `json.dump()` | Serialize evidence metadata with timestamps |
| `os.path.getsize()` | Record evidence file sizes |

## Configuration

| Variable | Description |
|----------|-------------|
| `SPLUNK_HOST` | Splunk search head URL for REST API queries |
| `SPLUNK_TOKEN` | Bearer token for Splunk authentication |
| `GRAPH_CLIENT_ID` | Azure AD app registration for Graph API access |
| `GRAPH_TENANT_ID` | Azure AD tenant ID |

## References

- [Splunk REST API Reference](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF)
- [Microsoft Purview DLP](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [CISA Insider Threat Guide](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation)
- [CERT Insider Threat Center](https://insights.sei.cmu.edu/library/common-sense-guide-to-mitigating-insider-threats/)
