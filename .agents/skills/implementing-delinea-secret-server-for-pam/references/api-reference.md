# API Reference: Implementing Delinea Secret Server for PAM

## Libraries

### requests (HTTP client for REST API)
- **Install**: `pip install requests`
- Used to interact with Secret Server REST API v1

## Secret Server REST API

### Authentication
- **Endpoint**: `POST /oauth2/token`
- **Grant type**: `password`
- **Parameters**: `username`, `password`, `domain` (optional)
- **Returns**: `access_token` (Bearer token)

### Secrets API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/secrets` | GET | Search/list secrets |
| `/api/v1/secrets/{id}` | GET | Get secret by ID |
| `/api/v1/secrets` | POST | Create new secret |
| `/api/v1/secrets/{id}` | PUT | Update secret |
| `/api/v1/secrets/{id}/change-password` | POST | Trigger password rotation |
| `/api/v1/secrets/{id}/check-out` | POST | Check out for exclusive access |
| `/api/v1/secrets/{id}/check-in` | POST | Release checked-out secret |
| `/api/v1/secrets/{id}/audits` | GET | Audit trail for secret |
| `/api/v1/secrets/{id}/fields/{slug}` | GET | Get specific field value |

### Folders API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/folders` | GET | List folders |
| `/api/v1/folders/{id}` | GET | Get folder details |
| `/api/v1/folders` | POST | Create folder |

### Administration API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/users` | GET | List users |
| `/api/v1/roles` | GET | List roles |
| `/api/v1/secret-templates` | GET | List secret templates |
| `/api/v1/configuration/general` | GET | Server configuration |

## Common Secret Templates
- **Windows Account**: Domain, username, password
- **Unix Account (SSH)**: Host, username, private key
- **SQL Server Account**: Server, database, username, password
- **Web Password**: URL, username, password

## Search Filters
- `filter.searchText` -- Keyword search
- `filter.folderId` -- Filter by folder
- `filter.secretTemplateId` -- Filter by template
- `filter.includeSubFolders` -- Include nested folders

## External References
- Secret Server REST API: https://docs.delinea.com/online-help/secret-server/api-scripting/rest-api-reference/
- Secret Server SDK: https://github.com/DelineaXPM/python-tss-sdk
- PAM Best Practices: https://docs.delinea.com/online-help/secret-server/
