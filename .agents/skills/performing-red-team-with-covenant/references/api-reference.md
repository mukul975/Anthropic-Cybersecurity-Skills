# API Reference: Performing Red Team with Covenant C2

## Covenant REST API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| /api/users/login | POST | Authenticate and get JWT token |
| /api/listeners | GET | List all listeners |
| /api/listeners/http | POST | Create HTTP listener |
| /api/grunts | GET | List all grunts (agents) |
| /api/grunts/{id}/interact | POST | Execute task on grunt |
| /api/grunttasks/{id} | GET | Get task output |
| /api/launchers/binary | PUT | Generate binary launcher |
| /api/launchers/powershell | PUT | Generate PowerShell launcher |
| /api/launchers/msbuild | PUT | Generate MSBuild launcher |

## Authentication

```json
POST /api/users/login
{"userName": "admin", "password": "pass"}

Response: {"covenantToken": "eyJhbGciOi..."}
Header: Authorization: Bearer <token>
```

## Listener Configuration

| Field | Type | Description |
|-------|------|-------------|
| name | string | Listener display name |
| bindAddress | string | IP to bind (0.0.0.0 for all) |
| bindPort | int | Port for grunt callbacks |
| connectAddresses | array | Callback addresses for grunts |
| listenerTypeId | int | 1=HTTP, 2=Bridge |

## Grunt Status Values

| Status | Description |
|--------|-------------|
| Uninitialized | Grunt created but not connected |
| Stage0 | Initial callback received |
| Stage1 | Key exchange in progress |
| Stage2 | Fully staged and active |
| Active | Connected and ready for tasks |
| Lost | Missed check-in threshold |

## Built-in Tasks

| Task | Description |
|------|-------------|
| WhoAmI | Current user identity |
| GetHostname | Target hostname |
| ListDirectory | Directory listing |
| Download | Retrieve file from target |
| Upload | Upload file to target |
| PowerShell | Execute PowerShell command |
| Assembly | Load and execute .NET assembly |
| Mimikatz | Credential extraction |

## References

- Covenant GitHub: https://github.com/cobbr/Covenant
- Covenant Wiki: https://github.com/cobbr/Covenant/wiki
- Covenant API Docs: Swagger UI at https://<host>:7443/swagger
- Netwrix Tutorial: https://netwrix.com/en/resources/blog/covenant-c2-tutorial/
