# osquery Endpoint Monitoring — API Reference

## Installation

| Platform | Command |
|----------|---------|
| macOS | `brew install osquery` |
| Ubuntu | `apt install osquery` |
| Windows | MSI installer from osquery.io |

## Key osquery Tables

| Table | Description |
|-------|-------------|
| `processes` | Running processes with pid, name, cmdline, uid |
| `listening_ports` | Open network ports with bound process |
| `suid_bin` | SUID/SGID binaries on the system |
| `crontab` | Scheduled cron jobs |
| `authorized_keys` | SSH authorized keys per user |
| `kernel_modules` | Loaded kernel modules |
| `docker_containers` | Docker container status |
| `startup_items` | Boot/login startup items |
| `file` | File metadata, hashes, timestamps |

## Fleet API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/fleet/hosts` | List enrolled hosts |
| GET | `/api/v1/fleet/hosts/{id}` | Host details |
| POST | `/api/v1/fleet/queries` | Create scheduled query |
| GET | `/api/v1/fleet/queries` | List queries |

## osquery CLI

```bash
osqueryi --json "SELECT * FROM processes LIMIT 5"
osqueryctl start   # Start osquery daemon
osqueryctl config-check  # Validate configuration
```

## External References

- [osquery Schema](https://osquery.io/schema/)
- [Fleet Documentation](https://fleetdm.com/docs)
- [osquery Packs](https://github.com/osquery/osquery/tree/master/packs)
