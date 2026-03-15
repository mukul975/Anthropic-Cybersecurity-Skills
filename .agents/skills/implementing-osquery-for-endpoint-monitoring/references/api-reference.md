# API Reference: Osquery Endpoint Monitoring

## osquery.conf Structure
```json
{
  "options": {
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "database_path": "/var/osquery/osquery.db",
    "worker_threads": "2"
  },
  "schedule": {
    "query_name": {
      "query": "SELECT * FROM processes;",
      "interval": 300,
      "description": "Description"
    }
  },
  "file_paths": {
    "category": ["/etc/%%", "/usr/bin/%%"]
  }
}
```

## Key Osquery Tables
| Table | Description |
|-------|-------------|
| processes | Running processes (pid, name, path, cmdline, uid) |
| listening_ports | Open listening ports (pid, port, protocol) |
| process_open_sockets | Active network connections |
| crontab | Cron job entries |
| suid_bin | SUID/SGID binaries |
| file | File metadata (path, size, mtime, sha256) |
| kernel_modules | Loaded kernel modules |
| authorized_keys | SSH authorized keys |
| startup_items | Startup/login items |
| shell_history | Shell command history |

## Result Log Format (JSON Lines)
```json
{"name":"query_name","action":"added","columns":{"pid":"1234","name":"suspicious"},"unixTime":"1705312200"}
```
- `action`: "added" (new row) or "removed" (row disappeared)
- `columns`: query result columns as key-value pairs

## osquery CLI
```bash
osqueryi "SELECT * FROM processes WHERE name = 'nc';"
osqueryctl start   # Start daemon
osqueryctl config-check  # Validate config
```
