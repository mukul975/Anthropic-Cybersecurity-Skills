# Host-Based Intrusion Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| requests | `pip install requests` | Wazuh REST API client |
| osquery | Binary install | SQL-based host inspection |
| hashlib | stdlib | File integrity hash computation |

## Wazuh API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/security/user/authenticate` | Obtain JWT token |
| GET | `/agents` | List managed agents |
| GET | `/agents/{id}` | Agent details |
| GET | `/sca/{agent_id}` | Security Configuration Assessment results |
| GET | `/rootcheck/{agent_id}` | Rootkit check results |
| GET | `/alerts` | Query security alerts |
| GET | `/rules` | List detection rules |

## Key osquery Tables

| Table | Description |
|-------|-------------|
| `processes` | Running processes with user, path, cmdline |
| `listening_ports` | Open network ports and bound processes |
| `users` | System user accounts |
| `file` | File metadata and hashes |
| `suid_bin` | SUID/SGID binaries |
| `crontab` | Scheduled cron jobs |

## OSSEC Rule IDs

| Rule ID Range | Category |
|---------------|----------|
| 500-599 | File integrity monitoring |
| 5700-5799 | SSH authentication |
| 18100-18199 | Linux audit events |
| 31100-31199 | Web attack detection |

## External References

- [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [osquery Schema](https://osquery.io/schema/)
- [OSSEC Rule Syntax](https://www.ossec.net/docs/syntax/head_rules.html)
