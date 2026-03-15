# API Reference: Insider Threat Investigation

## Data Sources

| Source | Log Type | Key Fields |
|--------|----------|------------|
| DLP System | File transfers, USB connections | user, action, file_path, bytes, device_id |
| Email Gateway | Sent/received/forwarded emails | sender, recipient, subject, attachment_size |
| VPN / Auth Logs | Authentication events | user, timestamp, source_ip, result |
| Cloud Access Broker | SaaS application activity | user, app, action, data_volume |
| Badge Access | Physical access events | user, location, timestamp, direction |

## Microsoft Graph API (for Microsoft 365 environments)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auditLogs/signIns` | GET | User sign-in activity logs |
| `/security/alerts` | GET | Security alerts including DLP |
| `/users/{id}/activities` | GET | User activity feed |
| `/users/{id}/mailFolders/{id}/messages` | GET | Email messages (eDiscovery) |

## Exabeam UEBA API

| Endpoint | Description |
|----------|-------------|
| `/api/users/{user}/timeline` | User activity timeline with risk scores |
| `/api/users/{user}/risk` | Current risk score and contributing factors |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `csv` | stdlib | Parse exported log files |
| `json` | stdlib | Report generation and data exchange |
| `datetime` | stdlib | Timestamp parsing and time-window analysis |
| `requests` | >=2.28 | API access for UEBA and SIEM platforms |

## References

- CISA Insider Threat Guide: https://www.cisa.gov/topics/physical-security/insider-threat-mitigation
- NIST SP 800-53 (PS-6 Access Agreements): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- Microsoft Purview Insider Risk: https://learn.microsoft.com/en-us/purview/insider-risk-management
- MITRE Insider Threat: https://attack.mitre.org/techniques/T1078/
