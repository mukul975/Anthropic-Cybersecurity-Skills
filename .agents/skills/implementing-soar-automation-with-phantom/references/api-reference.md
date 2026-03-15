# API Reference: Implementing SOAR Automation with Phantom

## Libraries

### requests (HTTP Client for SOAR REST API)
- **Install**: `pip install requests`
- Authentication: `ph-auth-token` header with API token

## Splunk SOAR REST API

### Playbooks

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/playbook` | GET | List all playbooks |
| `/rest/playbook/{id}` | GET | Get playbook details |
| `/rest/playbook_run` | POST | Execute a playbook |

### Containers (Events/Incidents)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/container` | GET | List containers |
| `/rest/container` | POST | Create new container |
| `/rest/container/{id}` | GET | Get container details |
| `/rest/container/{id}` | POST | Update container |

### Artifacts (IOCs)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/artifact` | POST | Add artifact to container |
| `/rest/artifact/{id}` | GET | Get artifact details |
| CEF fields: `sourceAddress`, `destinationAddress`, `fileHash`, `fileName` |

### Actions

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/action_run` | POST | Run an action on an asset |
| `/rest/action_run/{id}` | GET | Get action results |
| `/rest/app` | GET | List installed apps |
| `/rest/asset` | GET | List configured assets |

### System

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rest/system_info` | GET | System version and status |
| `/rest/ph_user` | GET | List SOAR users |

## Common App Actions

| App | Action | Description |
|-----|--------|-------------|
| VirusTotal | `file_reputation` | Check hash reputation |
| VirusTotal | `url_reputation` | Check URL safety |
| CrowdStrike | `contain_device` | Network isolate host |
| ActiveDirectory | `disable_user` | Disable AD account |
| ServiceNow | `create_ticket` | Create incident ticket |
| Exchange | `quarantine_email` | Remove phishing email |
| Splunk | `run_query` | Execute SPL search |

## Playbook Types
- **Automation**: Fully automated, no analyst input
- **Investigation**: Enrichment with analyst decision gates
- **Response**: Containment actions with approval prompts
- **Reporting**: Data collection and notification

## External References
- SOAR REST API: https://docs.splunk.com/Documentation/SOAR/current/PlatformAPI/
- Playbook Guide: https://docs.splunk.com/Documentation/SOAR/current/DevelopPlaybooks/
- App Development: https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/
- Splunkbase Apps: https://splunkbase.splunk.com/apps/#/product/soar
