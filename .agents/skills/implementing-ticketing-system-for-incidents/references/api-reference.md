# API Reference: Implementing Ticketing System for Incidents

## Libraries

### requests (HTTP Client)
- **Install**: `pip install requests`
- Used for ServiceNow REST API and TheHive API

## ServiceNow REST API

### Incident Table (`/api/now/table/incident`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/table/incident` | List/query incidents |
| POST | `/table/incident` | Create new incident |
| PATCH | `/table/incident/{sys_id}` | Update incident |
| DELETE | `/table/incident/{sys_id}` | Delete incident |

### Key Incident Fields

| Field | Description |
|-------|-------------|
| `short_description` | Incident title |
| `description` | Full description |
| `urgency` | 1 (High), 2 (Medium), 3 (Low) |
| `impact` | 1 (High), 2 (Medium), 3 (Low) |
| `priority` | Auto-calculated from urgency + impact |
| `state` | 1 (New) through 7 (Closed) |
| `assignment_group` | Team assigned |
| `work_notes` | Internal analyst notes |
| `close_code` | Resolution classification |
| `close_notes` | Resolution description |

### Query Parameters
- `sysparm_query` -- Encoded query string
- `sysparm_limit` -- Max results
- `sysparm_fields` -- Comma-separated fields to return
- `sysparm_display_value` -- Return display values

## TheHive API (v4/v5)

### Cases

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/case` | Create case |
| GET | `/api/case/{id}` | Get case details |
| PATCH | `/api/case/{id}` | Update case |
| POST | `/api/case/_search` | Search cases |

### Tasks and Observables

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/case/{id}/task` | Add task to case |
| POST | `/api/case/{id}/artifact` | Add observable/IOC |

### Severity Levels
- 1: Low, 2: Medium, 3: High, 4: Critical

### TLP Levels
- 0: WHITE, 1: GREEN, 2: AMBER, 3: RED

## SLA Target Reference
- P1 (Critical): Response 15 min, Resolve 4 hours
- P2 (High): Response 30 min, Resolve 8 hours
- P3 (Medium): Response 4 hours, Resolve 24 hours
- P4 (Low): Response 8 hours, Resolve 72 hours

## External References
- ServiceNow REST API: https://developer.servicenow.com/dev.do#!/reference/api/
- TheHive API: https://docs.strangebee.com/thehive/api-docs/
- Jira Service Management: https://developer.atlassian.com/cloud/jira/service-desk/rest/
- NIST Incident Handling: https://csrc.nist.gov/pubs/sp/800/61/r2/final
