# SOAR Phishing Playbook API Reference

## Splunk SOAR REST API

### Authentication
All requests require the `ph-auth-token` header:
```
ph-auth-token: <your-api-token>
```

### Create Container (Incident)
```
POST /rest/container
```
```json
{
  "name": "Phishing: Suspicious invoice email",
  "description": "User reported phishing email",
  "label": "phishing",
  "severity": "high",
  "status": "new",
  "sensitivity": "amber",
  "owner_id": 1,
  "tags": ["phishing", "email"]
}
```
Response: `{"success": true, "id": 1542}`

### Create Artifact
```
POST /rest/artifact
```
```json
{
  "container_id": 1542,
  "name": "Sender Email",
  "label": "email",
  "type": "email",
  "severity": "high",
  "cef": {
    "fromAddress": "attacker@evil.com",
    "toAddress": "victim@company.com",
    "emailSubject": "Urgent Invoice #9921",
    "sourceAddress": "198.51.100.23",
    "requestURL": "https://evil-phish.com/login"
  },
  "run_automation": true
}
```
Response: `{"success": true, "id": 8834}`

### Trigger Playbook
```
POST /rest/playbook_run
```
```json
{
  "container_id": 1542,
  "playbook_id": "local/phishing_investigate",
  "scope": "new",
  "run": true
}
```

### List Action Runs
```
GET /rest/action_run?_filter_container=1542&page_size=100
```

### Get Container Details
```
GET /rest/container/{container_id}
GET /rest/container/{container_id}/artifacts
GET /rest/container/{container_id}/actions
```

### Update Container Status
```
POST /rest/container/{container_id}
```
```json
{"status": "closed", "close_reason": "resolved"}
```

## XSOAR (Cortex XSOAR) API Comparison

### Create Incident
```
POST /incident
```
```json
{
  "name": "Phishing Report",
  "type": "Phishing",
  "severity": 3,
  "labels": [
    {"type": "Email/from", "value": "attacker@evil.com"},
    {"type": "Email/subject", "value": "Urgent Invoice"}
  ]
}
```

### Run Playbook on Incident
```
POST /incident/investigate
```
```json
{"id": "1542", "playbookId": "phishing_investigation"}
```

## Common Phishing Playbook Actions

| Action | App | Description |
|--------|-----|-------------|
| `url reputation` | VirusTotal | Check URL against VT database |
| `domain reputation` | VirusTotal | Check sender domain reputation |
| `ip reputation` | AbuseIPDB | Check originating IP reputation |
| `whois domain` | WHOIS | Domain registration lookup |
| `detonate url` | URLScan.io | Sandbox URL detonation |
| `get email headers` | IMAP | Retrieve full email headers |
| `block sender` | Exchange | Block sender at email gateway |
| `quarantine email` | O365 | Remove email from all mailboxes |
