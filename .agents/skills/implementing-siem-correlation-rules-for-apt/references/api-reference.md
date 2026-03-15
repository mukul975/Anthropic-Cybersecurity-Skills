# API Reference: SIEM Correlation Rules for APT

## Splunk REST API

### Authentication
```
POST /services/auth/login
Body: username=<user>&password=<pass>
Returns: { "sessionKey": "<token>" }
Header: Authorization: Splunk <sessionKey>
```

### Saved Searches (Correlation Rules)
```
POST /services/saved/searches
Parameters: name, search, cron_schedule, dispatch.earliest_time,
  dispatch.latest_time, alert.severity, action.notable (1=enabled),
  action.notable.param.severity, action.notable.param.security_domain
GET /services/saved/searches?output_mode=json&count=0
```

### Search Jobs
```
POST /services/search/jobs
Body: search=<SPL>, earliest_time, latest_time, output_mode=json
Returns: { "sid": "<job_id>" }
GET /services/search/jobs/<sid>?output_mode=json
GET /services/search/jobs/<sid>/results?output_mode=json&count=<n>
```

## Sigma Rule Format (YAML)
```yaml
title: <string>
status: experimental|test|stable
logsource:
  product: windows
  service: sysmon|security
detection:
  selection: { EventID: [1,3] }
  condition: selection
level: low|medium|high|critical
tags: [attack.t1021.001]
```

## sigma-cli Conversion
```bash
sigma convert -t splunk -p sysmon rule.yml
sigma convert -t elastic-eql -p sysmon rule.yml
```

## Key Windows Event IDs for Lateral Movement
| Event ID | Source | Description |
|----------|--------|-------------|
| 4624 | Security | Logon event (Type 3=Network, 10=RDP) |
| 4648 | Security | Explicit credential logon |
| 4688 | Security | Process creation |
| 7045 | System | Service installation |
| 1 | Sysmon | Process creation with hashes |
| 3 | Sysmon | Network connection |
| 10 | Sysmon | Process access (LSASS) |
| 17/18 | Sysmon | Named pipe created/connected |
