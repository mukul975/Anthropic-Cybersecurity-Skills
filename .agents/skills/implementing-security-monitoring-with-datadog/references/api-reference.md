# API Reference: Implementing Security Monitoring with Datadog

## Datadog Security Monitoring API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v2/security_monitoring/rules` | GET | List all detection rules |
| `/api/v2/security_monitoring/rules` | POST | Create detection rule |
| `/api/v2/security_monitoring/rules/{id}` | GET | Get rule details |
| `/api/v2/security_monitoring/signals/search` | POST | Search security signals |
| `/api/v2/security_monitoring/signals/{id}` | GET | Get signal details |
| `/api/v2/security_monitoring/signals/{id}/assignee` | PATCH | Update signal assignee |
| `/api/v2/security_monitoring/signals/{id}/state` | PATCH | Update signal state |
| `/api/v1/logs/config/pipelines` | GET | List log pipelines |
| `/api/v1/logs/config/indexes` | GET | List log indexes |
| `/api/v1/monitor` | GET | List all monitors |

## Authentication

```bash
# All requests require both keys
curl -X GET "https://api.datadoghq.com/api/v2/security_monitoring/rules" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}"
```

## Python SDK (datadog-api-client)

```python
from datadog_api_client import Configuration, ApiClient
from datadog_api_client.v2.api.security_monitoring_api import SecurityMonitoringApi

configuration = Configuration()
# Keys read from DD_API_KEY and DD_APP_KEY env vars automatically

with ApiClient(configuration) as api_client:
    api = SecurityMonitoringApi(api_client)
    rules = api.list_security_monitoring_rules()
    signals = api.search_security_monitoring_signals(
        body={"filter": {"query": "status:critical", "from": "now-24h", "to": "now"}}
    )
```

## Detection Rule Types

| Type | Source | Use Case |
|------|--------|----------|
| Log Detection | Ingested logs | SIEM correlation rules |
| Cloud Configuration | Cloud accounts | CSPM compliance checks |
| Infrastructure Configuration | Agent hosts | Host security posture |
| Application Security | APM traces | WAF and attack detection |
| Signal Correlation | Security signals | Multi-signal chaining |

## Signal Severity Levels

| Severity | Triage Priority | Example |
|----------|----------------|---------|
| CRITICAL | Immediate | Active exploitation detected |
| HIGH | < 4 hours | Credential compromise |
| MEDIUM | < 24 hours | Policy violation |
| LOW | Next review cycle | Informational anomaly |
| INFO | No action | Audit trail |

## Log Source Integration

```yaml
# datadog.yaml agent configuration
logs_enabled: true
logs_config:
  container_collect_all: true

# Security-relevant log sources
# conf.d/auth.d/conf.yaml
logs:
  - type: file
    path: /var/log/auth.log
    service: sshd
    source: syslog
    tags: ["security:authentication"]
```

## Cloud SIEM Rule Query Syntax

```
# Failed SSH logins from single IP
source:syslog service:sshd @evt.outcome:failure | count by @network.client.ip > 10

# AWS root account usage
source:cloudtrail @userIdentity.type:Root @evt.name:ConsoleLogin

# Kubernetes privileged container
source:kubernetes @objectRef.resource:pods @requestObject.spec.containers.securityContext.privileged:true
```

### References

- Datadog Security Monitoring API: https://docs.datadoghq.com/api/latest/security-monitoring/
- Datadog Cloud SIEM: https://docs.datadoghq.com/security/cloud_siem/
- Detection Rules: https://docs.datadoghq.com/security/detection_rules/
- datadog-api-client-python: https://github.com/DataDog/datadog-api-client-python
