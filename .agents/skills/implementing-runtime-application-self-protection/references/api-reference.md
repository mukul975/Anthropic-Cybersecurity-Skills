# API Reference: Implementing Runtime Application Self-Protection

## OpenRASP Deployment

```bash
# Java agent attachment (Tomcat)
export CATALINA_OPTS="-javaagent:/opt/rasp/rasp.jar"

# Spring Boot
java -javaagent:/opt/rasp/rasp.jar -jar app.jar

# Verify agent loaded
curl -s http://localhost:8080/rasp/status
```

## OpenRASP Configuration (rasp.yaml)

```yaml
# Detection plugin settings
plugin:
  timeout: 100        # Plugin execution timeout (ms)
  maxstack: 100       # Max stack frames to capture

# Block vs monitor mode
block:
  status_code: 302    # HTTP status on block
  redirect_url: /blocked.html

# Log settings
log:
  maxstack: 50
  syslog:
    enable: true
    url: "udp://siem.example.com:514"
    tag: openrasp
```

## Detection Hooks

| Hook Point | Attack Type | OWASP |
|------------|-------------|-------|
| sql_query | SQL Injection | A03:2021 |
| command_exec | OS Command Injection | A03:2021 |
| file_open / file_read | Path Traversal | A01:2021 |
| http_request | SSRF | A10:2021 |
| xml_parse | XXE | A05:2021 |
| deserialize | Insecure Deserialization | A08:2021 |
| response_write | XSS (reflected) | A03:2021 |
| ldap_query | LDAP Injection | A03:2021 |
| code_eval | Remote Code Execution | A03:2021 |

## Attack Log Format (JSON)

```json
{
  "attack_type": "sqli",
  "action": "block",
  "client_ip": "192.168.1.50",
  "request_url": "/api/users?id=1 OR 1=1",
  "attack_params": {"id": "1 OR 1=1"},
  "stack_trace": "com.app.UserDAO.findById(UserDAO.java:42)",
  "plugin_name": "sql_injection",
  "timestamp": "2025-06-15T10:30:00Z"
}
```

## RASP vs WAF Comparison

| Feature | WAF | RASP |
|---------|-----|------|
| Inspection point | Network perimeter | Inside application |
| Context | HTTP request only | Request + execution context |
| False positive rate | Higher | Near-zero |
| Encrypted traffic | Requires TLS termination | Sees plaintext |
| Deployment | Network device/proxy | Application library |

## Python RASP (Flask Middleware Example)

```python
from flask import request, abort
import re

SQL_INJECTION_PATTERN = re.compile(
    r"(\b(union|select|insert|update|delete|drop|alter)\b.*\b(from|into|table|set)\b)",
    re.IGNORECASE
)

@app.before_request
def rasp_check():
    for value in request.values.values():
        if SQL_INJECTION_PATTERN.search(str(value)):
            abort(403, description="RASP: SQL injection blocked")
```

### References

- OpenRASP: https://github.com/baidu/openrasp
- OWASP RASP: https://owasp.org/www-community/Runtime_Application_Self-Protection
- NIST AppSec: https://csrc.nist.gov/publications/detail/sp/800-95/final
