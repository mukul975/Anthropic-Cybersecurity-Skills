# API Reference: Implementing Endpoint Detection with Wazuh

## Wazuh REST API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| /security/user/authenticate | POST | Get JWT token (Basic Auth) |
| /agents | GET | List agents with status |
| /agents/summary/status | GET | Agent status summary |
| /alerts | GET | Query security alerts |
| /rules | GET | List detection rules |
| /logtest | PUT | Test log against decoders/rules |
| /manager/configuration | GET | Manager configuration |
| /agents/{id}/restart | PUT | Restart specific agent |

## Authentication

```python
import requests
from requests.auth import HTTPBasicAuth

resp = requests.post(
    "https://wazuh:55000/security/user/authenticate",
    auth=HTTPBasicAuth("wazuh-wui", "password"),
    verify=False,
)
token = resp.json()["data"]["token"]
headers = {"Authorization": f"Bearer {token}"}
```

## Custom Rule XML Syntax

```xml
<group name="custom_rules,">
  <rule id="100001" level="12">
    <if_sid>5716</if_sid>
    <srcip>!192.168.1.0/24</srcip>
    <description>SSH login from external IP</description>
    <mitre><id>T1078</id></mitre>
  </rule>
</group>
```

Location: `/var/ossec/etc/rules/local_rules.xml`

## Custom Decoder XML

```xml
<decoder name="custom_app">
  <program_name>myapp</program_name>
  <regex>^(\S+) (\S+) (\S+)</regex>
  <order>srcip,user,action</order>
</decoder>
```

Location: `/var/ossec/etc/decoders/local_decoder.xml`

## Alert Query Parameters

| Parameter | Example | Description |
|-----------|---------|-------------|
| limit | 20 | Max results |
| sort | -timestamp | Sort descending |
| q | rule.level>=10 | Filter by level |
| search | brute force | Text search |
| select | rule.id,agent.name | Field selection |

## References

- Wazuh API Docs: https://documentation.wazuh.com/current/user-manual/api/
- Wazuh Rules Syntax: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- Wazuh Custom Rules: https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html
