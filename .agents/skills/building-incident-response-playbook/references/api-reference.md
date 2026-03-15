# API Reference: Building Incident Response Playbook

## TheHive API (Case Management)

```python
import requests

THEHIVE_URL = "http://thehive:9000"
headers = {"Authorization": "Bearer <api_key>"}

# Create a new case from playbook
resp = requests.post(f"{THEHIVE_URL}/api/v1/case", headers=headers, json={
    "title": "Ransomware - IR-2024-0450",
    "severity": 3,
    "tlp": 3,
    "pap": 2,
    "tags": ["ransomware", "playbook:ransomware-v2.1"],
    "description": "Ransomware detected on WORKSTATION-042",
})

# Add tasks from playbook phases
resp = requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/task",
    headers=headers, json={
        "title": "Isolate affected hosts",
        "group": "Containment",
        "status": "Waiting",
    })

# Add observable (IOC)
resp = requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/observable",
    headers=headers, json={
        "dataType": "ip",
        "data": "185.234.218.50",
        "message": "C2 server",
        "tlp": 2,
        "ioc": True,
    })
```

## Cortex XSOAR API (SOAR Playbook)

```python
# Trigger a playbook run
resp = requests.post("https://xsoar/api/v2/incident/investigate",
    headers={"Authorization": "<api_key>"},
    json={"id": "incident-123", "playbookId": "Phishing_Response_v2"})

# List available playbooks
resp = requests.get("https://xsoar/api/v2/playbook/search",
    headers={"Authorization": "<api_key>"},
    json={"query": "name:Phishing*"})
```

## Splunk SOAR (Phantom) API

```python
# Run a playbook on a container
resp = requests.post("https://phantom/rest/playbook_run",
    headers={"ph-auth-token": "<token>"},
    json={"container_id": 42, "playbook_id": 15, "scope": "new"})
```

## NIST SP 800-61r3 Phases

| Phase | Key Actions |
|-------|-------------|
| Preparation | Playbooks, tools, contacts, training |
| Detection & Analysis | Alerts, triage, scoping, severity |
| Containment | Isolation, blocking, evidence preservation |
| Eradication | Root cause removal, IOC sweep |
| Recovery | Restore, validate, monitor |
| Post-Incident | Lessons learned, detection improvement |

### References

- TheHive API: https://docs.strangebee.com/thehive/api-docs/
- Cortex XSOAR API: https://xsoar.pan.dev/docs/reference/api/
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Splunk SOAR API: https://docs.splunk.com/Documentation/SOAR/
