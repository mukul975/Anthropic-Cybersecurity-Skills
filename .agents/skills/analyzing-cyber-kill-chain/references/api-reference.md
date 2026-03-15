# API Reference: Cyber Kill Chain Analysis Tools

## Lockheed Martin Cyber Kill Chain Phases

| Phase | Name | MITRE ATT&CK Tactic |
|-------|------|---------------------|
| 1 | Reconnaissance | TA0043 Reconnaissance |
| 2 | Weaponization | TA0042 Resource Development |
| 3 | Delivery | TA0001 Initial Access |
| 4 | Exploitation | TA0002 Execution |
| 5 | Installation | TA0003 Persistence, TA0004 Privilege Escalation |
| 6 | Command & Control | TA0011 Command and Control |
| 7 | Actions on Objectives | TA0010 Exfiltration, TA0040 Impact |

## Courses of Action (COA) Matrix

| COA | Description |
|-----|-------------|
| Detect | Alert on adversary activity |
| Deny | Prevent phase completion |
| Disrupt | Interrupt adversary mid-phase |
| Degrade | Reduce adversary effectiveness |
| Deceive | Expose activity via deception |
| Destroy | Neutralize adversary infrastructure |

## MITRE ATT&CK Navigator

### JSON Layer Format
```json
{
  "name": "Kill Chain Coverage",
  "versions": {"navigator": "4.8", "layer": "4.4", "attack": "13"},
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1566", "color": "#ff6666", "comment": "Phase 3: Delivery"}
  ]
}
```

### CLI Usage
```bash
# Export layer via ATT&CK Navigator API
curl -X POST https://mitre-attack.github.io/attack-navigator/api/layers \
  -d @layer.json -o coverage_map.svg
```

## Splunk - Kill Chain Phase Queries

### Phase 3 Detection (Delivery)
```spl
index=email sourcetype=exchange action=delivered
| eval has_macro=if(match(attachment, "\.(docm|xlsm|pptm)$"), 1, 0)
| where has_macro=1
| stats count by sender, subject, attachment
```

### Phase 6 Detection (C2)
```spl
index=proxy OR index=firewall
| stats count AS connections, dc(dest) AS unique_dests by src_ip
| where connections > 100 AND unique_dests < 3
| sort - connections
```

## Elastic Security EQL

### Multi-Phase Detection
```eql
sequence by host.name with maxspan=1h
  [process where event.action == "start" and process.name == "WINWORD.EXE"]
  [process where event.action == "start" and process.parent.name == "WINWORD.EXE"]
  [network where destination.port == 443 and not destination.ip in ("known_good")]
```

## MISP - Kill Chain Tagging

### Galaxy Cluster Tags
```
misp-galaxy:kill-chain="reconnaissance"
misp-galaxy:kill-chain="delivery"
misp-galaxy:kill-chain="exploitation"
misp-galaxy:kill-chain="installation"
misp-galaxy:kill-chain="command-and-control"
misp-galaxy:kill-chain="actions-on-objectives"
```

### PyMISP Event Tagging
```python
from pymisp import PyMISP, MISPEvent

misp = PyMISP("https://misp.example.com", "API_KEY")
event = MISPEvent()
event.add_tag("kill-chain:delivery")
event.add_tag("mitre-attack-pattern:T1566 - Phishing")
misp.update_event(event)
```
