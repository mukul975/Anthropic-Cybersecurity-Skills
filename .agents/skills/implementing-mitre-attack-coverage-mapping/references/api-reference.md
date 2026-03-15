# API Reference: Implementing MITRE ATT&CK Coverage Mapping

## ATT&CK Enterprise STIX Data

```bash
# Download latest ATT&CK STIX bundle
curl -sL "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -o attack.json
```

## ATT&CK Navigator Layer Format

```json
{
  "name": "Detection Coverage",
  "domain": "enterprise-attack",
  "versions": {"attack": "14", "navigator": "4.9.1"},
  "techniques": [
    {"techniqueID": "T1566", "score": 3, "color": "#80b1d3"}
  ]
}
```

## ATT&CK Tactics (Enterprise)

| ID | Tactic | Example Technique |
|----|--------|------------------|
| TA0001 | Initial Access | T1566 Phishing |
| TA0002 | Execution | T1059 Command Interpreter |
| TA0003 | Persistence | T1053 Scheduled Task |
| TA0004 | Privilege Escalation | T1078 Valid Accounts |
| TA0005 | Defense Evasion | T1027 Obfuscation |
| TA0006 | Credential Access | T1003 OS Credential Dumping |
| TA0008 | Lateral Movement | T1021 Remote Services |
| TA0011 | Command and Control | T1071 Application Layer Protocol |

## Coverage Score

| Score | Meaning | Color |
|-------|---------|-------|
| 0 | No detection | White |
| 1 | Single rule | Yellow |
| 2 | Multiple rules | Green |
| 3 | Good coverage | Blue |
| 4+ | Excellent | Red |

### References

- MITRE ATT&CK: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- ATT&CK STIX Data: https://github.com/mitre/cti
