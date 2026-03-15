# API Reference: Implementing SIEM Use Cases for Detection

## Libraries

### attackcti (MITRE ATT&CK)
- **Install**: `pip install attackcti`
- `attack_client()` -- Initialize ATT&CK data client
- `get_techniques()` -- All techniques for coverage calculation
- `get_groups()` -- Threat groups for threat-informed use cases

### splunk-sdk (Splunk Integration)
- **Install**: `pip install splunk-sdk`
- `splunklib.client.connect()` -- Connect to Splunk instance
- `service.jobs.create(query)` -- Execute detection rule SPL

## Use Case Lifecycle

| Phase | Activities |
|-------|-----------|
| Design | Map to ATT&CK, define data sources, write detection logic |
| Test | Validate with Atomic Red Team, measure FP/TP rates |
| Deploy | Push to SIEM with alerting and SLA configuration |
| Tune | Refine based on FP feedback, add exclusions |
| Retire | Deprecate when superseded or no longer relevant |

## Key ATT&CK Techniques for Use Cases

| ID | Name | Tactic |
|----|------|--------|
| T1110 | Brute Force | Credential Access |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1059.001 | PowerShell | Execution |
| T1048.003 | Exfiltration over DNS | Exfiltration |
| T1003.001 | LSASS Memory | Credential Access |
| T1098 | Account Manipulation | Persistence |
| T1486 | Data Encrypted for Impact | Impact |

## Sigma Rule Format
- **Spec**: https://sigmahq.io/docs/basics/rules.html
- Fields: `title`, `logsource`, `detection`, `level`, `tags`
- Tools: `sigma-cli` for converting to Splunk SPL, Elastic EQL, Sentinel KQL
- Repository: https://github.com/SigmaHQ/sigma

## Detection Quality Metrics
- True Positive Rate: Target >70%
- False Positive Rate: Target <30%
- Mean Time to Detect (MTTD): Varies by severity
- Coverage: Percentage of ATT&CK techniques with detections

## External References
- ATT&CK Techniques: https://attack.mitre.org/techniques/enterprise/
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Splunk ES Detections: https://research.splunk.com/detections/
- Elastic Detection Rules: https://github.com/elastic/detection-rules
