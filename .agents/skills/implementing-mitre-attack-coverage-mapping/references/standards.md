# Standards - MITRE ATT&CK Coverage Mapping

## MITRE ATT&CK Framework

- Current version: v18.1 (December 2025)
- 14 Tactics, 200+ Techniques, 400+ Sub-Techniques
- Domains: Enterprise, Mobile, ICS

### Tactics (Kill Chain Order)
1. Reconnaissance (TA0043)
2. Resource Development (TA0042)
3. Initial Access (TA0001)
4. Execution (TA0002)
5. Persistence (TA0003)
6. Privilege Escalation (TA0004)
7. Defense Evasion (TA0005)
8. Credential Access (TA0006)
9. Discovery (TA0007)
10. Lateral Movement (TA0008)
11. Collection (TA0009)
12. Command and Control (TA0011)
13. Exfiltration (TA0010)
14. Impact (TA0040)

## Detection Maturity Model

| Level | Description |
|---|---|
| L0 | No detection capability for the technique |
| L1 | Basic log collection for relevant data sources |
| L2 | Detection rule deployed but not validated |
| L3 | Validated detection with known false positive rate |
| L4 | Automated testing and continuous validation |
| L5 | Behavioral detection with ML-based anomaly detection |

## Related Frameworks
- MITRE D3FEND (Defensive techniques)
- MITRE ATT&CK Data Sources
- NIST CSF Detection function
- SANS Detection Maturity Level model
