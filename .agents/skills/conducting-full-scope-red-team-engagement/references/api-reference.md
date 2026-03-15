# Full-Scope Red Team Engagement — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| attackcti | `pip install attackcti` | MITRE ATT&CK STIX/TAXII client for technique enumeration |
| impacket | `pip install impacket` | AD attack tools (secretsdump, psexec, wmiexec) |
| requests | `pip install requests` | HTTP client for C2 API integration |

## Key attackcti Methods

| Method | Description |
|--------|-------------|
| `attack_client()` | Initialize MITRE ATT&CK client |
| `client.get_enterprise_techniques()` | List all Enterprise techniques |
| `client.get_enterprise_mitigations()` | List mitigations |
| `client.get_groups()` | List threat actor groups |
| `client.get_software()` | List tools and malware |

## Engagement Phases (PTES Framework)

| Phase | Duration | Key Activities |
|-------|----------|----------------|
| Pre-engagement | 1-2 weeks | Scoping, RoE, legal agreements |
| Reconnaissance | 3-5 days | OSINT, footprinting, enumeration |
| Initial Access | 5-7 days | Phishing, exploits, physical |
| Post-exploitation | 5-7 days | Lateral movement, persistence, privilege escalation |
| Objective | 2-3 days | Crown jewel access, exfiltration simulation |
| Reporting | 3-5 days | Findings, remediation, executive brief |

## C2 Frameworks

| Framework | Type | Protocol |
|-----------|------|----------|
| Cobalt Strike | Commercial | HTTPS, DNS, SMB |
| Sliver | Open source | mTLS, HTTPS, DNS, WireGuard |
| Mythic | Open source | HTTP, websocket, custom |

## External References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [PTES Standard](http://www.pentest-standard.org/)
- [attackcti Documentation](https://attackcti.readthedocs.io/)
- [Sliver C2 Wiki](https://github.com/BishopFox/sliver/wiki)
