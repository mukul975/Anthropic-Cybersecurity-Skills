# API Reference: Triaging Security Incidents with IR Playbooks

## Incident Classification Types

| Type | Keywords | Default Severity | Playbook |
|------|----------|-----------------|----------|
| Malware | trojan, ransomware, c2, beacon | High | malware-infection-playbook |
| Phishing | credential harvest, BEC, spear-phishing | Medium | phishing-response-playbook |
| Data Exfiltration | DLP, dns tunnel, large upload | Critical | data-exfiltration-playbook |
| Unauthorized Access | brute force, lateral movement | High | unauthorized-access-playbook |
| Denial of Service | DDoS, SYN flood, volumetric | High | ddos-response-playbook |
| Insider Threat | policy violation, terminated user | High | insider-threat-playbook |
| Web Attack | SQLi, XSS, web shell, RCE | High | web-attack-playbook |

## Severity Matrix

| Context Factor | Severity Override |
|----------------|-------------------|
| Crown jewel system affected | Critical |
| Active exploitation confirmed | Critical |
| Multiple systems (>5) affected | High |
| Single system affected | Medium |
| Reconnaissance only | Low |
| Minor policy violation | Informational |

## Escalation Paths

| Severity | Response Time | Escalation |
|----------|---------------|------------|
| Critical | 15 minutes | IR Team + CISO + Legal |
| High | 1 hour | SOC Tier 2 + IR Team |
| Medium | 4 hours | SOC Tier 2 |
| Low | 24 hours | SOC Tier 1 |
| Informational | Next business day | SOC Tier 1 |

## Python Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| `json` | stdlib | Alert parsing and report generation |
| `enum` | stdlib | Severity level enumeration |
| `pathlib` | stdlib | Output directory management |
| `datetime` | stdlib | Triage timestamps |

## References

- NIST SP 800-61r2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- SANS Incident Handler's Handbook: https://www.sans.org/white-papers/33901/
- TheHive: https://thehive-project.org/
