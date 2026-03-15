# API Reference: Malware Incident Communication Templates

## Severity Levels
| Level | Response Time | Escalation | Update Frequency |
|-------|--------------|------------|------------------|
| Critical | 15 minutes | CISO + Legal + CEO | 1 hour |
| High | 1 hour | CISO + SOC Manager | 2 hours |
| Medium | 4 hours | SOC Manager | 4 hours |
| Low | 24 hours | SOC Analyst | Daily |

## Malware Categories
| Type | Impact | Primary Containment |
|------|--------|-------------------|
| Ransomware | Data encryption, ops disruption | Isolate hosts, disable shares |
| Trojan | Unauthorized access, exfiltration | Block C2, isolate hosts |
| Wiper | Data destruction | Immediate isolation |
| Infostealer | Credential/PII theft | Block exfiltration channels |
| Worm | Lateral spread | Segment network |

## Incident Response Phases (NIST SP 800-61)
| Phase | Communication Focus |
|-------|-------------------|
| Detection | Initial notification, severity classification |
| Containment | Status updates, scope assessment |
| Eradication | Technical progress, IOC sharing |
| Recovery | Service restoration, monitoring |
| Post-Incident | Lessons learned, executive summary |

## Regulatory Notification Deadlines
| Regulation | Deadline | Authority |
|-----------|----------|-----------|
| GDPR | 72 hours | Data Protection Authority |
| HIPAA | 60 days | HHS OCR |
| PCI DSS | Immediate | Card brands + acquirer |
| CCPA | Without unreasonable delay | CA Attorney General |
| NIS2 | 24h early warning + 72h full | CSIRT |

## Communication Template Fields
| Field | Required | Description |
|-------|----------|-------------|
| incident_id | Yes | Unique incident identifier |
| severity | Yes | critical/high/medium/low |
| subject | Yes | Email/notification subject line |
| timestamp | Yes | ISO 8601 format |
| affected_systems | Yes | List of impacted assets |
| actions_taken | Yes | Completed response actions |
| next_steps | Yes | Planned response actions |

## VERIS Framework Mapping
| VERIS Field | Maps To |
|-------------|---------|
| action.malware.variety | malware_type |
| attribute.integrity | impact |
| timeline.incident | detection timestamp |
| asset.assets | affected_systems |
