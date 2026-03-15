# ModSecurity WAF Logging — API Reference

## Key ModSecurity Directives

| Directive | Description |
|-----------|-------------|
| `SecRuleEngine On/Off/DetectionOnly` | Enable/disable rule engine |
| `SecAuditEngine On/Off/RelevantOnly` | Configure audit logging scope |
| `SecAuditLog /path/to/modsec_audit.log` | Audit log file path |
| `SecAuditLogParts ABCDEFHZ` | Audit log sections to include |
| `SecRequestBodyAccess On` | Inspect request bodies |
| `SecResponseBodyAccess On` | Inspect response bodies |
| `SecRuleRemoveById <id>` | Disable specific rule by ID |
| `SecRuleUpdateTargetById <id> "!ARGS:param"` | Exclude parameter from rule |

## Audit Log Sections

| Section | Contents |
|---------|----------|
| A | Audit log header (timestamp, transaction ID) |
| B | Request headers |
| C | Request body |
| E | Response body |
| F | Response headers |
| H | Audit log trailer (rule matches, scores) |
| Z | End of entry marker |

## OWASP CRS Rule ID Ranges

| Range | Category |
|-------|----------|
| 911xxx | Method Enforcement |
| 920xxx | Protocol Enforcement |
| 930xxx | Local File Inclusion |
| 932xxx | Remote Code Execution |
| 941xxx | Cross-Site Scripting (XSS) |
| 942xxx | SQL Injection |
| 944xxx | Java/Spring Attack |
| 949xxx | Inbound Anomaly Score Blocking |

## CRS Paranoia Levels

| Level | Description |
|-------|-------------|
| PL1 | Default — low false positives, covers common attacks |
| PL2 | Moderate — adds more patterns, some tuning needed |
| PL3 | High — aggressive detection, significant tuning needed |
| PL4 | Extreme — maximum coverage, heavy tuning required |

## Configuration Example

```apache
SecRuleEngine DetectionOnly
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABCDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/modsec_audit.log
```

## External References

- [ModSecurity v3 Reference Manual](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))
- [OWASP CRS Documentation](https://coreruleset.org/docs/)
- [CRS Tuning Guide](https://coreruleset.org/docs/concepts/false_positives_tuning/)
