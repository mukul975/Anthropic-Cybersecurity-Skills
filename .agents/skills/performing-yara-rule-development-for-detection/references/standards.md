# YARA Rule Development Standards

## Rule Naming Convention
- `Malware_Family_Variant`: For specific malware variants
- `APT_Group_Tool`: For threat actor associated tools
- `Exploit_CVE_YYYY_NNNN`: For exploit payloads
- `Technique_Name`: For generic technique detection

## Rule Quality Metrics
| Metric | Target | Description |
|--------|--------|-------------|
| True Positive Rate | >99% | Detection of known samples |
| False Positive Rate | <0.1% | Matches on clean files |
| Scan Speed | >1000 files/s | Processing performance |
| Maintenance Burden | Low | Frequency of updates needed |

## String Types Reference
| Type | Syntax | Use Case |
|------|--------|----------|
| ASCII text | `"text" ascii` | Plain text strings |
| Wide text | `"text" wide` | UTF-16LE encoded strings |
| Case-insensitive | `"text" nocase` | Variable casing |
| Hex pattern | `{ AA BB CC }` | Byte sequences |
| Wildcard hex | `{ AA ?? CC }` | Single byte wildcard |
| Jump hex | `{ AA [2-4] CC }` | Variable length gap |
| Regex | `/pattern/` | Complex pattern matching |

## MITRE ATT&CK Relevance
- T1027 - Obfuscated Files: Rules detect packed/encoded malware
- T1036 - Masquerading: Rules identify file mimicry
- T1059 - Command Interpreter: Rules detect malicious scripts

## References
- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Performance Guidelines](https://yara.readthedocs.io/en/stable/writingrules.html)
