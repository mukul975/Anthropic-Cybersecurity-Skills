# API Reference — Performing Power Grid Cybersecurity Assessment

## Libraries Used
- **csv**: Parse and generate NERC CIP assessment CSV files

## CLI Interface
```
python agent.py template [--output nerc_cip_template.csv]
python agent.py assess --csv completed_assessment.csv
python agent.py esp --firewall-csv esp_rules.csv
```

## Core Functions

### `generate_assessment_template(output_file)` — Create NERC CIP checklist
Generates CSV with all requirements from 11 CIP standards.

### `assess_compliance(assessment_csv)` — Score compliance per standard
Calculates pass/fail rates per CIP standard. Lists all gap findings.

### `assess_esp_security(firewall_csv)` — Electronic Security Perimeter audit
Checks for: allow-from-any rules, allow-any-protocol, missing default-deny.

## NERC CIP Standards Covered (11)
| Standard | Title | Checks |
|----------|-------|--------|
| CIP-002 | BES Cyber System Categorization | 3 |
| CIP-003 | Security Management Controls | 3 |
| CIP-004 | Personnel & Training | 3 |
| CIP-005 | Electronic Security Perimeter | 4 |
| CIP-006 | Physical Security | 3 |
| CIP-007 | System Security Management | 4 |
| CIP-008 | Incident Reporting | 3 |
| CIP-009 | Recovery Plans | 3 |
| CIP-010 | Configuration Change Management | 3 |
| CIP-011 | Information Protection | 3 |
| CIP-013 | Supply Chain Risk Management | 3 |

## Dependencies
No external packages — Python standard library only.
