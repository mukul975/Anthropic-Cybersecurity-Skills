# API Reference — Performing Oil & Gas Cybersecurity Assessment

## Libraries Used
- **csv**: Parse asset inventories and compliance questionnaires
- **pathlib**: File operations

## CLI Interface
```
python agent.py network --assets ot_inventory.csv
python agent.py compliance --csv iec62443_assessment.csv
python agent.py safety --assets ot_inventory.csv
python agent.py report --assets ot_inventory.csv [--compliance-csv iec62443.csv]
```

## Core Functions

### `assess_network_segmentation(asset_file)` — Purdue model zone validation
Checks assets against expected Purdue level placement. Flags zone mismatches and missing DMZ.

### `assess_iec62443_compliance(assessment_csv)` — IEC 62443 security level assessment
Compares achieved vs target Security Levels (SL1-SL4) per zone.

### `assess_safety_systems(asset_file)` — SIS/ESD security posture
Flags CRITICAL: SIS network-connected, remote access enabled, shared controller with process.

### `generate_assessment_report(...)` — Comprehensive sector assessment

## OT Asset Categories
| Type | Criticality | Purdue Level |
|------|------------|-------------|
| SCADA | CRITICAL | Level 2 |
| DCS | CRITICAL | Level 1-2 |
| SIS | CRITICAL | Level 0-1 |
| PLC/RTU | HIGH | Level 1 |
| HMI | HIGH | Level 2 |
| Historian | MEDIUM | Level 3 |

## Frameworks Referenced
- IEC 62443 (Industrial Automation Security)
- NIST CSF (Cybersecurity Framework)
- API 1164 (Pipeline SCADA Security)
- IEC 61511 (Safety Instrumented Systems)

## Dependencies
No external packages — Python standard library only.
