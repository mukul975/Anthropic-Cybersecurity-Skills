# API Reference — Performing Physical Intrusion Assessment

## Libraries Used
- **csv**: Generate and parse assessment checklists
- **pathlib**: File operations

## CLI Interface
```
python agent.py checklist [--categories perimeter access_control server_room social_engineering] [--output checklist.csv]
python agent.py score --csv completed_assessment.csv
python agent.py report --csv completed_assessment.csv
```

## Core Functions

### `generate_checklist(categories, output_file)` — Create assessment template
22 checks across 4 categories with severity ratings. Outputs to CSV.

### `score_assessment(results_csv)` — Calculate compliance score
Groups by category and severity. Identifies critical failures.

### `generate_report(results_csv)` — Executive summary with risk level

## Assessment Categories (22 checks)
| Category | Checks | Focus |
|----------|--------|-------|
| Perimeter Security | 5 | Fencing, CCTV, lighting, barriers |
| Access Control | 6 | Badge access, tailgating, visitor policy |
| Server Room | 6 | MFA, CCTV, environmental, access logs |
| Social Engineering | 5 | Visitor challenge, clean desk, shredding |

## Risk Classification
- **CRITICAL**: Critical control failures found
- **HIGH**: >5 failed checks
- **MEDIUM**: 1-5 failed checks
- **LOW**: All checks passed

## Dependencies
No external packages — Python standard library only.
