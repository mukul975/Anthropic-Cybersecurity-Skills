# API Reference: CISA Zero Trust Maturity Model Assessment Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| (stdlib only) | Python 3.8+ | JSON processing, assessment logic |

## CLI Usage

```bash
python scripts/agent.py \
  --data /assessments/zt_responses.json \
  --output-dir /reports/ \
  --output ztmm_report.json
```

## Functions

### `assess_control(control, implemented, maturity) -> dict`
Scores a single control: 0 (Traditional) to 3 (Optimal).

### `assess_pillar(pillar, responses) -> dict`
Evaluates all controls within a CISA ZT pillar. Returns score, percentage, and maturity level.

### `compute_overall_maturity(pillar_results) -> dict`
Aggregates pillar scores into overall maturity: Traditional/Initial/Advanced/Optimal.

### `generate_recommendations(pillar_results) -> list`
Identifies unimplemented controls, prioritizes by pillar weakness.

### `generate_report(data_path) -> dict`
Full assessment pipeline: load data, assess 5 pillars, compute maturity, generate recommendations.

## CISA ZT Pillars

| Pillar | Controls Assessed |
|--------|-------------------|
| Identity | MFA, phishing-resistant MFA, JIT access, PAM |
| Devices | Inventory, EDR, health attestation, posture |
| Networks | Microsegmentation, encrypted DNS, SDP |
| Applications | Inventory, access controls, API security |
| Data | Classification, DLP, encryption at rest |

## Input Data Format

```json
{
  "Identity": {
    "MFA enforced for all users": {"implemented": true, "maturity": "Advanced"},
    "Phishing-resistant MFA (FIDO2/PIV)": {"implemented": false, "maturity": "Traditional"}
  }
}
```

## Output Schema

```json
{
  "overall_maturity": {"percentage": 52.3, "maturity_level": "Advanced"},
  "pillars": [{"pillar": "Identity", "percentage": 66.7, "maturity_level": "Advanced"}],
  "recommendations": [{"pillar": "Devices", "control": "EDR deployed", "priority": "HIGH"}]
}
```
