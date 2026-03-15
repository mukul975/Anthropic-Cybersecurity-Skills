# API Reference: Red Team Exercise Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| requests | >=2.28 | Download MITRE ATT&CK STIX data |

## CLI Usage

```bash
python scripts/agent.py \
  --actor "APT29" \
  --target "Retail Corp" \
  --objectives "Access POS data" "Exfiltrate cardholder data" \
  --output redteam_plan.json
```

## Functions

### `load_attack_techniques(cache_file) -> dict`
Downloads or loads cached MITRE ATT&CK Enterprise STIX bundle from GitHub (`mitre/cti`).

### `get_actor_techniques(attack_data, actor_name) -> list`
Resolves intrusion-set by name, follows `uses` relationships to collect `attack-pattern` objects. Returns list of `{id, name, tactic}`.

### `build_operation_plan(actor_name, target, objectives, attack_data) -> RedTeamOperation`
Creates a full operation plan with technique list mapped from the emulated actor's known TTPs.

### `log_technique_execution(op, technique_id, detected, notes)`
Updates a technique's status to `executed`, records detection boolean and timestamp.

### `generate_detection_gap_report(op) -> dict`
Compares executed vs. detected techniques. Outputs detection rate and missed technique recommendations.

## Data Classes

### `TechniqueExecution`
- `technique_id`, `technique_name`, `tactic`, `timestamp`, `status`, `detected`, `detection_time`, `notes`

### `RedTeamOperation`
- `operation_name`, `target_org`, `emulated_actor`, `start_date`, `objectives`, `techniques`

## MITRE ATT&CK Data Source

- URL: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- Format: STIX 2.0 bundle with `intrusion-set`, `attack-pattern`, and `relationship` objects
- Locally cached as `attack_enterprise.json` after first download
