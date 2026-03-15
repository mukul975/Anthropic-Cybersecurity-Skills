# Ransomware Tabletop Exercise - API Reference

## Scenario Framework

### Phase Structure
Each phase contains:

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Phase name: detection, containment, escalation, eradication, recovery |
| `inject` | string | Narrative scenario inject read to participants |
| `expected_actions` | list | Correct response actions for scoring |
| `time_pressure_minutes` | int | Simulated time window for decisions |

### Exercise Variants

- **standard** - Normal time pressure, full scenario
- **accelerated** - Half time windows, tests rapid decision-making

## Scoring Algorithm

```
phase_score = (correct_actions / expected_actions) * 100
overall_score = mean(all_phase_scores)
```

Rating thresholds:
- >= 90%: Excellent
- >= 70%: Good
- >= 50%: Needs Improvement
- < 50%: Critical Gaps

## Expected Actions by Phase

### Detection
- `isolate_host` - Quarantine affected endpoint
- `preserve_evidence` - Capture memory dump and disk image
- `notify_ir_lead` - Escalate to incident response lead

### Containment
- `network_segmentation` - Restrict lateral movement paths
- `disable_compromised_accounts` - Lock affected credentials
- `block_c2_domains` - Update firewall/proxy deny lists
- `preserve_shadow_copies` - Protect backup snapshots

### Escalation
- `notify_executive_team` - Brief C-suite leadership
- `engage_legal_counsel` - Activate legal response team
- `contact_law_enforcement` - Report to FBI IC3 or local CIRT
- `activate_crisis_comms` - Prepare stakeholder communications

### Eradication
- `remove_persistence` - Clean scheduled tasks, registry keys, WMI subscriptions
- `reset_all_credentials` - Reset passwords domain-wide
- `rebuild_compromised_hosts` - Reimage from gold images
- `reset_krbtgt_twice` - Invalidate all Kerberos tickets

### Recovery
- `restore_from_backup` - Use verified clean backup sets
- `validate_restored_systems` - Run integrity checks
- `monitor_for_reinfection` - Enhanced monitoring for 72+ hours
- `staged_network_reconnection` - Reconnect systems in phases

## After-Action Report Schema

```json
{
  "report": "ransomware_tabletop_aar",
  "evaluation": {
    "overall_score_pct": 78.5,
    "rating": "good",
    "phase_scores": [{"phase": "detection", "score_pct": 66.7}]
  },
  "recommendations": [{"phase": "detection", "gap": "Missed: preserve_evidence"}]
}
```

## CLI Usage

```bash
python agent.py --mode demo --output aar.json
python agent.py --mode generate --variant accelerated --output scenario.json
python agent.py --mode score --responses-file responses.json --output aar.json
```
