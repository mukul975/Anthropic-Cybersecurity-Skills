# API Reference: Diamond Model Intrusion Analysis Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| (stdlib only) | Python 3.8+ | Dataclass-based Diamond Model event modeling |

## CLI Usage

```bash
python scripts/agent.py --data /intel/events.json --output-dir /reports/
```

## Functions

### `DiamondEvent` (dataclass)
Four vertices: adversary, capability, infrastructure, victim. Plus: phase, result, confidence, notes.

### `create_event(adversary, capability, infrastructure, victim, **kwargs) -> DiamondEvent`
Factory for creating Diamond Model events with auto-generated ID and timestamp.

### `load_events(data_path) -> list`
Loads events from JSON file with `{"events": [...]}` structure.

### `pivot_on_vertex(events, vertex, value) -> list`
Analytic pivot: returns all events sharing a specific vertex value.

### `build_activity_thread(events, adversary) -> dict`
Groups events by adversary chronologically. Lists capabilities, infrastructure, victims.

### `cluster_by_infrastructure(events) -> dict`
Groups event IDs by shared infrastructure for campaign identification.

### `compute_vertex_statistics(events) -> dict`
Counts unique values per vertex and confidence distribution.

## Input Format

```json
{
  "events": [{
    "adversary": "APT29",
    "capability": "Cobalt Strike",
    "infrastructure": "185.220.101.42",
    "victim": "finance-server-01",
    "phase": "Lateral Movement",
    "confidence": "high"
  }]
}
```

## Output Schema

```json
{
  "statistics": {"total_events": 15, "unique_adversaries": 2},
  "activity_threads": [{"adversary": "APT29", "event_count": 8}],
  "infrastructure_clusters": {"185.220.101.42": ["evt1", "evt5"]}
}
```
