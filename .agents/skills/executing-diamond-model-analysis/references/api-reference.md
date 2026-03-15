# API Reference: Diamond Model Analysis Agent

## Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| Python stdlib | 3.8+ | json, dataclasses, hashlib, argparse |

## CLI Usage

```bash
python scripts/agent.py \
  --input events.json \
  --output diamond_report.json \
  --pivot-type infrastructure \
  --pivot-value "185.220.101.42"
```

## Input Format

```json
[
  {
    "event_id": "EVT-001",
    "timestamp": "2025-01-15T14:30:00Z",
    "adversary": ["APT29"],
    "adversary_confidence": "high",
    "capabilities": ["SUNBURST", "T1071.001"],
    "infrastructure": ["185.220.101.42", "evil-redir.com"],
    "victims": ["TargetCorp"],
    "phase": "C2",
    "result": "success"
  }
]
```

## Functions

### `create_event(event_data) -> DiamondEvent`
Constructs a `DiamondEvent` dataclass from raw dict. Auto-generates `event_id` via MD5 if not provided.

### `pivot_on_vertex(events, vertex_type, value) -> list`
Returns events sharing a specified vertex value. Supports pivoting on `adversary`, `capability`, `infrastructure`, `victim`.

### `cluster_events(events) -> dict`
Groups events by shared infrastructure or capability values. Returns clusters with overlapping event IDs.

### `build_activity_thread(events) -> list`
Sorts events chronologically and assigns sequence numbers for timeline reconstruction.

### `generate_report(events) -> dict`
Produces the full Diamond Model report with unique entities, activity thread, and clusters.

## Data Classes

### `Vertex`
Fields: `vertex_type` (str), `values` (list), `confidence` (str), `notes` (str)

### `DiamondEvent`
Fields: `event_id`, `timestamp`, `adversary` (Vertex), `capability` (Vertex), `infrastructure` (Vertex), `victim` (Vertex), `phase`, `direction`, `result`

## Output Schema

```json
{
  "report_date": "ISO-8601",
  "total_events": 5,
  "unique_adversaries": ["APT29"],
  "unique_infrastructure": ["185.220.101.42"],
  "activity_thread": [{"sequence": 1, "event_id": "EVT-001", ...}],
  "clusters": {"clusters": [...], "total_events": 5}
}
```
