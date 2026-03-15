# API Reference: User Behavior Analytics (UEBA) Agent

## Overview

Detects anomalous user behavior using Elasticsearch authentication logs: impossible travel via haversine distance, off-hours access against baselines, and composite risk scoring.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| elasticsearch | >= 8.0 | Elasticsearch Python client |
| math | stdlib | Haversine distance calculation |

## Core Functions

### `build_user_baselines(es, index, days)`
Builds 30-day behavioral baselines per user: unique IPs, countries, login hour stats, daily averages.
- **Returns**: `dict[str, dict]` - user to baseline mapping

### `detect_impossible_travel(es, index, hours)`
Detects sequential logins from locations requiring >900 km/h travel speed over >500 km distance.
- **Algorithm**: Haversine distance / time between consecutive logins per user
- **Returns**: `list[dict]` - alerts with from/to locations, distance, speed

### `detect_off_hours_access(es, baselines, index, hours)`
Flags logins outside 2 standard deviations from user's average login hour, on weekends, or between midnight-6am / after 10pm.
- **Returns**: `list[dict]` - alerts with user, timestamp, login hour, baseline

### `calculate_risk_scores(impossible_travel, off_hours, baselines)`
Aggregates anomalies into composite risk scores: +40 for impossible travel, +20 for off-hours.
- **Returns**: `list[tuple]` - (user, {risk, anomalies}) sorted descending

### `haversine(lat1, lon1, lat2, lon2)`
Great-circle distance between two geographic coordinates in km.
- **Returns**: `float` - distance in kilometers

## Elasticsearch Index Requirements

| Index | Fields Required |
|-------|----------------|
| `logs-auth-*` | `user.name`, `source.ip`, `source.geo.location`, `@timestamp`, `event.outcome` |

## Risk Score Weights

| Anomaly Type | Points |
|--------------|--------|
| Impossible travel | +40 |
| Off-hours access | +20 |
| Weekend access | +20 |

## Usage

```bash
python agent.py https://elastic.corp.local:9200
```
