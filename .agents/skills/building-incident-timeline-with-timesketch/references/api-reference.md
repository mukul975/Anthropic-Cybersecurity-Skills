# API Reference: Incident Timeline Building with Timesketch

## Authentication
```
POST /login/
Content-Type: application/x-www-form-urlencoded
Body: username=USER&password=PASS
```

## Sketch Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/sketches/` | List all sketches |
| POST | `/api/v1/sketches/` | Create new sketch |
| GET | `/api/v1/sketches/{id}/` | Get sketch details |
| DELETE | `/api/v1/sketches/{id}/` | Delete sketch |

## Timeline Upload
```
POST /api/v1/upload/
Content-Type: multipart/form-data
Fields: name, sketch_id, file (Plaso/CSV/JSONL)
```

## Event Search (Explore)
```
POST /api/v1/sketches/{id}/explore/
{
  "query": "source_short:EVT AND message:*logon*",
  "limit": 500,
  "fields": ["datetime", "timestamp_desc", "message", "source_short"],
  "filter": {
    "chips": [
      {"type": "datetime_range", "value": "2024-01-01T00:00:00,2024-01-31T23:59:59", "active": true}
    ]
  }
}
```

## Event Annotation
```
POST /api/v1/sketches/{id}/event/annotate/
{
  "annotation": "suspicious,lateral-movement",
  "annotation_type": "tag",
  "events": {"event_id": "abc123"}
}
```

## Supported Timeline Formats
| Format | Extension | Description |
|--------|-----------|-------------|
| Plaso | `.plaso` | log2timeline output |
| CSV | `.csv` | Timesketch CSV (datetime, message, timestamp_desc) |
| JSONL | `.jsonl` | One JSON event per line |

## Event Fields
| Field | Description |
|-------|-------------|
| `datetime` | Event timestamp (ISO 8601) |
| `timestamp_desc` | Timestamp meaning (e.g., "Creation Time") |
| `message` | Human-readable event description |
| `source_short` | Source type (EVT, FILE, LOG, REG) |
| `source_long` | Full source name |

## Analyzers
```
POST /api/v1/sketches/{id}/analyzer/
{"analyzer_names": ["domain", "similarity_scorer", "tagger"]}
```

## Python Client
```python
from timesketch_api_client import config as ts_config
from timesketch_api_client import client as ts_client

ts = ts_client.TimesketchApi(host, username, password)
sketch = ts.get_sketch(sketch_id)
results = sketch.explore(query="*", return_fields="datetime,message")
```
