# CrowdStrike EDR Deployment — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| crowdstrike-falconpy | `pip install crowdstrike-falconpy` | Official CrowdStrike Falcon SDK |

## Key FalconPy Service Classes

| Class | Description |
|-------|-------------|
| `Hosts(client_id, client_secret)` | Host/device management |
| `Detections(client_id, client_secret)` | Detection queries and management |
| `RealTimeResponse(client_id, client_secret)` | RTR session management |
| `SensorDownload(client_id, client_secret)` | Sensor installer download |
| `Prevention(client_id, client_secret)` | Prevention policy management |

## Key Methods

| Method | Description |
|--------|-------------|
| `hosts.query_devices_by_filter(filter=, limit=)` | Query host IDs |
| `hosts.get_device_details(ids=[])` | Get host details |
| `hosts.perform_action(action_name="contain", ids=[])` | Contain/lift containment |
| `detections.query_detects(filter=, sort=)` | Query detection IDs |
| `detections.get_detect_summaries(body={"ids": []})` | Get detection details |

## FQL Filter Examples

```
platform_name:'Windows' + status:'normal'
last_seen:>='2024-01-01T00:00:00Z'
hostname:'*server*'
```

## External References

- [FalconPy Documentation](https://www.falconpy.io/)
- [CrowdStrike API Swagger](https://assets.falcon.crowdstrike.com/support/api/swagger.html)
- [FalconPy GitHub](https://github.com/CrowdStrike/falconpy)
