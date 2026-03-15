# API Reference: Implementing Dragos Platform for OT Monitoring

## Dragos Platform API

```python
import requests
headers = {"Authorization": "Bearer <api_key>"}
base = "https://dragos-platform/api/v1"

assets = requests.get(f"{base}/assets", headers=headers).json()
detections = requests.get(f"{base}/detections", headers=headers).json()
vulns = requests.get(f"{base}/vulnerabilities", headers=headers).json()
```

## Monitored OT Protocols

| Protocol | Port | Use Case |
|----------|------|----------|
| Modbus/TCP | 502 | PLC communication |
| EtherNet/IP | 44818 | Industrial automation |
| DNP3 | 20000 | SCADA/utilities |
| OPC UA | 4840 | Industrial IoT |
| S7comm | 102 | Siemens PLCs |
| BACnet | 47808 | Building automation |
| IEC 61850 MMS | 102 | Power grid |

## Detection Categories

| Category | Description | Severity |
|----------|-------------|----------|
| New Asset | Unknown device on OT network | HIGH |
| Protocol Anomaly | Unusual command/response | HIGH |
| Firmware Change | PLC firmware modified | CRITICAL |
| Program Change | Ladder logic modified | CRITICAL |
| Unauthorized Access | IT device in OT zone | HIGH |

## ICS-CERT Vulnerability Feeds

```bash
# Dragos WorldView intelligence feed integration
curl "https://dragos-platform/api/v1/worldview/advisories" \
  -H "Authorization: Bearer $KEY"
```

### References

- Dragos Platform: https://www.dragos.com/platform/
- IEC 62443: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- CISA ICS Advisories: https://www.cisa.gov/news-events/ics-advisories
