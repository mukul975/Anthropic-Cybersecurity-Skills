# API Reference: Implementing OT Network Traffic Analysis with Nozomi

## Nozomi Guardian REST API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/alerts` | GET | Retrieve security alerts |
| `/api/v1/assets` | GET | Get discovered asset inventory |
| `/api/v1/nodes` | GET | Get network nodes |
| `/api/v1/links` | GET | Get network links/connections |
| `/api/v1/sessions` | GET | Get active network sessions |
| `/api/v1/queries` | POST | Execute N2OS query |
| `/api/v1/health` | GET | Sensor health status |

## Authentication

```bash
# Bearer token
curl -s -k -H "Authorization: Bearer <token>" https://guardian/api/v1/assets

# API key (Vantage)
curl -s -H "X-Api-Key: <key>" https://vantage.nozominetworks.com/api/v1/assets
```

## N2OS Query Language

```sql
-- Find all PLCs
alerts | where type == plc

-- Find new connections in last 24h
sessions | where first_seen > ago(24h) | sort by bytes desc

-- Find Modbus traffic
sessions | where protocol == modbus | select src_ip, dst_ip, function_code
```

## Supported OT Protocols

| Protocol | Detection | DPI Support |
|----------|-----------|-------------|
| Modbus/TCP | Full | Function code analysis |
| S7comm | Full | Block read/write detection |
| EtherNet/IP (CIP) | Full | Service code inspection |
| DNP3 | Full | Object group parsing |
| OPC UA | Full | Service/node inspection |
| BACnet | Full | Object/property analysis |
| PROFINET | Full | Cyclic/acyclic detection |
| IEC 60870-5-104 | Full | ASDU type parsing |

## Alert Risk Levels

| Level | Score Range | Response |
|-------|-------------|----------|
| Critical | 9.0 - 10.0 | Immediate investigation |
| High | 7.0 - 8.9 | Investigate within 4 hours |
| Medium | 4.0 - 6.9 | Investigate within 24 hours |
| Low | 0.1 - 3.9 | Review during next shift |

## Sensor Deployment

| Mode | Use Case |
|------|----------|
| SPAN/Mirror | Switch mirror port monitoring |
| TAP | Network TAP for full-duplex capture |
| Smart Polling | Active query for asset enrichment |

### References

- Nozomi Guardian API Docs: https://www.nozominetworks.com/resources/
- IEC 62443-3-3: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NIST SP 800-82 Rev 3: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
