---
name: analyzing-network-flow-data-with-netflow
description: >-
  Parse NetFlow v9 and IPFIX records to detect volumetric anomalies, port scanning, data
  exfiltration, and C2 beaconing patterns. Uses the Python netflow library to decode flow
  records, builds traffic baselines, and applies statistical analysis to identify flows
  with abnormal byte counts, connection durations, and periodic timing patterns.
domain: cybersecurity
subdomain: network-security
tags: [analyzing, network, flow, data]
version: "1.0"
author: mahipal
license: Apache-2.0
---

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Generate a prioritized findings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Examples

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```
