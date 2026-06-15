---
name: analyzing-network-flow-data-with-netflow
description: Parse NetFlow v9 and IPFIX records to detect volumetric anomalies, port
  scanning, data exfiltration, and C2 beaconing patterns. Uses the Python netflow
  library to decode flow records, builds traffic baselines, and applies statistical
  analysis to identify flows with abnormal byte counts, connection durations, and
  periodic timing patterns.
domain: cybersecurity
subdomain: network-security
tags:
- analyzing
- network
- flow
- data
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1071
- T1048
- T1046
- T1095
---


# Analyzing Network Flow Data with Netflow


## When to Use

- When investigating security incidents that require analyzing network flow data with netflow
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

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
