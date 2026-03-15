# API Reference: Implementing Network Segmentation for OT

## Purdue Reference Model

| Level | Name | Assets |
|-------|------|--------|
| 0 | Process | Sensors, actuators, field devices |
| 1 | Basic Control | PLCs, RTUs, safety systems |
| 2 | Supervisory | HMIs, engineering workstations |
| 3 | Operations | Historians, MES, OPC servers |
| 3.5 | DMZ | Data diodes, patch servers |
| 4 | Enterprise | ERP, email, business apps |
| 5 | External | Internet, cloud, vendors |

## Zone Audit Checks

| Check | Severity | Description |
|-------|----------|-------------|
| No firewall | CRITICAL | Zone boundary unprotected |
| Control zone internet access | CRITICAL | Level 0/1 reaches internet |
| No IDS monitoring | HIGH | No intrusion detection |
| No DPI | HIGH | No OT protocol filtering |
| IT-OT bypass DMZ | CRITICAL | Direct Level 4 to Level 1 |

## Common OT Protocols

| Protocol | Port | Purdue Level |
|----------|------|-------------|
| Modbus/TCP | 502 | 0-1 |
| EtherNet/IP | 44818 | 0-2 |
| DNP3 | 20000 | 0-1 |
| OPC UA | 4840 | 1-3 |
| S7comm | 102 | 0-1 |

### References

- IEC 62443: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NIST SP 800-82: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- CISA ICS Security: https://www.cisa.gov/topics/industrial-control-systems
