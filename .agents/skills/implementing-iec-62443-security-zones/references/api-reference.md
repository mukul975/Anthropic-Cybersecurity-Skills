# API Reference: Implementing IEC 62443 Security Zones

## Purdue Reference Model Levels

| Level | Name | Assets |
|-------|------|--------|
| 0 | Process | Sensors, actuators |
| 1 | Basic Control | PLCs, RTUs, safety controllers |
| 2 | Area Supervisory | HMIs, engineering workstations |
| 3 | Site Operations | Historians, OPC servers, MES |
| 3.5 | DMZ | Data diode, patch server |
| 4 | Enterprise | ERP, email, business systems |
| 5 | External | Internet, cloud, vendors |

## IEC 62443 Security Levels

| SL | Protection Against |
|----|--------------------|
| SL1 | Casual or coincidental violation |
| SL2 | Intentional violation using simple means |
| SL3 | Sophisticated attack with moderate resources |
| SL4 | State-sponsored attack with extended resources |

## Zone Audit Checks

| Check | Severity | Description |
|-------|----------|-------------|
| No SL-T defined | CRITICAL | Zone missing security level target |
| SL gap (achieved < target) | HIGH | Controls below target |
| No conduit controls | CRITICAL | Unprotected zone boundary |
| IT-OT bypass DMZ | CRITICAL | Direct Level 4/5 to Level 0/1 |
| Remote access without MFA | CRITICAL | Unprotected remote conduit |

## Conduit Security Controls

| Control | Purdue Boundary | Required |
|---------|----------------|----------|
| Protocol-aware firewall | L0-L1, L1-L2 | Yes |
| Data diode | L3-DMZ | Recommended |
| IDS/IPS | L2-L3, DMZ | Yes |
| VPN + MFA | DMZ-External | Yes |

### References

- IEC 62443-3-2: https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards
- NIST SP 800-82: https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final
- Purdue Model: https://www.nist.gov/system/files/documents/2017/04/28/08_Didier_NICE-Workshop.pdf
