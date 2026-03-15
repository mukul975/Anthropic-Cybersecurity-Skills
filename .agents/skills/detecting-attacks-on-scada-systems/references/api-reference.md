# SCADA Attack Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| pymodbus | `pip install pymodbus` | Modbus TCP client for PLC interaction |
| requests | `pip install requests` | SIEM and historian API queries |

## Common SCADA Protocols and Ports

| Port | Protocol | Vendor/Use |
|------|----------|------------|
| 502 | Modbus TCP | Universal PLC communication |
| 102 | S7comm (ISO-TSAP) | Siemens S7 PLCs |
| 44818 | EtherNet/IP CIP | Allen-Bradley / Rockwell |
| 20000 | DNP3 | Power grid, water systems |
| 4840 | OPC-UA | Universal ICS integration |
| 47808 | BACnet | Building automation |
| 34962 | PROFINET RT | Siemens distributed I/O |

## Modbus Attack Indicators

| Indicator | Description | Severity |
|-----------|-------------|----------|
| Broadcast unit ID (0/255) | Access to all devices simultaneously | CRITICAL |
| Write to coils from IT network | Unauthorized process control change | CRITICAL |
| Unusual function codes (8, 17, 43) | Diagnostic/recon commands | HIGH |
| Bulk register reads | Data exfiltration from PLC memory | MEDIUM |

## S7comm Connection Request (COTP CR)

| Field | Value | Description |
|-------|-------|-------------|
| TPKT version | 0x03 | ISO transport header |
| COTP PDU type | 0xe0 | Connection request |
| Source TSAP | 0x0100 | Client address |
| Destination TSAP | 0x0102 | PLC rack/slot |

## MITRE ATT&CK for ICS

| Technique | ID | Description |
|-----------|----|-------------|
| Point & Tag Identification | T0861 | Enumerate process data points |
| Unauthorized Command Message | T0855 | Send rogue commands to controller |
| Modify Controller Tasking | T0821 | Change PLC program logic |
| Denial of Service | T0814 | Disrupt SCADA communications |

## External References

- [pymodbus Documentation](https://pymodbus.readthedocs.io/)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
- [CISA ICS Advisories](https://www.cisa.gov/ics-advisories)
- [NIST SP 800-82 Rev 3](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
