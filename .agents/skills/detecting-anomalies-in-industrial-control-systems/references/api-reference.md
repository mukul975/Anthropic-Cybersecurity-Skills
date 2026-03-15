# ICS Anomaly Detection — API Reference

## Libraries

| Library | Install | Purpose |
|---------|---------|---------|
| pymodbus | `pip install pymodbus` | Modbus TCP/RTU client |
| requests | `pip install requests` | Historian and SIEM API access |

## Modbus TCP Protocol

| Function Code | Name | Risk |
|---------------|------|------|
| 1 | Read Coils | Low |
| 3 | Read Holding Registers | Low |
| 5 | Write Single Coil | Medium |
| 6 | Write Single Register | Medium |
| 15 | Write Multiple Coils | High |
| 16 | Write Multiple Registers | High |
| 43 | Read Device Identification | Recon |

## Common ICS Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 502 | Modbus TCP | PLC communication |
| 102 | S7comm | Siemens S7 PLCs |
| 44818 | EtherNet/IP | Allen-Bradley / Rockwell |
| 20000 | DNP3 | Distributed Network Protocol |
| 4840 | OPC-UA | OPC Unified Architecture |
| 47808 | BACnet | Building automation |

## pymodbus Client Usage

```python
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient("192.168.1.10", port=502)
client.connect()
result = client.read_holding_registers(0, count=10, slave=1)
print(result.registers)
client.close()
```

## Anomaly Detection Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| Unusual function codes | FC 8, 17, 43, 90+ | HIGH |
| Write frequency > 100/min | Burst writes | CRITICAL |
| Exception responses | Any exception code | MEDIUM |
| New source IP to PLC | Unauthorized access | CRITICAL |

## External References

- [pymodbus Docs](https://pymodbus.readthedocs.io/)
- [ICS-CERT Advisories](https://www.cisa.gov/ics-advisories)
- [NIST SP 800-82 Guide to ICS Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
