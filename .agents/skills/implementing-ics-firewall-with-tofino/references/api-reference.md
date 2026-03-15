# API Reference: Implementing ICS Firewall with Tofino

## OT Protocol Ports

| Protocol | Port | Layer | DPI Support |
|----------|------|-------|-------------|
| Modbus/TCP | 502 | TCP | Yes |
| EtherNet/IP | 44818 | TCP/UDP | Yes |
| DNP3 | 20000 | TCP | Yes |
| OPC UA | 4840 | TCP | Yes |
| S7comm | 102 | TCP | Yes |
| BACnet | 47808 | UDP | Yes |
| IEC 61850 MMS | 102 | TCP | Yes |

## Risky Modbus Function Codes

| Code | Function | Risk |
|------|----------|------|
| 5 | Write Single Coil | HIGH |
| 6 | Write Single Register | HIGH |
| 15 | Write Multiple Coils | HIGH |
| 16 | Write Multiple Registers | HIGH |
| 22 | Mask Write Register | HIGH |

## Tofino Xenon Configuration

```xml
<TofinoRule>
  <Action>Allow</Action>
  <Source>192.168.1.10</Source>
  <Destination>192.168.1.50</Destination>
  <Protocol>Modbus</Protocol>
  <Port>502</Port>
  <DPI enabled="true">
    <AllowedFunctions>1,2,3,4</AllowedFunctions>
  </DPI>
  <Logging>true</Logging>
</TofinoRule>
```

## Rule Audit Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Allow-any-any | CRITICAL | Overly permissive rule |
| No default deny | CRITICAL | Missing deny-all at end |
| No DPI for OT protocol | HIGH | Missing deep packet inspection |
| Write functions allowed | HIGH | Modbus write codes permitted |
| Allow without logging | MEDIUM | No audit trail |

### References

- Belden Tofino: https://www.belden.com/products/industrial-networking/cybersecurity
- IEC 62443-3-3: Industrial Automation Security
- NIST SP 800-82: Guide to ICS Security
