# API Reference: Detecting Modbus Command Injection Attacks

## Modbus Function Codes

| Code | Function | Risk |
|------|----------|------|
| 1 | Read Coils | Read |
| 3 | Read Holding Registers | Read |
| 5 | Write Single Coil | Write (dangerous) |
| 6 | Write Single Register | Write (dangerous) |
| 15 | Write Multiple Coils | Write (dangerous) |
| 16 | Write Multiple Registers | Write (dangerous) |
| 8 | Diagnostics | Diagnostic |

## Zeek Modbus Log

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p func
```

## Suricata Modbus Rules

```
alert modbus any any -> any 502 (msg:"Modbus Write Coil"; \
  modbus: function 5; sid:3000001;)
alert modbus any any -> any 502 (msg:"Modbus Write Multiple Registers"; \
  modbus: function 16; sid:3000002;)
```

## pymodbus Library

```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient("192.168.1.100", port=502)
client.connect()
result = client.read_holding_registers(0, 10, slave=1)
print(result.registers)
client.close()
```

## Scapy Modbus Parsing

```python
from scapy.contrib.modbus import ModbusADURequest
from scapy.all import rdpcap

pkts = rdpcap("modbus.pcap")
for pkt in pkts:
    if pkt.haslayer(ModbusADURequest):
        print(f"Function: {pkt.funcCode}")
```

## Detection Thresholds

| Anomaly | Threshold | Severity |
|---------|-----------|----------|
| Write flood | >20 writes/60s | CRITICAL |
| Unknown function code | Any | HIGH |
| Unauthorized master | Not in allowlist | CRITICAL |

## CLI Usage

```bash
python agent.py --zeek-log modbus.log
python agent.py --zeek-log modbus.log --authorized-masters 10.0.0.1 10.0.0.2
```
