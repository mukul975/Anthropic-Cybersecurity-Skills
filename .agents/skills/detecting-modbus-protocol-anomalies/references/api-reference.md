# API Reference: Detecting Modbus Protocol Anomalies

## Modbus Protocol Limits

| Parameter | Maximum Value |
|-----------|--------------|
| Coil read quantity | 2000 |
| Register read quantity | 125 |
| Register write quantity | 123 |
| Unit ID range | 1-247 |
| PDU size | 253 bytes |

## Anomaly Detection Methods

| Anomaly | Detection | Severity |
|---------|-----------|----------|
| Timing deviation | Polling interval outside tolerance | MEDIUM-HIGH |
| Excessive read | Quantity > protocol limits | HIGH |
| Invalid function code | Not in standard set | HIGH |
| Modbus scan | >5 unique function codes from source | HIGH |
| Register range violation | Address outside configured range | MEDIUM |

## Zeek Modbus Log Fields

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p func exception quantity
```

## Suricata Modbus Rules

```
alert modbus any any -> any 502 (msg:"Modbus Invalid Function Code"; \
  modbus: function !1,!2,!3,!4,!5,!6,!15,!16; sid:4000001;)
alert modbus any any -> any 502 (msg:"Modbus Excessive Register Read"; \
  modbus: function 3; modbus: quantity > 125; sid:4000002;)
```

## Scapy Modbus Analysis

```python
from scapy.contrib.modbus import ModbusADURequest
from scapy.all import rdpcap

pkts = rdpcap("modbus.pcap")
for pkt in pkts:
    if pkt.haslayer(ModbusADURequest):
        print(f"FC={pkt.funcCode} Len={pkt.len}")
```

## Baseline Monitoring

```python
# Expected polling behavior
expected_interval = 1.0  # seconds
tolerance = 0.5
# Alert if interval < 0.5s or > 3.0s
```

## CLI Usage

```bash
python agent.py --modbus-log modbus.log
python agent.py --modbus-log modbus.log --expected-interval 2.0
```
