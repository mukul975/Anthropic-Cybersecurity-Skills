# API Reference: Detecting DNP3 Protocol Anomalies

## DNP3 Function Codes

| Code | Name | Risk Level |
|------|------|------------|
| 0x01 | READ | Normal |
| 0x02 | WRITE | Caution |
| 0x03 | SELECT | Caution |
| 0x04 | OPERATE | Critical |
| 0x05 | DIRECT_OPERATE | Critical |
| 0x0D | COLD_RESTART | Critical |
| 0x0E | WARM_RESTART | Critical |
| 0x10 | INITIALIZE_APPLICATION | Critical |
| 0x12 | STOP_APPLICATION | Critical |

## Zeek DNP3 Log Fields

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p fc_request fc_reply
```

## Zeek DNP3 Protocol Analyzer

```bash
# Enable DNP3 analyzer in Zeek
zeek -C -r capture.pcap protocols/dnp3

# Output: dnp3.log with function codes, objects, IIN bits
```

## Suricata DNP3 Rules

```
alert dnp3 any any -> any 20000 (msg:"DNP3 Cold Restart"; \
  dnp3_func:cold_restart; sid:1000001; rev:1;)

alert dnp3 any any -> any 20000 (msg:"DNP3 Direct Operate"; \
  dnp3_func:direct_operate; sid:1000002; rev:1;)
```

## Scapy DNP3 Parsing

```python
from scapy.all import rdpcap
from scapy.contrib.dnp3 import DNP3

packets = rdpcap("dnp3_capture.pcap")
for pkt in packets:
    if pkt.haslayer(DNP3):
        print(pkt[DNP3].func_code)
```

## ICS-CERT Detection Indicators

| Anomaly | Detection Method |
|---------|-----------------|
| Unauthorized master | Source IP not in allowed list |
| Burst traffic | >10 events/sec from single source |
| Off-hours commands | Control operations outside maintenance windows |
| Unknown function codes | Function codes not in normal baseline |

## CLI Usage

```bash
python agent.py --zeek-log dnp3.log
python agent.py --zeek-log dnp3.log --authorized-masters masters.txt
```
