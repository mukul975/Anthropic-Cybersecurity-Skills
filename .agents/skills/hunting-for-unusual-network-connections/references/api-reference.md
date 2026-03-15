# API Reference: Hunting for Unusual Network Connections

## Connection Analysis Indicators

| Indicator | Threshold | Severity |
|-----------|-----------|----------|
| Known bad port (4444, 31337) | Any connection | CRITICAL |
| Non-standard port | Not in common set | MEDIUM |
| Rare destination (< 3 conns) | Unique in environment | HIGH |
| Long connection (> 1hr) | Duration > 3600s | HIGH |
| Periodic beaconing (CV < 0.3) | Low interval variance | CRITICAL |

## Splunk SPL - Rare Destinations

```spl
index=firewall action=allowed
| stats dc(src_ip) as src_count count by dest_ip dest_port
| where src_count == 1 AND count < 5
| sort -count
| table dest_ip dest_port count src_count
```

## KQL - Non-Standard Ports

```kql
DeviceNetworkEvents
| where RemotePort !in (80, 443, 53, 22, 25, 8080)
| summarize ConnectionCount=count(), dcount(DeviceId) by RemoteIP, RemotePort
| where ConnectionCount < 5
| sort by ConnectionCount asc
```

## Zeek conn.log Analysis

```python
from zat.log_to_dataframe import LogToDataFrame
df = LogToDataFrame().create_dataframe("conn.log")
# Filter rare external destinations
external = df[~df["id.resp_h"].str.startswith(("10.", "172.16.", "192.168."))]
rare = external.groupby("id.resp_h").size().reset_index(name="count")
rare = rare[rare["count"] < 3]
```

## Beaconing Detection

```python
import numpy as np
intervals = np.diff(sorted_timestamps)
cv = np.std(intervals) / np.mean(intervals)
# CV < 0.3 = high periodicity (likely beacon)
```

## Sysmon Event ID 3 (Network Connection)

```xml
<EventData>
  <Data Name="Image">C:\Windows\System32\svchost.exe</Data>
  <Data Name="DestinationIp">203.0.113.50</Data>
  <Data Name="DestinationPort">4444</Data>
</EventData>
```

### References

- MITRE T1071: https://attack.mitre.org/techniques/T1071/
- MITRE T1571: https://attack.mitre.org/techniques/T1571/
- ZAT: https://github.com/SuperCowPowers/zat
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
