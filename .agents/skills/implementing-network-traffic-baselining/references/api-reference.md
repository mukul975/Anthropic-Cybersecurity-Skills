# Network Traffic Baselining API Reference

## NetFlow/IPFIX CSV Format

### Expected Columns
```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets
2024-01-15T08:30:00Z,10.0.1.5,203.0.113.10,54321,443,6,15234,42
```

### Alternative Column Names (auto-mapped)
```
ts -> timestamp    sa -> src_ip     da -> dst_ip
sp -> src_port     dp -> dst_port   pr -> protocol
ibyt -> bytes      ipkt -> packets
```

### Protocol Numbers
| Number | Protocol |
|--------|----------|
| 1 | ICMP |
| 6 | TCP |
| 17 | UDP |

## Pandas Analysis Functions

### Hourly Aggregation
```python
df["hour"] = df["timestamp"].dt.hour
hourly = df.groupby("hour").agg(
    total_bytes=("bytes", "sum"),
    total_packets=("packets", "sum"),
    flow_count=("bytes", "count"),
)
```

### Z-Score Anomaly Detection
```python
mean = host_stats["total_bytes"].mean()
std = host_stats["total_bytes"].std()
host_stats["zscore"] = (host_stats["total_bytes"] - mean) / std
anomalies = host_stats[host_stats["zscore"].abs() >= 3.0]
```

### IQR Outlier Detection
```python
q1 = series.quantile(0.25)
q3 = series.quantile(0.75)
iqr = q3 - q1
outliers = series[(series < q1 - 1.5 * iqr) | (series > q3 + 1.5 * iqr)]
```

## NetFlow Export Tools

### nfdump CSV Export
```bash
nfdump -r nfcapd.202401 -o csv > flows.csv
```

### SiLK rwcut Export
```bash
rwcut --fields=sIP,dIP,sPort,dPort,protocol,bytes,packets,sTime flows.rw > flows.csv
```

### Elastic NetFlow to CSV
```json
GET netflow-*/_search
{ "size": 10000, "query": { "range": { "@timestamp": { "gte": "now-7d" } } } }
```

## CLI Usage
```bash
python agent.py --netflow-csv flows.csv --output baseline.json
python agent.py --netflow-csv flows.csv --zscore-threshold 2.5 --scan-threshold 30
```
