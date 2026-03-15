---
name: detecting-beaconing-patterns-with-zeek
description: >
  Performs statistical analysis of Zeek conn.log connection intervals to detect C2
  beaconing patterns. Uses the ZAT library to load Zeek logs into Pandas DataFrames,
  calculates inter-arrival time standard deviation, and flags periodic connections
  with low jitter. Use when hunting for command-and-control callbacks in network data.
domain: cybersecurity
subdomain: security-operations
tags: [detecting, beaconing, patterns, with]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Beaconing Patterns with Zeek

## Instructions

Load Zeek conn.log data using ZAT (Zeek Analysis Tools), group connections by
source/destination pairs, and compute timing statistics to identify beaconing.

```python
from zat.log_to_dataframe import LogToDataFrame
import numpy as np

log_to_df = LogToDataFrame()
conn_df = log_to_df.create_dataframe('/path/to/conn.log')

# Group by src/dst pair and calculate inter-arrival time
for (src, dst), group in conn_df.groupby(['id.orig_h', 'id.resp_h']):
    times = group['ts'].sort_values()
    intervals = times.diff().dt.total_seconds().dropna()
    if len(intervals) > 10:
        std_dev = np.std(intervals)
        mean_interval = np.mean(intervals)
        # Low std_dev relative to mean = likely beaconing
```

Key analysis steps:
1. Parse Zeek conn.log into DataFrame with ZAT LogToDataFrame
2. Group connections by source IP and destination IP pairs
3. Calculate inter-arrival time intervals between consecutive connections
4. Compute standard deviation and coefficient of variation
5. Flag pairs with low coefficient of variation as potential beacons

## Examples

```python
from zat.log_to_dataframe import LogToDataFrame
log_to_df = LogToDataFrame()
df = log_to_df.create_dataframe('conn.log')
print(df[['id.orig_h', 'id.resp_h', 'ts', 'duration']].head())
```
