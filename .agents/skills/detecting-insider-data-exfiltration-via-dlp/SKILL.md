---
name: detecting-insider-data-exfiltration-via-dlp
description: >
  Detects insider data exfiltration by analyzing DLP policy violations, file access
  patterns, upload volume anomalies, and off-hours activity in endpoint and cloud logs.
  Uses pandas for behavioral analytics and statistical baselines. Use when investigating
  insider threats or building user behavior analytics for data loss prevention.
domain: cybersecurity
subdomain: security-operations
tags: [detecting, insider, data, exfiltration]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Detecting Insider Data Exfiltration via DLP

## Instructions

Analyze endpoint activity logs, cloud storage access, and email DLP events to detect
data exfiltration patterns using behavioral baselines and statistical anomaly detection.

```python
import pandas as pd

df = pd.read_csv("file_activity.csv", parse_dates=["timestamp"])
# Baseline: average daily upload volume per user
baseline = df.groupby(["user", df["timestamp"].dt.date])["bytes_transferred"].sum()
user_avg = baseline.groupby("user").mean()

# Alert on users exceeding 3x their baseline
today = df[df["timestamp"].dt.date == pd.Timestamp.today().date()]
today_totals = today.groupby("user")["bytes_transferred"].sum()
anomalies = today_totals[today_totals > user_avg * 3]
```

Key indicators:
1. Upload volume exceeding 3x daily baseline
2. Access to files outside normal scope
3. Bulk downloads before resignation
4. Off-hours file access patterns
5. USB/external device usage spikes

## Examples

```python
# Detect off-hours activity
df["hour"] = df["timestamp"].dt.hour
off_hours = df[(df["hour"] < 6) | (df["hour"] > 22)]
suspicious = off_hours.groupby("user").size().sort_values(ascending=False)
```
