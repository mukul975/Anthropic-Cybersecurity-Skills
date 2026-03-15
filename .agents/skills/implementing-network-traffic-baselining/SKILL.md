---
name: implementing-network-traffic-baselining
description: Build network traffic baselines from NetFlow/IPFIX data using Python pandas for statistical analysis, z-score anomaly detection, and hourly/daily traffic pattern profiling
domain: cybersecurity
subdomain: network-security
tags:
  - netflow
  - ipfix
  - traffic-analysis
  - baselining
  - anomaly-detection
  - pandas
  - network-monitoring
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Network Traffic Baselining

## Overview

Network traffic baselining establishes normal communication patterns by analyzing historical NetFlow/IPFIX data to create statistical profiles of expected behavior. This skill uses Python pandas to compute hourly and daily traffic distributions, per-host byte/packet counts, protocol ratios, and top-N talker profiles. Anomalies are detected using z-score thresholds and IQR (interquartile range) outlier methods, enabling SOC analysts to identify deviations such as data exfiltration spikes, beaconing patterns, and unusual port usage.

## Prerequisites

- NetFlow v5/v9 or IPFIX flow data exported as CSV or JSON
- Python 3.8+ with pandas and numpy libraries
- Historical flow data (minimum 7 days recommended for baseline)

## Steps

1. Ingest NetFlow/IPFIX records from CSV or JSON exports
2. Compute hourly and daily traffic volume distributions (bytes, packets, flows)
3. Build per-source-IP baseline profiles with mean, median, standard deviation
4. Calculate protocol and port distribution baselines
5. Apply z-score anomaly detection to identify statistical outliers
6. Flag flows exceeding IQR-based thresholds as potential anomalies
7. Generate baseline report with anomaly alerts

## Expected Output

JSON report containing traffic baselines (hourly/daily profiles), per-host statistics, detected anomalies with z-scores, and top talker rankings with deviation indicators.
