---
name: detecting-anomalies-in-industrial-control-systems
description: >
  This skill covers deploying anomaly detection systems for industrial control
  environments using machine learning models trained on OT network baselines,
  physics-based process models, and behavioral analysis of industrial protocol
  communications. It addresses building normal behavior profiles for SCADA polling
  patterns, detecting deviations in Modbus/DNP3/OPC UA traffic, identifying rogue
  devices, and correlating network anomalies with physical process data from historians.
domain: cybersecurity
subdomain: ot-ics-security
tags: [ot-security, ics, scada, industrial-control, iec62443, anomaly-detection, machine-learning]
version: 1.0.0
author: mahipal
license: Apache-2.0
---

# Detecting Anomalies in Industrial Control Systems

## When to Use

- When deploying continuous monitoring for OT environments that lack intrusion detection
- When building behavior-based detection to complement signature-based IDS in OT networks
- When establishing baselines for deterministic SCADA communications to detect deviations
- When integrating machine learning anomaly detection with OT security monitoring platforms
- When investigating alerts from Nozomi Guardian or Dragos Platform that require deeper analysis

**Do not use** for signature-based detection of known exploits (see detecting-attacks-on-scada-systems), for IT network anomaly detection without OT protocols, or as a replacement for process safety systems (SIS).

## Prerequisites

- Passive network monitoring sensors on OT network SPAN/TAP ports
- Minimum 2-4 weeks of baseline traffic capture during normal operations
- Python 3.9+ with scikit-learn, numpy, pandas for ML model training
- Process historian access for physical process correlation data
- Understanding of normal operational patterns including shift changes, batch processes, and maintenance windows

## Workflow

### Step 1: Build Multi-Dimensional Baseline Model

Capture and model the deterministic behavior of ICS communications across multiple dimensions: timing, protocol behavior, and network topology.

```python
#!/usr/bin/env python3
"""ICS Anomaly Detection System.

Builds multi-dimensional baselines from OT network traffic and
detects anomalies using statistical and machine learning methods.
Designed for deterministic SCADA communication patterns.
"""

import json
import sys
import time
import warnings
from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")


@dataclass
class CommunicationProfile:
    """Profile for a single master-slave communication pair."""
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    avg_interval_ms: float = 0.0
    std_interval_ms: float = 0.0
    avg_payload_size: float = 0.0
    function_codes: dict = field(default_factory=dict)
    packets_per_minute: float = 0.0
    first_seen: str = ""
    last_seen: str = ""


class ICSAnomalyDetector:
    """Multi-dimensional anomaly detection for ICS environments."""

    def __init__(self):
        self.profiles = {}
        self.topology_baseline = set()
        self.timing_model = None
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.anomalies = []
        self.training_data = []

    def build_baseline_from_pcap(self, pcap_data):
        """Build baselines from parsed pcap data (list of flow records)."""
        print("[*] Building ICS communication baselines...")

        for flow in pcap_data:
            key = f"{flow['src']}->{flow['dst']}:{flow['port']}"

            if key not in self.profiles:
                self.profiles[key] = CommunicationProfile(
                    src_ip=flow["src"],
                    dst_ip=flow["dst"],
                    protocol=flow.get("protocol", "TCP"),
                    port=flow["port"],
                    first_seen=flow.get("timestamp", ""),
                )

            profile = self.profiles[key]
            profile.last_seen = flow.get("timestamp", "")

            # Track function codes for industrial protocols
            fc = flow.get("function_code")
            if fc is not None:
                profile.function_codes[fc] = profile.function_codes.get(fc, 0) + 1

            # Add to topology baseline
            self.topology_baseline.add((flow["src"], flow["dst"], flow["port"]))

        # Calculate interval statistics
        self._calculate_timing_stats(pcap_data)

        print(f"  Communication pairs: {len(self.profiles)}")
        print(f"  Topology entries: {len(self.topology_baseline)}")

    def _calculate_timing_stats(self, flows):
        """Calculate packet timing statistics per communication pair."""
        timestamps = defaultdict(list)
        for flow in flows:
            key = f"{flow['src']}->{flow['dst']}:{flow['port']}"
            ts = flow.get("timestamp_epoch")
            if ts:
                timestamps[key].append(ts)

        for key, ts_list in timestamps.items():
            if key in self.profiles and len(ts_list) > 1:
                ts_sorted = sorted(ts_list)
                intervals = [
                    (ts_sorted[i+1] - ts_sorted[i]) * 1000
                    for i in range(len(ts_sorted) - 1)
                ]
                self.profiles[key].avg_interval_ms = np.mean(intervals)
                self.profiles[key].std_interval_ms = np.std(intervals)
                duration_min = (ts_sorted[-1] - ts_sorted[0]) / 60
                if duration_min > 0:
                    self.profiles[key].packets_per_minute = len(ts_list) / duration_min

    def train_isolation_forest(self, features_df):
        """Train Isolation Forest model on feature vectors from baseline traffic."""
        print("[*] Training Isolation Forest model...")

        feature_cols = [
            "interval_ms", "payload_size", "packets_per_window",
            "unique_func_codes", "new_connection_flag",
        ]

        available_cols = [c for c in feature_cols if c in features_df.columns]
        X = features_df[available_cols].fillna(0).values

        X_scaled = self.scaler.fit_transform(X)

        self.isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=0.01,  # Expect 1% anomaly rate in baseline
            random_state=42,
            n_jobs=-1,
        )
        self.isolation_forest.fit(X_scaled)

        scores = self.isolation_forest.decision_function(X_scaled)
        print(f"  Model trained on {len(X)} samples")
        print(f"  Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")
        print(f"  Threshold: {np.percentile(scores, 1):.4f}")

    def detect_topology_anomaly(self, src_ip, dst_ip, port):
        """Detect new/unauthorized communication pairs."""
        if (src_ip, dst_ip, port) not in self.topology_baseline:
            return {
                "type": "NEW_COMMUNICATION_PAIR",
                "severity": "high",
                "detail": f"New connection: {src_ip} -> {dst_ip}:{port} not in baseline",
                "recommendation": "Verify if this is an authorized new device or configuration change",
            }
        return None

    def detect_timing_anomaly(self, src_ip, dst_ip, port, interval_ms):
        """Detect polling interval deviations."""
        key = f"{src_ip}->{dst_ip}:{port}"
        profile = self.profiles.get(key)

        if profile and profile.std_interval_ms > 0:
            z_score = abs(interval_ms - profile.avg_interval_ms) / profile.std_interval_ms
            if z_score > 4.0:
                return {
                    "type": "TIMING_ANOMALY",
                    "severity": "medium",
                    "detail": (
                        f"Interval {interval_ms:.1f}ms deviates from baseline "
                        f"{profile.avg_interval_ms:.1f}ms (z-score: {z_score:.1f})"
                    ),
                    "recommendation": "Check for network congestion, device malfunction, or MITM attack",
                }
        return None

    def detect_function_code_anomaly(self, src_ip, dst_ip, port, func_code):
        """Detect unauthorized Modbus/DNP3 function codes."""
        key = f"{src_ip}->{dst_ip}:{port}"
        profile = self.profiles.get(key)

        if profile and func_code not in profile.function_codes:
            severity = "critical" if func_code in {5, 6, 15, 16, 8} else "high"
            return {
                "type": "UNAUTHORIZED_FUNCTION_CODE",
                "severity": severity,
                "detail": (
                    f"Function code {func_code} from {src_ip} to {dst_ip}:{port} "
                    f"not in baseline. Allowed: {list(profile.function_codes.keys())}"
                ),
                "recommendation": "Investigate source - possible command injection attack",
            }
        return None

    def analyze_flow(self, flow):
        """Analyze a single network flow against all detection models."""
        results = []

        # Topology check
        topo = self.detect_topology_anomaly(flow["src"], flow["dst"], flow["port"])
        if topo:
            results.append(topo)

        # Timing check
        if "interval_ms" in flow:
            timing = self.detect_timing_anomaly(
                flow["src"], flow["dst"], flow["port"], flow["interval_ms"])
            if timing:
                results.append(timing)

        # Function code check
        if "function_code" in flow:
            fc = self.detect_function_code_anomaly(
                flow["src"], flow["dst"], flow["port"], flow["function_code"])
            if fc:
                results.append(fc)

        self.anomalies.extend(results)
        return results

    def generate_report(self):
        """Generate anomaly detection report."""
        print(f"\n{'='*60}")
        print(f"ICS ANOMALY DETECTION REPORT")
        print(f"{'='*60}")
        print(f"Baseline Profiles: {len(self.profiles)}")
        print(f"Anomalies Detected: {len(self.anomalies)}")

        severity_counts = defaultdict(int)
        for a in self.anomalies:
            severity_counts[a["severity"]] += 1

        for sev in ["critical", "high", "medium", "low"]:
            if severity_counts[sev]:
                print(f"  {sev.upper()}: {severity_counts[sev]}")

        for a in self.anomalies[:20]:
            print(f"\n  [{a['severity'].upper()}] {a['type']}")
            print(f"    {a['detail']}")


if __name__ == "__main__":
    print("ICS Anomaly Detection System")
    print("Load baseline data and call analyze_flow() for real-time detection")
```

## Key Concepts

| Term | Definition |
|------|------------|
| Deterministic Traffic | ICS networks exhibit highly predictable communication patterns where the same master polls the same slaves at fixed intervals with identical function codes |
| Isolation Forest | Unsupervised machine learning algorithm that isolates anomalies by randomly partitioning feature space, effective for OT traffic with low anomaly rates |
| Polling Interval | Time between consecutive SCADA master requests to a slave device, typically fixed and configurable (100ms to 10s) |
| Function Code Allowlist | Set of permitted industrial protocol operations for each communication pair, enforced by anomaly detection rules |
| Topology Baseline | Complete map of all authorized device-to-device communication paths in the OT network |
| Physics-Based Detection | Using physical process models (thermodynamics, fluid dynamics) to detect attacks that manipulate the process while spoofing sensor data |

## Tools & Systems

- **Nozomi Networks Guardian**: OT anomaly detection with AI-powered baseline learning and industrial protocol analysis
- **Dragos Platform**: Threat detection using behavioral analytics and threat intelligence specific to ICS environments
- **Scikit-learn**: Python ML library with Isolation Forest, One-Class SVM, and Local Outlier Factor for anomaly detection
- **Zeek with OT plugins**: Network security monitor with Modbus, DNP3, and BACnet protocol analyzers for baseline building

## Output Format

```
ICS Anomaly Detection Report
==============================
Detection Period: YYYY-MM-DD to YYYY-MM-DD
Baseline Size: [N] communication profiles

ANOMALIES DETECTED: [N]
  Critical: [N]  High: [N]  Medium: [N]  Low: [N]

[SEVERITY] ANOMALY_TYPE
  Source: [IP] -> Target: [IP]:[Port]
  Detail: [Description of deviation from baseline]
  Baseline: [Expected behavior]
  Observed: [Actual behavior]
```
