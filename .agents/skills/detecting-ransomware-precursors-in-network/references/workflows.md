# Workflows - Detecting Ransomware Precursors in Network

## Workflow 1: Network Sensor Deployment

```
Start
  |
  v
[Identify network chokepoints] --> Core switches, internet edge, DC segments
  |
  v
[Deploy network TAPs or configure SPAN ports]
  |
  v
[Install Zeek sensor] --> Configure local.zeek with site-specific networks
  |
  v
[Install Suricata IDS] --> Load ET Open + custom ransomware rules
  |
  v
[Configure log forwarding to SIEM]
  |-- Zeek: conn.log, ssl.log, dns.log, smb.log, kerberos.log, notice.log
  |-- Suricata: eve.json (alerts, flow, dns, tls)
  |
  v
[Deploy RITA for beacon analysis] --> Schedule hourly Zeek log imports
  |
  v
[Load threat intelligence feeds] --> Feodo, ThreatFox, CISA KEV
  |
  v
[Validate detection with controlled Cobalt Strike beacon test]
  |
  v
End
```

## Workflow 2: Alert Triage for Ransomware Precursors

```
Alert Received
  |
  v
[Classify alert type]
  |-- C2 Beaconing --> Priority: CRITICAL, SLA: 15 min
  |-- Credential Harvesting --> Priority: CRITICAL, SLA: 15 min
  |-- Internal Scanning --> Priority: HIGH, SLA: 30 min
  |-- Admin Share Access --> Priority: HIGH, SLA: 30 min
  |-- RDP Brute Force --> Priority: MEDIUM, SLA: 1 hour
  |-- DNS Anomaly --> Priority: LOW, SLA: 4 hours
  |
  v
[Check for correlated alerts on same source IP]
  |-- Multiple categories? --> Elevate to CRITICAL regardless
  |-- Single category? --> Proceed with category SLA
  |
  v
[Verify source host context]
  |-- Known admin workstation? --> Check if scheduled activity
  |-- Server? --> Check for authorized maintenance window
  |-- Standard workstation? --> Likely compromise indicator
  |
  v
[Decision: True Positive or False Positive?]
  |
  TP --> [Contain host: network isolation via NAC/EDR]
  |       |
  |       v
  |       [Trigger incident response playbook]
  |
  FP --> [Document FP reason]
          |
          v
          [Update detection rule to reduce FP rate]
          |
          v
          End
```

## Workflow 3: Beacon Detection with RITA

```
Hourly Cron Job
  |
  v
[Import latest Zeek logs into RITA database]
  $ rita import /opt/zeek/logs/current rita-db
  |
  v
[Analyze beacons]
  $ rita show-beacons rita-db --human-readable
  |
  v
[Filter results by beacon score > 0.7]
  |
  v
[For each high-score beacon:]
  |-- Look up destination IP in threat intel
  |-- Check JA3/JA4 hash against known C2 fingerprints
  |-- Verify beacon interval and jitter pattern
  |
  v
[Score > 0.9 AND matches threat intel?]
  |
  Yes --> [Generate CRITICAL alert]
  |
  No --> [Score > 0.7?]
          |
          Yes --> [Generate MEDIUM alert for analyst review]
          |
          No --> [Log and continue monitoring]
  |
  v
End
```
