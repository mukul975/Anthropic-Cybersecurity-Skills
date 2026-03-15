# Ransomware Precursor Detection Deployment Template

## Network Sensor Placement

| Sensor Location | TAP/SPAN | Sensor Type | Protocols Monitored |
|----------------|----------|-------------|---------------------|
| Internet Edge | | Zeek + Suricata | All outbound |
| DC Segment | | Zeek | Kerberos, LDAP, SMB, DNS |
| Server VLAN | | Zeek + Suricata | SMB, RDP, WMI, WinRM |
| Workstation VLAN | | Zeek | SMB, HTTP/S, DNS |

## Detection Rules Deployed

| Rule ID | Category | Description | Severity | Status |
|---------|----------|-------------|----------|--------|
| | C2 Beaconing | | | |
| | Credential Harvest | | | |
| | Internal Scanning | | | |
| | Lateral Movement | | | |

## Threat Intelligence Feeds

| Feed | Source | Update Frequency | IOC Types |
|------|--------|-----------------|-----------|
| Feodo Tracker | abuse.ch | Hourly | IPs (C2) |
| ThreatFox | abuse.ch | Hourly | IPs, domains, hashes |
| ET Open Rules | Proofpoint | Daily | Suricata signatures |
| CISA KEV | CISA | As published | CVEs |

## Alert Triage SLAs

| Category | Priority | Triage SLA | Escalation Path |
|----------|----------|-----------|-----------------|
| Confirmed C2 | CRITICAL | 15 min | SOC -> IR Team -> CISO |
| Credential Harvest | CRITICAL | 15 min | SOC -> IR Team |
| Internal Scanning | HIGH | 30 min | SOC -> IR Team |
| Admin Share Enum | HIGH | 30 min | SOC -> IR Team |
| RDP Anomaly | MEDIUM | 1 hour | SOC Tier 2 |
| DNS Anomaly | LOW | 4 hours | SOC Tier 1 |

## Detection Tuning Log

| Date | Rule | Change | Reason | FP Rate Before | FP Rate After |
|------|------|--------|--------|----------------|---------------|
| | | | | | |
