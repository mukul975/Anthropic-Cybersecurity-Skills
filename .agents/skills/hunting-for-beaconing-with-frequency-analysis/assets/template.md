# Beaconing Frequency Analysis Hunt Template

## Hunt Metadata
| Field | Value |
|-------|-------|
| Hunt ID | TH-BEACON-YYYY-MM-DD-NNN |
| Analyst | |
| Date | |
| Data Window | [Start] to [End] |
| Status | [ ] In Progress / [ ] Complete |

## Hypothesis
> Compromised endpoints are beaconing to adversary C2 infrastructure using periodic HTTP/HTTPS/DNS connections with detectable frequency patterns.

## Data Sources
- [ ] Proxy logs
- [ ] Firewall logs
- [ ] Zeek conn.log
- [ ] Zeek dns.log
- [ ] Zeek ssl.log
- [ ] Sysmon Event ID 3 (Network Connection)

## Beaconing Findings

| # | Source IP | Source Host | Destination | Protocol | Avg Interval | CV | Jitter % | Connections | Risk |
|---|----------|-------------|-------------|----------|--------------|-----|----------|-------------|------|
| 1 | | | | | | | | | |

## Domain Intelligence

| Domain/IP | WHOIS Age | VirusTotal Score | PassiveDNS | JA3 Match | Assessment |
|-----------|-----------|------------------|------------|-----------|------------|
| | | | | | |

## Endpoint Correlation

| Host | Process | PID | User | Parent Process | File Path | Suspicious |
|------|---------|-----|------|----------------|-----------|------------|
| | | | | | | |

## IOC List
| Type | Value | Confidence | Source |
|------|-------|-----------|--------|
| Domain | | | |
| IP | | | |
| JA3 | | | |
| User-Agent | | | |

## Recommendations
1. **Block**: [Domains/IPs to block at firewall and proxy]
2. **Isolate**: [Endpoints to contain via EDR]
3. **Detect**: [New detection rules to deploy]
4. **Hunt**: [Additional IOCs to sweep for across the environment]
