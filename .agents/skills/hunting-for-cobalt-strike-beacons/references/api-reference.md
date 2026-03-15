# API Reference: Hunting for Cobalt Strike Beacons

## Cobalt Strike Default TLS Indicators

| Indicator | Value | Detection Confidence |
|-----------|-------|---------------------|
| Default cert serial | `8BB00EE` | 95% (unmodified teamserver) |
| Default cert issuer | `Major Cobalt Strike` | 95% |
| JA3S hash (Java TLS) | `ae4edc6faf64d08308082ad26be60767` | 80% |
| JA3S hash (alt) | `a0e9f5d64349fb13191bc781f81f42e1` | 80% |
| JARM fingerprint | `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | 90% |

## Zeek Log Fields for Detection

### ssl.log Key Fields

| Field Index | Name | Use |
|-------------|------|-----|
| 0 | ts | Connection timestamp |
| 2 | id.orig_h | Source IP |
| 4 | id.resp_h | Destination IP (C2 server) |
| 5 | id.resp_p | Destination port |
| 20 | cert_chain_fps | Certificate serial number |
| 21 | ja3s | JA3S server fingerprint hash |

### conn.log Beacon Timing Fields

| Field Index | Name | Use |
|-------------|------|-----|
| 0 | ts | Connection epoch timestamp |
| 2 | id.orig_h | Beaconing host |
| 4 | id.resp_h | C2 destination |
| 5 | id.resp_p | C2 port |
| 8 | duration | Session length |
| 9 | orig_bytes | Bytes sent (check size) |
| 10 | resp_bytes | Bytes received (check size) |

## RITA Beacon Analysis

```bash
# Import Zeek logs into RITA
rita import /opt/zeek/logs/current rita_dataset

# Show beaconing connections ranked by score
rita show-beacons rita_dataset --human-readable

# Show long connections (persistent C2)
rita show-long-connections rita_dataset

# Export beacon results as CSV
rita show-beacons rita_dataset -H > beacons.csv

# Show DNS tunneling (alternate C2 channel)
rita show-exploded-dns rita_dataset
```

## Suricata Detection Rules

```yaml
# Detect default Cobalt Strike TLS certificate
alert tls any any -> any any (msg:"ET MALWARE Cobalt Strike Default Certificate"; \
  tls.cert_serial; content:"8BB00EE"; sid:2029560; rev:3;)

# Detect known Cobalt Strike JA3S
alert tls any any -> any any (msg:"ET MALWARE Cobalt Strike JA3S"; \
  ja3s.hash; content:"ae4edc6faf64d08308082ad26be60767"; sid:2029561; rev:2;)

# Detect Cobalt Strike default HTTP beacon URI
alert http any any -> any any (msg:"ET MALWARE CobaltStrike Beacon URI"; \
  content:"GET"; http_method; pcre:"/^\/[a-zA-Z]{4}$/U"; sid:2029562; rev:1;)

# Detect Cobalt Strike named pipe (SMB beacon)
alert smb any any -> any any (msg:"ET MALWARE CobaltStrike Named Pipe"; \
  content:"|MSRPC|"; content:"\\\\pipe\\\\"; content:"MSSE-"; sid:2029563; rev:1;)
```

## Malleable C2 Profile HTTP Indicators

| Pattern | URI Regex | Context |
|---------|-----------|---------|
| Default GET | `^/[a-zA-Z]{4}$` | 4-char alpha URI (e.g., /aGth) |
| submit.php | `^/submit\.php\?id=\d+$` | POST callback with numeric ID |
| Pixel tracking | `^/pixel\.(gif\|png)$` | Fake tracking pixel |
| UTM beacon | `^/__utm\.gif$` | Mimics Google Analytics |
| RSS feed | `^/updates\.(rss\|json)$` | Fake feed endpoint |
| JS beacon | `^/visit\.js$` | Fake JavaScript resource |

## Default User-Agent Strings

```
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)
Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)
```

## Beacon Timing Analysis Formula

```python
# Jitter percentage calculation
intervals = [t[i+1] - t[i] for i in range(len(t) - 1)]
avg = sum(intervals) / len(intervals)
std = sqrt(sum((x - avg)**2 for x in intervals) / len(intervals))
jitter_pct = (std / avg) * 100

# Beacon score (0-100, higher = more likely beacon)
beacon_score = max(0, 1 - (jitter_pct / 100)) * 100
# Score >= 85 = critical, >= 60 = high suspicion
```

## JARM Scanner CLI

```bash
# Scan single host for JARM fingerprint
python3 jarm.py -p 443 suspicious-host.example.com

# Known Cobalt Strike JARM
# 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1

# Compare against threat intel JARM database
python3 jarm.py -p 8443 10.0.0.50 | grep -f cs_jarm_list.txt
```

## MITRE ATT&CK Mapping

| Technique | ID | Beacon Indicator |
|-----------|----|-----------------|
| Application Layer Protocol | T1071.001 | HTTP/HTTPS beaconing pattern |
| Encrypted Channel | T1573.002 | Default TLS cert / JA3S match |
| Non-Standard Port | T1571 | HTTPS on 8080, 8443, 444 |
| Ingress Tool Transfer | T1105 | Large resp_bytes in beacon |
| Proxy | T1090 | Redirector infrastructure |

### References

- JARM Scanner: https://github.com/salesforce/jarm
- RITA: https://github.com/activecm/rita
- JA3/JA3S: https://github.com/salesforce/ja3
- Cobalt Strike Detection: https://thedfirreport.com
- MITRE T1071.001: https://attack.mitre.org/techniques/T1071/001/
