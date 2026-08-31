---
name: detecting-command-and-control-over-dns
description: Detect command-and-control (C2) traffic tunneled over DNS from tools like Iodine, dnscat2, dns2tcp, and Cobalt Strike DNS beacon, using Shannon entropy analysis of query subdomains, ML-based DGA classification, passive DNS correlation, and Zeek/Suricata signatures. Use when investigating suspected DNS tunneling, classifying DGA domains, detecting DNS beaconing, or building DNS anomaly rules for a SOC/SIEM. Do not use for detecting bulk data exfiltration over DNS queries - use detecting-dns-exfiltration-with-dns-query-analysis.
domain: cybersecurity
subdomain: network-security
tags:
- dns
- c2
- tunneling
- dga
- network-forensics
- threat-detection
version: 1.0.0
author: mukul975
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1095
---

# Detecting Command and Control Over DNS

## When to Use

- Investigating suspected DNS tunneling used for C2 communication or data exfiltration
- Analyzing DNS query logs for signs of encoded payloads in subdomain strings
- Classifying domains as DGA-generated vs. legitimate using statistical or ML methods
- Detecting DNS beaconing patterns (regular intervals, consistent query sizes)
- Hunting for Iodine, dnscat2, dns2tcp, Cobalt Strike DNS, or Sliver DNS traffic
- Monitoring TXT record abuse for command delivery or staged payload download
- Building DNS anomaly detection rules for SOC/SIEM deployment

**Do not use** for general DNS performance monitoring or DNS configuration auditing; use DNS health monitoring tools for those. For HTTP/HTTPS-based C2 detection, use network traffic analysis skills focused on web protocols.

**DISCLAIMER**: DNS tunneling tools referenced in this skill (Iodine, dnscat2, dns2tcp) are dual-use. They have legitimate uses (bypassing captive portals, security research) and malicious uses (C2 channels, exfiltration). Only deploy detection in networks you are authorized to monitor. Testing tunneling tools requires explicit authorization.

## Prerequisites

- DNS query logs from recursive resolver, Zeek/Bro, Suricata, or passive DNS tap
- Python 3.9+ with `numpy`, `scikit-learn`, `pandas`, `tldextract`, and `dnspython`
- Zeek (formerly Bro) with dns.log output or Suricata with DNS EVE JSON logging
- SIEM access (Splunk, Elastic, Microsoft Sentinel) for log correlation
- Passive DNS database access (CIRCL pDNS, Farsight DNSDB, or internal) for enrichment
- Wireshark/tshark for packet-level DNS inspection
- Known-good domain whitelist (Alexa/Tranco top 1M or Majestic Million)

## Workflow

### Step 1: Collect and Parse DNS Query Logs

Ingest DNS traffic from network sensors and parse into analyzable format:

```bash
# Zeek - extract dns.log fields
# Default Zeek dns.log columns:
# ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rtt query
# qclass qclass_name qtype qtype_name rcode rcode_name AA TC RD RA Z
# answers TTLs rejected

# Filter for potentially suspicious record types
cat dns.log | zeek-cut ts id.orig_h query qtype_name answers rcode_name | \
    grep -E "TXT|NULL|CNAME|MX" > suspicious_qtypes.log

# Extract unique queried domains
cat dns.log | zeek-cut query | sort -u > unique_domains.txt

# Suricata EVE JSON - extract DNS events
cat eve.json | jq -r 'select(.event_type=="dns") |
    [.timestamp, .src_ip, .dns.rrname, .dns.rrtype, .dns.rcode] |
    @tsv' > dns_events.tsv

# tshark - extract DNS queries from pcap
tshark -r capture.pcap -T fields \
    -e frame.time -e ip.src -e ip.dst \
    -e dns.qry.name -e dns.qry.type \
    -e dns.resp.type -e dns.txt \
    -Y "dns" > dns_queries.tsv

# Count queries per domain (find high-volume destinations)
cat dns.log | zeek-cut query | \
    awk -F. '{print $(NF-1)"."$NF}' | \
    sort | uniq -c | sort -rn | head -50
```

### Step 2: Shannon Entropy Analysis of DNS Queries

Calculate entropy of subdomain strings to identify encoded/encrypted data:

See [references/detection-scripts.md](references/detection-scripts.md) for the full entropy analysis script (Step 2), TXT payload detection (Step 3), DGA ML classifier (Step 4), and beaconing detection (Step 5).


### Step 3: TXT Record Payload Detection

Identify C2 commands or staged payloads delivered via DNS TXT records:


See [references/detection-scripts.md](references/detection-scripts.md#step-3-txt-record-payload-detection) for the full TXT record payload detection script.


### Step 4: DGA Domain Classification with Machine Learning

Train a classifier to distinguish DGA-generated domains from legitimate ones:


See [references/detection-scripts.md](references/detection-scripts.md#step-4-dga-domain-classification-with-machine-learning) for the full DGA classification and ML training script.


### Step 5: DNS Beaconing Pattern Detection

Identify periodic DNS query patterns indicative of C2 check-ins:


See [references/detection-scripts.md](references/detection-scripts.md#step-5-dns-beaconing-pattern-detection) for the full beaconing detection script.


### Step 6: Integrated DNS C2 Detection Pipeline

Combine all detection methods into a unified analysis:

```
DNS C2 Detection Pipeline Architecture:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ┌────────────────────────────────────────────────────────┐
  │                  DATA SOURCES                          │
  │  Zeek dns.log  |  Suricata EVE  |  Recursive Resolver │
  │  Passive DNS   |  PCAP capture  |  EDR DNS telemetry  │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │              PREPROCESSING                             │
  │  Parse timestamps | Extract subdomains | Normalize     │
  │  FQDN | Resolve base domain | Lookup in whitelist     │
  └───────────────────────┬────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │  ENTROPY     │ │  BEACONING  │ │  DGA        │
  │  ANALYSIS    │ │  DETECTION  │ │  CLASSIFIER │
  │              │ │             │ │             │
  │ Shannon ent. │ │ Interval    │ │ ML model    │
  │ Subdomain    │ │ analysis    │ │ Random      │
  │ length       │ │ Jitter/CV   │ │ Forest or   │
  │ Encoding     │ │ Duration    │ │ Gradient    │
  │ patterns     │ │ Periodicity │ │ Boosting    │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
  │ TXT RECORD   │ │  TOOL       │ │  PASSIVE    │
  │ PAYLOAD      │ │  SIGNATURE  │ │  DNS        │
  │ ANALYSIS     │ │  MATCHING   │ │  ENRICHMENT │
  │              │ │             │ │             │
  │ Base64 decode│ │ Iodine      │ │ First seen  │
  │ PE/ELF detect│ │ dnscat2     │ │ Registrar   │
  │ PS stager    │ │ dns2tcp     │ │ Age check   │
  │ Size anomaly │ │ Cobalt DNS  │ │ Reputation  │
  └───────┬──────┘ └──────┬──────┘ └──────┬──────┘
          │               │               │
  ┌───────▼───────────────▼───────────────▼────────────────┐
  │                CORRELATION ENGINE                       │
  │  Combine scores from all detectors                     │
  │  Weighted scoring: entropy(30%) + beacon(25%) +        │
  │    DGA(20%) + TXT payload(15%) + signature(10%)        │
  │  Threshold: score > 60 = alert, > 40 = investigate     │
  └───────────────────────┬────────────────────────────────┘
                          │
  ┌───────────────────────▼────────────────────────────────┐
  │                ALERTING & RESPONSE                     │
  │  Generate SIEM alert with all evidence                 │
  │  Block domain in DNS firewall / RPZ                    │
  │  Isolate endpoint via EDR                              │
  │  Create incident ticket with IOCs                      │
  └────────────────────────────────────────────────────────┘
```

### Step 7: SIEM Detection Rules

Deploy detection queries in your SIEM platform:

See [references/siem-and-signatures.md](references/siem-and-signatures.md) for the full Splunk SPL, Elastic KQL, and Zeek detection content.


### Step 8: Suricata Rules for Known DNS C2 Tools


See [references/siem-and-signatures.md](references/siem-and-signatures.md#step-8-suricata-rules-for-known-dns-c2-tools) for the full Suricata ruleset.


## Key Concepts

| Term | Definition |
|------|------------|
| **DNS Tunneling** | Technique of encoding data within DNS queries and responses to create a covert communication channel, bypassing firewalls that allow DNS traffic |
| **Shannon Entropy** | Information theory metric measuring randomness in a string; legitimate domains typically have entropy below 3.5, while encoded tunnel data exceeds 3.8-4.5 |
| **Domain Generation Algorithm (DGA)** | Malware technique that algorithmically generates thousands of pseudo-random domain names for C2 rendezvous, making domain-based blocking impractical |
| **DNS Beaconing** | Regular, periodic DNS queries from a compromised host to a C2 domain, identifiable by consistent inter-query intervals and low timing jitter |
| **TXT Record Abuse** | Using DNS TXT records to deliver encoded C2 commands or staged payloads, exploiting the large payload capacity (up to 65535 bytes across multiple strings) |
| **Iodine** | Open-source DNS tunneling tool that tunnels IPv4 traffic through DNS using NULL, TXT, or CNAME records, commonly used to bypass captive portals |
| **dnscat2** | Encrypted C2 tool that creates a command channel over DNS, supporting file transfer, port forwarding, and shell access through DNS queries |
| **Cobalt Strike DNS Beacon** | Commercial C2 framework's DNS communication mode that uses A, AAAA, and TXT records to receive tasks and return results via DNS resolution |
| **Passive DNS (pDNS)** | Database of historical DNS resolution data collected by monitoring DNS traffic; used to identify infrastructure reuse and domain history |
| **Response Policy Zone (RPZ)** | DNS firewall mechanism that allows real-time blocking of malicious domains by injecting override responses at the recursive resolver level |
| **Coefficient of Variation** | Standard deviation divided by mean, expressed as percentage; used to measure beacon jitter -- lower CV indicates more regular (suspicious) timing |
| **NXDOMAIN** | DNS response code indicating the queried domain does not exist; high NXDOMAIN rates from a host suggest DGA activity where most generated domains are unregistered |

## Tools & Systems

- **Zeek (Bro)**: Network security monitor that produces structured dns.log with query/response details for offline analysis
- **Suricata**: IDS/IPS with DNS protocol parsing and signature-based detection of tunneling patterns
- **tshark/Wireshark**: Packet capture and analysis tools for deep DNS protocol inspection
- **tldextract**: Python library for accurate domain/subdomain extraction using the Public Suffix List
- **dnspython**: Python DNS toolkit for programmatic query resolution and record parsing
- **scikit-learn**: ML library used to train DGA classifiers (Random Forest, Gradient Boosting)
- **Farsight DNSDB / CIRCL pDNS**: Passive DNS databases for historical domain resolution lookups
- **DNS Response Policy Zone (RPZ)**: Recursive resolver feature for real-time DNS blocking of identified C2 domains
- **Splunk / Elastic**: SIEM platforms for DNS log aggregation, entropy calculation, and beacon detection queries

## Common Scenarios

### Scenario: Investigating Suspected DNS Tunneling from an Internal Host

**Context**: The SOC receives an alert from the DNS firewall showing a single internal host (10.1.5.42) making 15,000+ DNS queries to the domain `c8a3f1e2.tunnelsvc.example.com` in the past hour. All queries are TXT type with long, random-looking subdomains. Normal DNS volume for this host is ~200 queries/hour.

**Approach**:
1. Extract all DNS queries from 10.1.5.42 for the past 24 hours from Zeek dns.log
2. Run entropy analysis on subdomain strings -- expect Shannon entropy > 4.0 for encoded tunnel data
3. Check query timing intervals for beaconing pattern (likely sub-second for active tunnel)
4. Examine TXT record responses for size anomalies (tunnel tools use maximum-size TXT responses)
5. Compare subdomain patterns against known tool signatures (Iodine, dnscat2, dns2tcp)
6. Query passive DNS for `tunnelsvc.example.com` registration date, nameserver, and historical resolutions
7. If confirmed, add domain to DNS RPZ blocklist and isolate endpoint via EDR
8. Capture full packet trace for forensic analysis of tunnel payload content

**Pitfalls**:
- Blocking the domain before capturing evidence (need packet captures for forensics)
- Assuming all high-entropy DNS is malicious (CDN subdomains like Akamai can have high entropy)
- Not checking for multiple tunnel domains (attacker may have fallback C2 channels)
- Missing the initial compromise vector by focusing only on the DNS channel
- Not checking other hosts for similar patterns (lateral movement may have already occurred)

### Scenario: Building a DGA Detection Model for SOC Deployment

**Context**: The threat intelligence team identified that a botnet family active in the industry uses DGA for C2 domain generation. The SOC needs an automated way to classify DNS queries as potentially DGA-generated and alert on matches.

**Approach**:
1. Collect training data: Tranco/Alexa top 1M for legitimate domains, DGArchive or OSINT feeds for known DGA domains
2. Extract character-level features: entropy, length, digit ratio, consonant sequences, bigram scores
3. Train Random Forest and Gradient Boosting classifiers, evaluate with 5-fold cross-validation
4. Deploy the model as a scoring enrichment in the SIEM (Splunk ML Toolkit or Elastic ML)
5. Set threshold: DGA probability > 0.85 generates alert, > 0.65 generates investigation ticket
6. Create a whitelist of known high-entropy legitimate domains (CDNs, cloud services) to reduce false positives
7. Retrain monthly with new DGA samples from threat intel feeds

**Pitfalls**:
- Training only on one DGA family and missing others (dictionary-based DGAs like Suppobox have low entropy)
- Not whitelisting CDN and cloud service domains that have randomized subdomains
- Setting the threshold too low, overwhelming the SOC with false positives
- Not accounting for punycode/internationalized domain names in feature extraction
- Deploying without a feedback loop for analysts to flag false positives for model retraining

## Output Format

```
DNS C2 DETECTION ANALYSIS REPORT
====================================
Analysis Period: 2026-03-15 00:00 to 2026-03-19 23:59
Data Source:     Zeek dns.log (gateway sensor)
Total Queries:   14,283,501
Unique Domains:  892,041
Hosts Analyzed:  3,847

ENTROPY ANALYSIS
Queries with entropy > 3.5:       2,847 (0.02%)
Queries with subdomain > 40 chars: 1,203 (0.008%)
Suspicious base domains:           12

  [CRITICAL] tunnelsvc.example[.]com
    Queries: 15,247  Source: 10.1.5.42  Avg Entropy: 4.21
    Avg Subdomain Length: 63  Record Types: TXT (98%), A (2%)
    Tool Signature: dnscat2 (hex prefix pattern match)

  [HIGH] update-cdn.malicious[.]net
    Queries: 3,891  Source: 10.1.12.7  Avg Entropy: 3.87
    Avg Subdomain Length: 48  Record Types: A (60%), TXT (40%)
    Tool Signature: Cobalt Strike DNS beacon (interval pattern)

BEACONING DETECTION
Beacon patterns detected:          4

  Score: 85.0  10.1.5.42 -> tunnelsvc.example[.]com
    Interval: 0.5s +/- 0.1s  Jitter: 8.2%  Duration: 18.4h
    Queries: 15,247  Flags: very_low_jitter, persistent, high_volume

  Score: 72.0  10.1.12.7 -> update-cdn.malicious[.]net
    Interval: 60.2s +/- 3.1s  Jitter: 5.1%  Duration: 72.1h
    Queries: 3,891  Flags: very_low_jitter, persistent, common_c2_interval:~60s

DGA CLASSIFICATION
Domains classified:                892,041
DGA predictions (>0.85 conf):      47
DGA predictions (0.65-0.85):       183

  [HIGH] a8f3k2m1x9.com  (DGA prob: 0.97, entropy: 3.92)
  [HIGH] j7t2p5q8w3.net  (DGA prob: 0.95, entropy: 4.01)
  [HIGH] m3x8k1f6y2.org  (DGA prob: 0.94, entropy: 3.88)

TXT RECORD ANALYSIS
Suspicious TXT responses:          8
Base64 payloads detected:          3
PowerShell stager patterns:        1

  [CRITICAL] cmd.staging[.]example.com
    TXT Length: 4,096  Entropy: 5.82
    Finding: Base64-encoded PowerShell stager with IEX pattern

RECOMMENDED ACTIONS
[CRITICAL] Block tunnelsvc.example[.]com and update-cdn.malicious[.]net in DNS RPZ
[CRITICAL] Isolate hosts 10.1.5.42 and 10.1.12.7 for forensic investigation
[HIGH]     Block 47 high-confidence DGA domains in DNS firewall
[HIGH]     Investigate cmd.staging[.]example.com TXT payload staging
[MEDIUM]   Review 183 moderate-confidence DGA domains with threat intel
[MEDIUM]   Deploy Suricata rules for dnscat2 and Cobalt Strike DNS signatures
```
