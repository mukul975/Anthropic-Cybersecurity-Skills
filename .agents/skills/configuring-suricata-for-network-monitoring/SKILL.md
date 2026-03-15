---
name: configuring-suricata-for-network-monitoring
description: >
  Deploys and configures Suricata IDS/IPS with Emerging Threats rulesets, EVE JSON
  logging, and custom rules for real-time network traffic inspection, threat detection,
  and integration with SIEM platforms for centralized security monitoring.
domain: cybersecurity
subdomain: network-security
tags: [network-security, suricata, ids, ips, network-monitoring]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Configuring Suricata for Network Monitoring

## When to Use

- Deploying a high-performance IDS/IPS capable of multi-threaded packet processing for 10+ Gbps network links
- Monitoring network traffic with protocol-aware inspection for HTTP, TLS, DNS, SMB, and other protocols
- Generating structured EVE JSON logs for direct SIEM ingestion without custom parsers
- Running in inline (IPS) mode to actively block malicious traffic at network choke points
- Combining signature-based detection with protocol anomaly detection and file extraction

**Do not use** as a standalone security solution without complementary controls, for encrypted traffic inspection without TLS decryption capabilities, or on systems with insufficient CPU/memory for the expected traffic volume.

## Prerequisites

- Suricata 7.0+ installed from PPA or source (`suricata --build-info`)
- Network interface on a span port, tap, or inline bridge for traffic capture
- AF_PACKET or DPDK support for high-performance packet capture
- Emerging Threats Open or Pro ruleset subscription (or Snort Talos rules via oinkcode)
- suricata-update tool for automated rule management
- Elasticsearch/Kibana or Splunk for log analysis and visualization

## Workflow

### Step 1: Install Suricata and Dependencies

```bash
# Install from PPA (Ubuntu/Debian)
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata suricata-update jq

# Verify installation
suricata --build-info | grep -E "Version|AF_PACKET|NFQueue"

# Or install from source for latest features
sudo apt install -y libpcre2-dev build-essential autoconf automake libtool \
  libpcap-dev libnet1-dev libyaml-dev libjansson-dev libcap-ng-dev \
  libmagic-dev libnetfilter-queue-dev libhiredis-dev rustc cargo cbindgen
git clone https://github.com/OISF/suricata.git
cd suricata && git clone https://github.com/OISF/libhtp.git -b 0.5.x
./autogen.sh && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
  --enable-nfqueue --enable-af-packet
make -j$(nproc) && sudo make install install-conf
```

### Step 2: Configure Network Interfaces

```bash
# Disable NIC offloading features
sudo ethtool -K eth1 gro off lro off tso off gso off rx off tx off sg off

# Set interface to promiscuous mode
sudo ip link set eth1 promisc on

# For high-performance deployments, configure AF_PACKET with multiple threads
# Edit /etc/suricata/suricata.yaml
```

### Step 3: Configure suricata.yaml

```yaml
# /etc/suricata/suricata.yaml (key sections)

# Network variables
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"

# Default rule path
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# AF_PACKET configuration for high performance
af-packet:
  - interface: eth1
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    ring-size: 200000
    buffer-size: 262144

# EVE JSON logging (primary output format)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      pcap-file: false
      community-id: true
      types:
        - alert:
            tagged-packets: yes
            payload: yes
            payload-printable: yes
            http-body: yes
            http-body-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
            force-hash: [md5, sha256]
        - smtp:
            extended: yes
        - flow
        - netflow
        - anomaly:
            enabled: yes
        - stats:
            totals: yes
            threads: yes

  # PCAP logging for captured packets that trigger alerts
  - pcap-log:
      enabled: yes
      filename: alert-%n.pcap
      limit: 100mb
      max-files: 50
      mode: normal
      use-stream-depth: no
      honor-pass-rules: no

# Stream engine settings
stream:
  memcap: 512mb
  checksum-validation: no
  reassembly:
    memcap: 1gb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

# Detection engine
detect:
  profile: high
  custom-values:
    toclient-groups: 200
    toserver-groups: 200
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# Protocol detection and parsing
app-layer:
  protocols:
    http:
      enabled: yes
      memcap: 64mb
    tls:
      enabled: yes
      detection-ports:
        dp: 443, 8443
      ja3-fingerprints: yes
    dns:
      enabled: yes
      tcp:
        enabled: yes
      udp:
        enabled: yes
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
    ssh:
      enabled: yes
      hassh: yes
```

### Step 4: Download and Manage Rulesets

```bash
# Update Suricata rules using suricata-update
sudo suricata-update

# Enable additional rule sources
sudo suricata-update list-sources
sudo suricata-update enable-source et/open
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source ptresearch/attackdetection

# Update with all enabled sources
sudo suricata-update

# Check rule statistics
sudo suricata-update list-sources --enabled
wc -l /var/lib/suricata/rules/suricata.rules

# Disable noisy rules
sudo tee /etc/suricata/disable.conf << 'EOF'
# Disable overly broad rules
2100498
2013028
2210000-2210050
group:emerging-policy.rules
EOF

# Create custom local rules
sudo tee /etc/suricata/rules/local.rules << 'EOF'
# Detect reverse shell connections
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"LOCAL Reverse Shell Port 4444"; flow:established,to_server; content:"|2f 62 69 6e 2f|"; sid:9000001; rev:1; classtype:trojan-activity; priority:1;)

# Detect DNS tunneling by query length
alert dns $HOME_NET any -> any any (msg:"LOCAL DNS Tunneling Long Query"; dns.query; content:"."; offset:50; sid:9000002; rev:1; classtype:policy-violation; priority:2;)

# Detect TLS to suspicious JA3 hash (Cobalt Strike default)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Cobalt Strike JA3 Hash"; ja3.hash; content:"72a589da586844d7f0818ce684948eea"; sid:9000003; rev:1; classtype:trojan-activity; priority:1;)

# Detect SSH brute force
alert ssh $EXTERNAL_NET any -> $HOME_NET 22 (msg:"LOCAL SSH Brute Force Attempt"; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; sid:9000004; rev:1; classtype:attempted-admin; priority:2;)

# Detect data exfiltration via HTTP POST (large uploads)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Large HTTP POST Upload"; flow:to_server,established; http.method; content:"POST"; http.content_len; content:">"; byte_test:8,>,10000000,0,string; sid:9000005; rev:1; classtype:policy-violation; priority:2;)
EOF

# Add local rules to configuration
echo "  - local.rules" | sudo tee -a /etc/suricata/suricata.yaml
```

### Step 5: Deploy and Validate

```bash
# Validate configuration
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Run Suricata in IDS mode
sudo suricata -c /etc/suricata/suricata.yaml --af-packet=eth1 -D

# Or run in IPS mode (inline with NFQueue)
# First configure iptables to send traffic to NFQueue
# sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
# sudo suricata -c /etc/suricata/suricata.yaml -q 0 -D

# Create systemd service
sudo tee /etc/systemd/system/suricata.service << 'EOF'
[Unit]
Description=Suricata IDS/IPS
After=network.target
Requires=network.target

[Service]
Type=simple
ExecStartPre=/usr/bin/suricata -T -c /etc/suricata/suricata.yaml
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet=eth1 --pidfile /var/run/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now suricata

# Test with a known signature
curl http://testmynids.org/uid/index.html
# Should trigger ET GPL rule for uid.

# Verify alerts are generated
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Step 6: Integrate with SIEM and Monitor

```bash
# Parse EVE JSON with jq for quick analysis
# Top 10 alerts
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn | head -10

# Extract IOCs from alerts
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | [.timestamp, .src_ip, .dest_ip, .alert.signature, .alert.severity] | @csv' > alert_summary.csv

# JA3 fingerprint analysis
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="tls") | [.src_ip, .tls.ja3.hash, .tls.sni] | @csv' | sort | uniq -c | sort -rn

# DNS query analysis
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="dns" and .dns.type=="query") | [.src_ip, .dns.rrname, .dns.rrtype] | @csv' | sort | uniq -c | sort -rn | head -20

# Configure Filebeat for Elastic integration
sudo tee /etc/filebeat/modules.d/suricata.yml << 'EOF'
- module: suricata
  eve:
    enabled: true
    var.paths: ["/var/log/suricata/eve.json"]
EOF

sudo filebeat modules enable suricata
sudo systemctl restart filebeat

# Monitor Suricata performance
cat /var/log/suricata/eve.json | jq 'select(.event_type=="stats") | .stats.capture' | tail -1
# Check for packet drops: kernel_drops should be 0
```

## Key Concepts

| Term | Definition |
|------|------------|
| **EVE JSON** | Suricata's primary logging format producing structured JSON events for alerts, protocol metadata, flow records, and statistics |
| **AF_PACKET** | Linux kernel packet capture mechanism used by Suricata for high-performance traffic capture with kernel-bypass capabilities |
| **JA3/JA3S** | TLS fingerprinting method that creates hash values from TLS Client Hello and Server Hello parameters for identifying applications and malware |
| **HASSH** | SSH fingerprinting method similar to JA3 that creates hashes from SSH key exchange parameters to identify SSH client and server implementations |
| **Community ID** | Standardized flow identifier hash that enables correlation of the same network flow across different monitoring tools (Suricata, Zeek, Wireshark) |
| **suricata-update** | Official rule management tool that downloads, merges, and manages multiple rulesets with enable/disable controls |

## Tools & Systems

- **Suricata 7.0+**: Open-source multi-threaded IDS/IPS/NSM engine with protocol detection, file extraction, and JA3/HASSH fingerprinting
- **suricata-update**: Ruleset management tool supporting ET Open, ET Pro, Snort rules, and custom rule sources
- **Elastic Stack (ELK)**: Log aggregation and visualization platform with native Suricata module in Filebeat for dashboards and alerting
- **Scirius**: Web-based Suricata rule management interface for editing, enabling/disabling, and monitoring rule performance
- **Evebox**: Lightweight event viewer for Suricata EVE JSON logs with alert management and escalation capabilities

## Common Scenarios

### Scenario: Deploying Suricata IDS on a 10 Gbps Enterprise Network Perimeter

**Context**: A technology company needs to deploy IDS at their internet egress point handling 10 Gbps of traffic. They require protocol-level metadata logging for threat hunting, signature-based alerting for known threats, and JA3 fingerprinting for detecting malware C2 communications. Alerts must feed into their Elastic SIEM.

**Approach**:
1. Deploy Suricata on a server with 16 CPU cores, 64 GB RAM, and dual 10G NICs using AF_PACKET with 14 worker threads
2. Enable ET Open and ptresearch/attackdetection rulesets via suricata-update, totaling approximately 35,000 active rules
3. Configure EVE JSON logging with community-id, extended HTTP/TLS/DNS metadata, and file hashing (MD5 + SHA256)
4. Enable JA3 and HASSH fingerprinting for TLS and SSH traffic profiling
5. Write custom rules for organization-specific threats: known bad JA3 hashes, DNS queries to DGA domains, large data uploads to uncommon destinations
6. Integrate with Elastic via Filebeat's Suricata module, deploying pre-built Kibana dashboards for real-time visibility
7. Tune rules over a 2-week baseline period, disabling false-positive generators and adjusting thresholds

**Pitfalls**:
- Not allocating sufficient CPU threads, causing packet drops at peak traffic volumes
- Enabling all available rules without tuning, overwhelming analysts with false positives
- Forgetting to disable NIC offloading, resulting in incorrect checksums and missed detections
- Not enabling community-id, making it difficult to correlate Suricata events with Zeek or other tools

## Output Format

```
## Suricata IDS Deployment Report

**Sensor**: suricata-gw-01 (10.10.1.251)
**Interface**: eth1 (span from border router)
**Configuration**: /etc/suricata/suricata.yaml
**Worker Threads**: 14 AF_PACKET threads
**Active Rules**: 35,247 (ET Open + Custom)

### Performance Metrics (24-hour)

| Metric | Value |
|--------|-------|
| Packets Processed | 847,293,421 |
| Kernel Drops | 0 (0.000%) |
| Alerts Generated | 1,247 |
| Unique Signatures Fired | 89 |
| JA3 Fingerprints Observed | 342 unique |
| Files Extracted | 2,847 |

### Top 10 Alert Signatures

| Count | SID | Signature | Severity |
|-------|-----|-----------|----------|
| 312 | 2024897 | ET POLICY curl User-Agent Outbound | 3 |
| 189 | 9000003 | LOCAL Cobalt Strike JA3 Hash | 1 |
| 145 | 2028765 | ET SCAN Nmap SYN Scan | 2 |
| 98 | 9000002 | LOCAL DNS Tunneling Long Query | 2 |

### Critical Alerts Requiring Immediate Triage
1. SID 9000003: Cobalt Strike JA3 from 10.10.5.12 to 203.0.113.50 (189 alerts)
2. SID 9000002: DNS tunneling from 10.10.3.45 to suspect-domain.xyz (98 alerts)
```
