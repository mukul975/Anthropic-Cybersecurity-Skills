---
name: implementing-network-intrusion-prevention-with-suricata
description: Deploy and configure Suricata as a network intrusion prevention system with custom rules, Emerging Threats rulesets, and inline traffic inspection for real-time threat blocking.
domain: cybersecurity
subdomain: network-security
tags: [suricata, ips, ids, intrusion-prevention, network-security, emerging-threats, rule-management, nfqueue, inline-mode]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing Network Intrusion Prevention with Suricata

## Overview

Suricata is a high-performance, open-source network threat detection engine developed by the Open Information Security Foundation (OISF). It functions as an IDS (Intrusion Detection System), IPS (Intrusion Prevention System), and network security monitoring tool. Suricata performs deep packet inspection using extensive rule sets, protocol analysis, and file extraction capabilities. In IPS mode, Suricata inspects packets inline and can actively block malicious traffic. This skill covers deploying Suricata in IPS mode, configuring rulesets, writing custom rules, performance tuning, and integration with logging infrastructure.

## Prerequisites

- Linux server (Ubuntu 22.04+ or CentOS 8+) with 4+ CPU cores and 8GB+ RAM
- Suricata 7.0+ installed
- Network position for inline deployment (bridge mode or NFQUEUE)
- Emerging Threats Open or ET Pro ruleset subscription
- Suricata-update tool for rule management
- Logging infrastructure (ELK Stack, Splunk, or Wazuh)

## Core Concepts

### Operating Modes

| Mode | Function | Network Position |
|------|----------|-----------------|
| IDS (AF_PACKET) | Passive monitoring, alert-only | TAP/SPAN mirror |
| IPS (NFQUEUE) | Inline blocking via netfilter | In traffic path |
| IPS (AF_PACKET) | Inline blocking via AF_PACKET | Bridge between interfaces |
| Offline (PCAP) | Analyze captured traffic files | N/A |

### Rule Anatomy

Suricata rules follow a structured format:

```
action protocol src_ip src_port -> dst_ip dst_port (rule_options;)
```

- **Action**: `alert`, `pass`, `drop`, `reject`, `rejectsrc`, `rejectdst`, `rejectboth`
- **Protocol**: `tcp`, `udp`, `icmp`, `ip`, `http`, `tls`, `dns`, `smtp`, `ftp`
- **Direction**: `->` (unidirectional), `<>` (bidirectional)

### Rule Categories

- **Emerging Threats Open** - Community-maintained, free ruleset with broad coverage
- **ET Pro** - Commercial ruleset from Proofpoint with enhanced coverage
- **Suricata Traffic ID** - Application identification rules
- **Custom Rules** - Organization-specific detections

## Implementation Steps

### Step 1: Install Suricata

```bash
# Add Suricata PPA (Ubuntu)
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata suricata-update

# Verify installation
suricata --build-info
suricata -V
```

### Step 2: Configure Suricata for IPS Mode

Edit `/etc/suricata/suricata.yaml`:

```yaml
%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    DNS_SERVERS: "[10.0.1.10/32,10.0.1.11/32]"
    SMTP_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"
    DNS_PORTS: "53"

# IPS mode with NFQUEUE
nfq:
  mode: accept
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  fail-open: yes

# Threading configuration
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [0]
    - receive-cpu-set:
        cpu: [1,2]
    - worker-cpu-set:
        cpu: [3,4,5,6,7]
        mode: exclusive

# Detection engine
detect-engine:
  - profile: high
  - custom-values:
      toclient-groups: 50
      toserver-groups: 50
  - sgh-mpm-context: auto
  - inspection-recursion-limit: 3000

# Stream engine
stream:
  memcap: 512mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 1gb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

# Logging configuration
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            tagged-packets: yes
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
        - flow
        - netflow
        - stats:
            totals: yes
            threads: no
            deltas: yes

  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log

  - stats:
      enabled: yes
      filename: /var/log/suricata/stats.log
      interval: 30

# Rule files
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
```

### Step 3: Configure NFQUEUE for Inline IPS

Set up iptables to redirect traffic through Suricata:

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect FORWARD chain to NFQUEUE
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

# For multi-queue (better performance)
sudo iptables -I FORWARD -j NFQUEUE --queue-balance 0:3 --queue-bypass

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4
```

Alternative: AF_PACKET inline mode between two interfaces:

```yaml
# In suricata.yaml
af-packet:
  - interface: eth0
    cluster-id: 98
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    copy-mode: ips
    copy-iface: eth1
  - interface: eth1
    cluster-id: 97
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    copy-mode: ips
    copy-iface: eth0
```

### Step 4: Manage Rules with Suricata-Update

```bash
# Update rules from default sources (ET Open)
sudo suricata-update

# List available rule sources
sudo suricata-update list-sources

# Enable ET Pro (requires license key)
sudo suricata-update enable-source et/pro secret-code=YOUR_OINKCODE

# Enable additional sources
sudo suricata-update enable-source oisf/trafficid
sudo suricata-update enable-source ptresearch/attackdetection
sudo suricata-update enable-source sslbl/ssl-fp-blacklist

# Disable specific rules that generate false positives
echo "2100498" >> /etc/suricata/disable.conf
echo "group:emerging-policy.rules" >> /etc/suricata/disable.conf

# Modify rule actions (change alert to drop)
echo 're:ET MALWARE' >> /etc/suricata/modify.conf

# Apply updates
sudo suricata-update --reload-command="suricatasc -c reload-rules"
```

### Step 5: Write Custom Rules

Create `/var/lib/suricata/rules/local.rules`:

```
# Detect potential reverse shell over TCP
drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Potential Reverse Shell - /bin/bash in payload"; flow:to_server,established; content:"/bin/bash"; content:"-i"; within:20; classtype:trojan-activity; sid:1000001; rev:1;)

# Block known malicious user agent
drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Malicious User-Agent - Cobalt Strike"; http.user_agent; content:"Mozilla/5.0 (compatible|3b| MSIE 9.0|3b| Windows NT 6.1|3b| WOW64|3b| Trident/5.0)"; classtype:trojan-activity; sid:1000002; rev:1;)

# Detect DNS query for known DGA domain pattern
alert dns $HOME_NET any -> any 53 (msg:"LOCAL Suspicious DGA Domain Query"; dns.query; content:".top"; pcre:"/^[a-z0-9]{12,30}\.(top|xyz|club|online|site)$/"; classtype:bad-unknown; sid:1000003; rev:1;)

# Detect large DNS TXT response (potential C2)
alert dns any 53 -> $HOME_NET any (msg:"LOCAL Large DNS TXT Response - Potential C2"; dns.opcode:0; content:"|00 10|"; byte_test:2,>,500,0,relative; classtype:bad-unknown; sid:1000004; rev:1;)

# Block outbound traffic to Tor exit nodes
drop tcp $HOME_NET any -> [100.2.18.10,104.244.76.13,109.70.100.1] any (msg:"LOCAL Outbound Connection to Known Tor Exit Node"; classtype:policy-violation; sid:1000005; rev:1;)

# Detect SMB lateral movement attempts
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL Internal SMB Connection - Possible Lateral Movement"; flow:to_server,established; content:"|ff|SMB"; offset:4; depth:4; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000006; rev:1;)

# Detect PowerShell download cradle
drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL PowerShell Download Cradle Detected"; http.user_agent; content:"PowerShell"; nocase; http.method; content:"GET"; classtype:trojan-activity; sid:1000007; rev:1;)

# Detect ICMP tunneling (large ICMP packets)
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Oversized ICMP Packet - Possible Tunneling"; dsize:>800; threshold:type both,track by_src,count 10,seconds 60; classtype:bad-unknown; sid:1000008; rev:1;)
```

### Step 6: Start Suricata in IPS Mode

```bash
# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Start in NFQUEUE IPS mode
sudo suricata -c /etc/suricata/suricata.yaml -q 0

# Start with AF_PACKET inline mode
sudo suricata -c /etc/suricata/suricata.yaml --af-packet

# Start as systemd service
sudo systemctl enable suricata
sudo systemctl start suricata

# Monitor performance stats
tail -f /var/log/suricata/stats.log

# Reload rules without restart
sudo suricatasc -c reload-rules
```

## Monitoring and Tuning

### Performance Metrics

```bash
# Check kernel drops
sudo suricatasc -c dump-counters | grep -E "capture.kernel_drops|decoder.pkts"

# Monitor EVE JSON alerts
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# Check rule loading
grep -c "rules loaded" /var/log/suricata/suricata.log

# Memory usage
sudo suricatasc -c dump-counters | grep memuse
```

### Tuning for False Positives

```bash
# Identify noisy rules
cat /var/log/suricata/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature_id' | sort | uniq -c | sort -rn | head -20

# Suppress specific rules per source
echo "suppress gen_id 1, sig_id 2100498, track by_src, ip 10.0.5.0/24" >> /etc/suricata/threshold.config

# Rate-limit alerts
echo "rate_filter gen_id 1, sig_id 2100366, track by_src, count 10, seconds 60, new_action alert, timeout 300" >> /etc/suricata/threshold.config
```

## Best Practices

- **Start in IDS Mode** - Deploy in IDS (alert-only) mode first, tune for 2-4 weeks, then switch to IPS
- **Fail-Open** - Configure fail-open mode so network traffic continues if Suricata crashes
- **Rule Tuning** - Use threshold and suppress directives to reduce false positives before enabling drop actions
- **CPU Affinity** - Pin Suricata worker threads to dedicated CPU cores for consistent performance
- **Bypass for Trusted Traffic** - Use `pass` rules for known-good traffic to reduce processing load
- **Regular Updates** - Run `suricata-update` daily via cron to keep signatures current
- **Monitor Drops** - Track kernel packet drops and increase ring buffer size if needed

## References

- [Suricata Documentation](https://docs.suricata.io/en/latest/)
- [Suricata Rules Format](https://docs.suricata.io/en/latest/rules/index.html)
- [Emerging Threats Rulesets](https://rules.emergingthreats.net/)
- [OISF Suricata GitHub](https://github.com/OISF/suricata)
- [Suricata-Update Documentation](https://suricata-update.readthedocs.io/)
