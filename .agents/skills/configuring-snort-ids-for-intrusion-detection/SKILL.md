---
name: configuring-snort-ids-for-intrusion-detection
description: >
  Installs, configures, and tunes Snort 3 intrusion detection system to monitor
  network traffic for malicious activity using custom and community rulesets,
  preprocessors, and alert output plugins on authorized network segments.
domain: cybersecurity
subdomain: network-security
tags: [network-security, snort, ids, intrusion-detection, rule-writing]
version: "1.0"
author: mahipal
license: Apache-2.0
---
# Configuring Snort IDS for Intrusion Detection

## When to Use

- Deploying a network-based intrusion detection system to monitor traffic at key network boundaries
- Writing custom Snort rules to detect organization-specific threats, attack patterns, or policy violations
- Tuning existing rulesets to reduce false positives while maintaining detection coverage
- Integrating Snort alerts with SIEM platforms for centralized security monitoring
- Validating network security controls by generating test traffic and confirming detection

**Do not use** as a replacement for endpoint detection, for monitoring encrypted traffic without TLS inspection, or as the sole security control without complementary defenses.

## Prerequisites

- Snort 3.x installed from source or package manager (`snort --version` to verify)
- Network interface configured for promiscuous mode on a span port or network tap
- DAQ (Data Acquisition Library) installed for packet capture integration
- Registered Snort account for downloading Snort Subscriber (paid) or Community rulesets from snort.org
- PulledPork 3 or similar rule management tool for automated ruleset updates
- Sufficient CPU and memory for inline traffic inspection at line rate

## Workflow

### Step 1: Install and Verify Snort 3

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install -y build-essential libpcap-dev libpcre3-dev libnet1-dev \
  zlib1g-dev luajit hwloc libdumbnet-dev bison flex libcmocka-dev \
  libnetfilter-queue-dev libmnl-dev autotools-dev libluajit-5.1-dev \
  pkg-config cmake libhwloc-dev liblzma-dev openssl libssl-dev cpputest \
  libsqlite3-dev uuid-dev

# Install DAQ from source
git clone https://github.com/snort3/libdaq.git
cd libdaq && ./bootstrap && ./configure && make && sudo make install

# Install Snort 3
git clone https://github.com/snort3/snort3.git
cd snort3 && ./configure_cmake.sh --prefix=/usr/local
cd build && make -j$(nproc) && sudo make install
sudo ldconfig

# Verify installation
snort -V
```

### Step 2: Configure Network Interfaces

```bash
# Disable offloading features that interfere with packet inspection
sudo ethtool -K eth1 gro off lro off tso off gso off rx off tx off

# Enable promiscuous mode
sudo ip link set eth1 promisc on

# Create systemd service for persistent interface configuration
sudo tee /etc/systemd/system/snort-iface.service << 'EOF'
[Unit]
Description=Configure Snort capture interface
Before=snort.service

[Service]
Type=oneshot
ExecStart=/sbin/ethtool -K eth1 gro off lro off tso off gso off rx off tx off
ExecStart=/sbin/ip link set eth1 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable snort-iface.service
```

### Step 3: Configure Snort 3 with Lua Configuration

```bash
# Create Snort directory structure
sudo mkdir -p /usr/local/etc/snort/{rules,builtin_rules,lists,appid}
sudo mkdir -p /var/log/snort

# Edit the main Snort configuration
sudo tee /usr/local/etc/snort/snort.lua << 'LUAEOF'
-- Snort 3 Configuration

-- Network variables
HOME_NET = '10.10.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

-- Path variables
RULE_PATH = '/usr/local/etc/snort/rules'
BUILTIN_RULE_PATH = '/usr/local/etc/snort/builtin_rules'

-- Configure DAQ
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = { { name = 'afpacket', variables = { 'buffer_size_mb=256' } } }
}

-- Decoder configuration
normalizer = { tcp = { ips = true } }

-- Stream inspection
stream = { }
stream_tcp = { policy = 'linux', session_timeout = 180 }
stream_udp = { session_timeout = 30 }
stream_icmp = { }

-- HTTP inspection
http_inspect = { }

-- DNS inspection
dns = { }

-- SSL/TLS inspection
ssl = { }

-- SMB inspection
dce_smb = { }

-- File identification and processing
file_id = { rules_file = '/usr/local/etc/snort/file_magic.rules' }

-- Port scan detection
port_scan = {
    protos = 'all',
    scan_types = 'all',
    memcap = 10000000
}

-- Reputation-based filtering
-- reputation = {
--     blacklist = RULE_PATH .. '/blocklist.rules'
-- }

-- IPS rules
ips = {
    enable_builtin_rules = true,
    include = RULE_PATH .. '/snort3-community.rules',
    variables = {
        nets = { HOME_NET = HOME_NET, EXTERNAL_NET = EXTERNAL_NET },
        ports = {
            HTTP_PORTS = '80 8080 8443',
            SSH_PORTS = '22',
            DNS_PORTS = '53'
        }
    }
}

-- Alert output
alert_fast = {
    file = true,
    packet = false,
    limit = 100
}

-- Unified2 output for Barnyard2/SIEM integration
-- alert_unified2 = { limit = 128 }

-- JSON alert output
alert_json = {
    file = true,
    limit = 100,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_addr src_port dst_addr dst_port service rule action'
}

-- Syslog output
-- alert_syslog = { level = 'info', facility = 'local1' }

LUAEOF
```

### Step 4: Download and Configure Rulesets

```bash
# Download Snort 3 Community Rules
wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
tar xzf snort3-community-rules.tar.gz
sudo cp snort3-community-rules/snort3-community.rules /usr/local/etc/snort/rules/

# Install PulledPork 3 for automated rule management
git clone https://github.com/shirkdog/pulledpork3.git
cd pulledpork3
sudo python3 setup.py install

# Configure PulledPork
sudo tee /usr/local/etc/pulledpork3/pulledpork.conf << 'EOF'
registered_ruleset = true
oinkcode = <YOUR_OINK_CODE>
snort_path = /usr/local/bin/snort
local_rules = /usr/local/etc/snort/rules/local.rules
sorule_path = /usr/local/etc/snort/so_rules/
snort_version = 3.0.0.0
blocklist_path = /usr/local/etc/snort/lists/
pid_path = /var/run/snort.pid
ips_policy = balanced
EOF

# Run PulledPork to fetch and process rules
sudo pulledpork3 -c /usr/local/etc/pulledpork3/pulledpork.conf
```

### Step 5: Write Custom Detection Rules

```bash
# Create local rules file
sudo tee /usr/local/etc/snort/rules/local.rules << 'EOF'
# Detect reverse shell on common ports
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (
    msg:"LOCAL Possible Reverse Shell on port 4444";
    flow:established,to_server;
    content:"/bin/sh"; nocase;
    sid:1000001; rev:1;
    classtype:trojan-activity;
    priority:1;
)

# Detect Mimikatz execution indicators over SMB
alert tcp any any -> $HOME_NET 445 (
    msg:"LOCAL Mimikatz Lateral Movement via SMB";
    flow:established,to_server;
    content:"|FF|SMB";
    content:"mimikatz"; nocase; distance:0;
    sid:1000002; rev:1;
    classtype:trojan-activity;
    priority:1;
)

# Detect DNS tunneling (high-entropy long subdomain queries)
alert udp $HOME_NET any -> any 53 (
    msg:"LOCAL Possible DNS Tunneling - Long Query Name";
    content:"|01 00|"; offset:2; depth:2;
    byte_test:1,>,50,12;
    sid:1000003; rev:1;
    classtype:policy-violation;
    priority:2;
)

# Detect cleartext password transmission via FTP
alert tcp $HOME_NET any -> any 21 (
    msg:"LOCAL FTP Cleartext Password Detected";
    flow:established,to_server;
    content:"PASS "; depth:5;
    sid:1000004; rev:1;
    classtype:policy-violation;
    priority:2;
)

# Detect potential port scan (SYN flood pattern)
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"LOCAL Possible Port Scan SYN Flood";
    flow:stateless;
    flags:S,12;
    threshold:type both, track by_src, count 100, seconds 10;
    sid:1000005; rev:1;
    classtype:attempted-recon;
    priority:2;
)
EOF
```

### Step 6: Validate Configuration and Run

```bash
# Validate configuration
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -T

# Run Snort in IDS mode on the capture interface
sudo snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq \
  -i eth1 -l /var/log/snort -D

# Test rules against a PCAP file
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq \
  -r test_traffic.pcap -l /var/log/snort/test/ -A fast

# Create systemd service for production deployment
sudo tee /etc/systemd/system/snort.service << 'EOF'
[Unit]
Description=Snort 3 IDS
After=network.target snort-iface.service

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i eth1 -l /var/log/snort -D
ExecReload=/bin/kill -SIGHUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now snort.service
```

### Step 7: Monitor Alerts and Tune Rules

```bash
# View real-time alerts
tail -f /var/log/snort/alert_fast.txt

# Parse JSON alerts for analysis
cat /var/log/snort/alert_json.txt | python3 -m json.tool

# Identify top triggered rules for tuning
grep -oP 'sid:\d+' /var/log/snort/alert_fast.txt | sort | uniq -c | sort -rn | head -20

# Suppress noisy false-positive rules
sudo tee -a /usr/local/etc/snort/rules/suppress.rules << 'EOF'
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.10.1.100
suppress gen_id 1, sig_id 2100366, track by_dst, ip 10.10.5.0/24
EOF

# Verify rule count and performance
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -T 2>&1 | grep -i "rules loaded"
```

## Key Concepts

| Term | Definition |
|------|------------|
| **IDS vs IPS** | IDS passively monitors traffic and generates alerts; IPS sits inline and can actively block or drop malicious packets in real time |
| **Snort Rule** | Detection signature with header (action, protocol, src/dst, ports) and options (content matches, flow direction, metadata) that triggers on matching traffic |
| **Preprocessor** | Snort component that normalizes and reassembles protocol-specific traffic before rule inspection, handling fragmentation, stream reassembly, and protocol anomalies |
| **DAQ (Data Acquisition)** | Abstraction layer in Snort 3 that interfaces with packet capture mechanisms (AF_PACKET, PCAP, NFQ) for receiving network data |
| **Oink Code** | Personal registration code from snort.org required to download Snort Subscriber or Registered rulesets |
| **Threshold/Suppression** | Tuning mechanisms that control alert frequency (threshold) or completely silence alerts from specific sources/destinations (suppress) |

## Tools & Systems

- **Snort 3**: Open-source network intrusion detection and prevention system with Lua-based configuration and multithreaded architecture
- **PulledPork 3**: Automated Snort rule management tool that downloads, processes, and deploys rulesets with policy-based filtering
- **Barnyard2**: Dedicated spooler that reads Snort's unified2 binary output and writes to databases (MySQL, PostgreSQL) for SIEM integration
- **Snorby**: Web-based Snort alert management console providing dashboards, event classification, and reporting
- **tcpreplay**: Tool for replaying PCAP files through Snort to validate rules and test detection capabilities

## Common Scenarios

### Scenario: Deploying Snort IDS at a Network Perimeter for Compliance

**Context**: A healthcare organization needs to deploy network IDS to meet HIPAA technical safeguard requirements. The IDS must monitor traffic between the DMZ and internal network, detect common attack patterns, and forward alerts to the existing Splunk SIEM. The network carries approximately 500 Mbps of traffic during peak hours.

**Approach**:
1. Install Snort 3 on a dedicated sensor with dual NICs -- one for monitoring (span port from core switch) and one for management
2. Configure AF_PACKET DAQ with a 512 MB ring buffer to handle peak throughput without drops
3. Deploy Snort Community rules plus Emerging Threats Open ruleset as baseline detection
4. Write custom rules for organization-specific threats: detection of PHI data patterns (SSN, MRN formats) leaving the network, unauthorized access to DICOM/HL7 ports, and connections to known bad IP lists
5. Configure JSON alert output and forward to Splunk via syslog using rsyslog
6. Run Snort against 24 hours of captured baseline traffic to identify false positives, then create suppression rules for legitimate traffic patterns
7. Enable Snort as a systemd service with automatic restart and log rotation

**Pitfalls**:
- Deploying all available rules without tuning, overwhelming the sensor and SOC with thousands of daily false positives
- Forgetting to disable NIC offloading, causing Snort to miss packets due to checksum errors or jumbo frames
- Not sizing the sensor hardware for peak traffic, leading to packet drops during high-volume periods
- Relying solely on community rules without custom rules for organization-specific threats and compliance requirements

## Output Format

```
## Snort IDS Deployment Report

**Sensor**: snort-sensor-01 (10.10.1.250)
**Interface**: eth1 (span port from Core-SW1 gi0/24)
**Configuration**: /usr/local/etc/snort/snort.lua
**Ruleset**: Snort Community 3.0 + Local Rules (1,247 active rules)
**HOME_NET**: 10.10.0.0/16

### Detection Summary (24-hour baseline)

| Category | Alert Count | Top Rule SID |
|----------|-------------|--------------|
| Attempted Recon | 342 | 1:2100498 (ICMP ping) |
| Trojan Activity | 12 | 1:1000001 (Reverse shell) |
| Policy Violation | 87 | 1:1000004 (FTP cleartext) |
| Web Application Attack | 23 | 1:2100654 (SQL injection) |

### Tuning Actions Taken
- Suppressed SID 2100498 for 10.10.1.100 (monitoring server legitimate ICMP)
- Thresholded SID 1000004 to 5 alerts per source per hour
- Added 3 custom rules for PHI exfiltration detection
```
