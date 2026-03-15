# Snort IDS API Reference

## Snort 3 CLI

```bash
# Validate configuration
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -T

# Run IDS mode on interface
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i eth1 -l /var/log/snort -D

# Analyze PCAP file
snort -c /usr/local/etc/snort/snort.lua -r capture.pcap -l /var/log/snort/test/ -A fast

# Show version
snort -V

# Dump parsed rules count
snort -c /usr/local/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -T 2>&1 | grep "rules loaded"
```

## Snort Rule Syntax

```
action protocol src_ip src_port -> dst_ip dst_port (options;)

# Actions: alert, log, pass, drop, reject, sdrop
# Protocols: tcp, udp, icmp, ip

# Example rule
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SMB exploit attempt";
    flow:established,to_server;
    content:"|FF|SMB";
    content:"|25 00|"; distance:0; within:2;
    sid:1000010; rev:1;
    classtype:attempted-admin;
    priority:1;
)
```

## Rule Options

| Option | Description | Example |
|--------|-------------|---------|
| `content` | Match byte sequence | `content:"admin";` |
| `nocase` | Case-insensitive match | `content:"GET"; nocase;` |
| `depth` | Limit search depth | `depth:5;` |
| `offset` | Start search at offset | `offset:4;` |
| `distance` | Bytes between matches | `distance:0;` |
| `within` | Max bytes for match | `within:10;` |
| `flow` | Flow direction | `flow:established,to_server;` |
| `threshold` | Rate limiting | `threshold:type both, track by_src, count 10, seconds 60;` |
| `sid` | Signature ID | `sid:1000001;` |
| `classtype` | Alert classification | `classtype:trojan-activity;` |

## PulledPork 3 CLI

```bash
# Fetch and process rules
pulledpork3 -c /usr/local/etc/pulledpork3/pulledpork.conf

# Verify rule download
pulledpork3 -c /usr/local/etc/pulledpork3/pulledpork.conf -P
```

## DAQ Module Configuration (Lua)

```lua
daq = {
    module_dirs = { '/usr/local/lib/daq' },
    modules = {
        { name = 'afpacket', variables = { 'buffer_size_mb=256' } }
    }
}
```

## Suppress / Threshold Syntax

```
suppress gen_id 1, sig_id 2100498, track by_src, ip 10.10.1.100
event_filter gen_id 1, sig_id 1000004, type limit, track by_src, count 5, seconds 3600
```
