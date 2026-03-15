# Zeek Network Anomaly Detection API Reference

## Zeek CLI

```bash
# Process PCAP file
zeek -r capture.pcap -C

# Run on live interface
zeek -i eth1

# Run with custom script
zeek -r capture.pcap local.zeek

# ZeekControl
zeekctl deploy       # Deploy and start
zeekctl status       # Check status
zeekctl stop         # Stop all workers
zeekctl diag         # Diagnostics
```

## Zeek Log Files

| Log | Content | Key Fields |
|-----|---------|------------|
| `conn.log` | All connections | ts, id.orig_h, id.resp_h, service, duration |
| `dns.log` | DNS queries/responses | query, qtype_name, rcode_name |
| `ssl.log` | TLS handshakes | server_name, ja3, validation_status |
| `http.log` | HTTP requests | method, host, uri, user_agent |
| `files.log` | File transfers | md5, sha1, mime_type, filename |
| `notice.log` | Zeek notices/alerts | note, msg, src, dst |
| `weird.log` | Protocol anomalies | name, addl |
| `x509.log` | Certificate details | san.dns, certificate.not_valid_after |

## Zeek Scripting - Custom Detection

```zeek
# Detect DNS tunneling (long queries)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (|query| > 60) {
        NOTICE([$note=DNS::Tunneling,
                $conn=c,
                $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
                $identifier=cat(c$id$orig_h)]);
    }
}

# Detect C2 beaconing
@load base/frameworks/sumstats
event connection_established(c: connection) {
    if (Site::is_local_addr(c$id$orig_h) && !Site::is_local_addr(c$id$resp_h)) {
        SumStats::observe("ext_conns",
            SumStats::Key($str=cat(c$id$orig_h, "->", c$id$resp_h)),
            SumStats::Observation($num=1));
    }
}
```

## Zeek Log Parsing (Python)

```python
# Parse tab-separated Zeek logs
with open("conn.log") as f:
    for line in f:
        if line.startswith("#"):
            continue
        fields = line.strip().split("\t")
        ts, uid, orig_h, orig_p, resp_h, resp_p = fields[:6]
```

## zeek-cut (CLI field extraction)

```bash
# Extract specific fields
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p service

# DNS queries sorted by count
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20

# JA3 fingerprints
cat ssl.log | zeek-cut ja3 server_name | sort | uniq -c | sort -rn
```

## Beaconing Detection Formula

```
interval_avg = mean(connection_intervals)
jitter = mean(|interval - interval_avg|) / interval_avg
if jitter < 0.15 and connections > 10:
    flag as potential C2 beacon
```
