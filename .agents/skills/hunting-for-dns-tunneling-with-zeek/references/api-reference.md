# API Reference: DNS Tunneling Detection with Zeek

## Detection Heuristics

| Indicator | Threshold | Score |
|-----------|-----------|-------|
| Shannon entropy | > 3.5 | +40 |
| Avg subdomain length | > 30 chars | +30 |
| Tunnel query type ratio | > 50% TXT/NULL/CNAME | +20 |
| High query volume | > 500 queries | +10 |

## Zeek dns.log Fields

| Index | Field | Description |
|-------|-------|-------------|
| 0 | `ts` | Timestamp |
| 2 | `id.orig_h` | Source IP |
| 4 | `id.resp_h` | DNS server |
| 9 | `query` | Query name |
| 13 | `qtype_name` | Query type (A, TXT, etc.) |
| 21 | `answers` | Response answers |

## DNS Tunneling Tools (for detection reference)

| Tool | Encoding | Query Type |
|------|----------|-----------|
| iodine | Base128 | NULL, TXT |
| dnscat2 | Hex/Base64 | CNAME, TXT, MX |
| dns2tcp | Base64 | TXT |
| Cobalt Strike | Hex | A, AAAA, TXT |

## Shannon Entropy Reference

| Data Type | Entropy |
|-----------|---------|
| Normal hostnames | 2.0 - 3.0 |
| Base32 encoded | 3.5 - 4.0 |
| Base64 encoded | 4.0 - 5.0 |
| Hex encoded | 3.5 - 4.0 |

## Python Libraries

| Library | Use |
|---------|-----|
| `math` | Entropy calculation |
| `csv` | TSV log parsing |
| `collections.defaultdict` | Domain aggregation |
| `dpkt` | PCAP DNS parsing |
| `dnslib` | DNS packet construction |

## Zeek Scripts for DNS Analysis

```zeek
@load base/protocols/dns
redef DNS::max_pending_queries = 1000;
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count) {
    if (|query| > 50) print fmt("Long query: %s", query);
}
```
