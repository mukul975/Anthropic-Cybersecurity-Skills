# API Reference: Arkime Network Traffic Analysis

## Authentication
```
HTTPDigestAuth(username, password)
```
All API requests require Digest authentication.

## Session Search
```
GET /api/sessions
```
| Parameter | Type | Description |
|-----------|------|-------------|
| `date` | int | Time range in hours (1=last hour) |
| `expression` | string | Arkime search expression |
| `length` | int | Max results to return |
| `order` | string | Sort field:direction (e.g. `lastPacket:desc`) |
| `fields` | string | Comma-separated field list |

## PCAP Download
```
GET /api/sessions/pcap
GET /api/sessions/pcapng
```
| Parameter | Description |
|-----------|-------------|
| `date` | Time range in hours |
| `expression` | Filter expression |
Returns raw PCAP/PCAPNG binary data.

## Connection Graph
```
GET /api/connections
```
Returns `nodes` (IPs) and `links` (connections) for network graph visualization.

## SPI View (Field Statistics)
```
GET /api/spiview
```
| Parameter | Description |
|-----------|-------------|
| `spi` | Comma-separated fields (e.g. `srcIp,dstIp,dstPort`) |
Returns top values and counts for each field.

## Session Fields
| Field | Description |
|-------|-------------|
| `srcIp` | Source IP address |
| `dstIp` | Destination IP address |
| `srcPort` | Source port |
| `dstPort` | Destination port |
| `srcBytes` | Bytes sent by source |
| `dstBytes` | Bytes sent by destination |
| `lastPacket` | Timestamp of last packet (ms) |
| `srcJa3` | JA3 fingerprint of client TLS |
| `tls.issuerCN` | TLS certificate issuer CN |
| `tls.subjectCN` | TLS certificate subject CN |
| `tls.notAfter` | Certificate expiry (ms epoch) |

## Search Expressions
```
ip.src == 10.0.0.0/8
port.dst == 443
protocols == tls
country.src == CN
bytes > 1000000
```

## Beaconing Detection Logic
- Collect connection timestamps per (src, dst, port) tuple
- Calculate intervals between consecutive connections
- Compute jitter ratio: `std_dev / avg_interval`
- Jitter < 0.05 = high confidence C2, < 0.15 = medium
