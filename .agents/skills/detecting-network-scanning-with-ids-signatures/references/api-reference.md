# API Reference: Detecting Network Scanning with IDS Signatures

## Scan Types and Detection

| Scan Type | Method | Detection |
|-----------|--------|-----------|
| SYN Scan | Half-open SYN packets | Many SYN without ACK |
| Connect Scan | Full TCP handshake | Many connections, short duration |
| Host Sweep | Same port, many hosts | Single port, >10 destinations |
| Service Enum | Banner grabbing | Short-lived connections |

## Suricata EVE JSON Format

```json
{
  "event_type": "alert",
  "src_ip": "10.0.0.5",
  "dest_ip": "192.168.1.100",
  "alert": {
    "signature": "ET SCAN Nmap SYN Scan",
    "category": "Attempted Information Leak",
    "severity": 2,
    "signature_id": 2000001
  }
}
```

## Suricata Scan Detection Rules

```
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; \
  flags:S; threshold:type both, track by_src, count 25, seconds 60; \
  sid:5000001;)
```

## Zeek conn.log Fields

```
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service
        duration orig_bytes resp_bytes conn_state
```

## Detection Thresholds

| Metric | Threshold | Severity |
|--------|-----------|----------|
| Unique ports per destination | >20 | HIGH |
| Unique ports >100 | >100 | CRITICAL |
| Hosts per single port sweep | >10 | MEDIUM |
| Hosts >50 | >50 | HIGH |

## Splunk SPL Detection

```spl
index=network
| stats dc(dest_port) as unique_ports by src_ip, dest_ip
| where unique_ports > 20
| sort -unique_ports
```

## CLI Usage

```bash
python agent.py --eve-log eve.json
python agent.py --conn-log conn.log --port-threshold 25 --sweep-threshold 15
```
