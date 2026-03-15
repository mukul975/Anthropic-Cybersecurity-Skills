# API Reference — Performing Network Packet Capture Analysis

## Libraries Used
- **scapy**: PCAP parsing, protocol dissection, packet analysis
- **subprocess**: Execute tshark for HTTP extraction and conversation analysis
- **collections.Counter**: Traffic statistics aggregation

## CLI Interface
```
python agent.py analyze --pcap capture.pcap
python agent.py http --pcap capture.pcap
python agent.py suspicious --pcap capture.pcap
python agent.py conversations --pcap capture.pcap
```

## Core Functions

### `analyze_pcap_scapy(pcap_file)` — Protocol and IP statistics
Returns: protocol distribution, top source/dest IPs, top destination ports, DNS queries.

### `extract_http_requests(pcap_file)` — HTTP request extraction via tshark
Extracts: source/dest IP, method, host, URI, user agent from HTTP requests.

### `detect_suspicious_traffic(pcap_file)` — Anomaly detection
Detects: port scanning (>=20 SYN to same target), DNS exfiltration (queries >60 chars),
suspicious ports (4444, 31337, 6667, etc.).

### `conversation_analysis(pcap_file)` — TCP conversation summary
Uses tshark `-z conv,tcp` for conversation-level statistics.

## Suspicious Port Detection
4444, 5555, 6666, 8888, 9999, 1234, 31337, 12345, 6667, 6697

## Detection Categories
| Finding | Severity | Trigger |
|---------|----------|---------|
| PORT_SCAN | HIGH | >=20 SYN packets to same target |
| DNS_EXFILTRATION | HIGH | DNS queries >60 characters |
| SUSPICIOUS_PORTS | MEDIUM | Traffic on known C2 ports |

## Dependencies
```
pip install scapy
```
System: tshark (optional, for HTTP and conversation analysis)
