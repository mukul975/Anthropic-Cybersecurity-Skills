# API Reference: Malware Network Traffic Analysis

## dpkt - Python Packet Parsing

### PCAP Reading
```python
import dpkt
with open("malware.pcap", "rb") as f:
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
```

### HTTP Parsing
```python
http_req = dpkt.http.Request(tcp.data)
http_req.method       # GET, POST
http_req.uri          # Request URI
http_req.headers      # Header dict
http_req.body         # POST body

http_resp = dpkt.http.Response(tcp.data)
http_resp.status      # Status code
http_resp.body        # Response body
```

### IP Address Conversion
```python
dpkt.utils.inet_to_str(ip.src)    # bytes -> "1.2.3.4"
dpkt.utils.inet_aton("1.2.3.4")   # "1.2.3.4" -> bytes
```

## Wireshark Display Filters for Malware

### C2 Detection
```
http.request.method == "POST" && http.content_length > 0
tls.handshake.type == 1                   # TLS Client Hello
tcp.flags.syn == 1 && tcp.flags.ack == 0  # New connections
dns.qry.type == 16                        # TXT records
```

### Payload Analysis
```
tcp.payload contains "MZ"                 # PE downloads
http.response.code == 200 && http.content_type contains "octet"
frame.len > 1400                          # Large packets
```

## tshark - Field Extraction

### HTTP Requests
```bash
tshark -r malware.pcap -Y "http.request" -T fields \
  -e http.request.method -e http.host -e http.request.uri \
  -e http.user_agent -e http.content_length
```

### TLS/JA3 Fingerprinting
```bash
tshark -r malware.pcap -Y "tls.handshake.type==1" -T fields \
  -e ip.src -e ip.dst -e tls.handshake.ja3
```

### DNS Queries
```bash
tshark -r malware.pcap -Y "dns.qr==0" -T fields \
  -e ip.src -e dns.qry.name -e dns.qry.type
```

### Stream Follow
```bash
tshark -r malware.pcap -z follow,tcp,ascii,0
tshark -r malware.pcap -z follow,http,ascii,0
```

## Suricata Rule Syntax

### HTTP Rules
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"MALWARE C2 Beacon";
  flow:established,to_server;
  http.method; content:"POST";
  http.uri; content:"/gate.php";
  sid:9000001; rev:1;
)
```

### DNS Rules
```
alert dns $HOME_NET any -> any any (
  msg:"MALWARE DNS Tunneling";
  dns.query; pcre:"/^[a-z0-9]{20,}\./";
  threshold:type threshold, track by_src, count 10, seconds 60;
  sid:9000002; rev:1;
)
```

### TLS Rules
```
alert tls $HOME_NET any -> $EXTERNAL_NET any (
  msg:"MALWARE JA3 Match";
  ja3.hash; content:"a0e9f5d64349fb13191bc781f81f42e1";
  sid:9000003; rev:1;
)
```

## RITA - Beacon Analysis

### Syntax
```bash
rita import zeek_logs dataset_name
rita analyze dataset_name
rita show-beacons dataset_name
rita show-long-connections dataset_name
rita show-dns-fqdn-lengths dataset_name
```

## NetworkMiner

### CLI Syntax
```bash
NetworkMiner --inputfile malware.pcap --outputdir /tmp/extracted
```
Extracts files, sessions, credentials, DNS from PCAP
