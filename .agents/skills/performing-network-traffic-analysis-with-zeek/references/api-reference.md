# API Reference — Performing Network Traffic Analysis with Zeek

## Libraries Used
- **pathlib**: Read Zeek TSV log files
- **subprocess**: Execute Zeek on PCAP files
- **collections.Counter**: Traffic pattern aggregation

## CLI Interface
```
python agent.py conn --log conn.log
python agent.py dns --log dns.log
python agent.py http --log http.log
python agent.py notice --log notice.log
python agent.py run --pcap capture.pcap [--output-dir /tmp/zeek_output]
```

## Core Functions

### `parse_zeek_log(log_file)` — Generic Zeek TSV parser
Parses `#fields` header and data rows. Returns headers and record list.

### `analyze_conn_log(conn_log)` — Connection analysis
Statistics: protocols, services, top IPs/ports, total bytes, long connections (>1hr).

### `analyze_dns_log(dns_log)` — DNS query analysis
Detects: long queries (>50 chars), TXT queries, NXDOMAIN responses.
Flags potential DNS tunneling indicators.

### `analyze_http_log(http_log)` — Web traffic analysis
Tracks: methods, status codes, top hosts, user agents.
Flags suspicious UAs: curl, wget, python, powershell, certutil, bitsadmin.

### `analyze_notice_log(notice_log)` — Security alert review
Parses Zeek notice.log for detected security events.

### `run_zeek_on_pcap(pcap_file, output_dir)` — Generate Zeek logs from PCAP
Executes Zeek against PCAP to produce conn.log, dns.log, http.log, etc.

## Zeek Log Fields
| Log | Key Fields |
|-----|-----------|
| conn.log | id.orig_h, id.resp_h, id.resp_p, proto, service, duration, orig_bytes |
| dns.log | query, qtype_name, rcode_name |
| http.log | method, host, uri, status_code, user_agent |
| notice.log | note, msg, src, dst |

## Dependencies
System: zeek (for PCAP processing)
No Python packages required.
