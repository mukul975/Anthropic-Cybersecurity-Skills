# API Reference — Performing External Network Penetration Test

## Libraries Used
- **socket**: TCP port scanning and banner grabbing
- **subprocess**: Execute nmap with XML output parsing
- **dns.resolver** (dnspython): DNS record enumeration and subdomain discovery
- **ssl**: TLS certificate inspection and cipher analysis
- **xml.etree.ElementTree**: Parse nmap XML output

## CLI Interface
```
python agent.py scan --host <target_ip> [--ports 22 80 443]
python agent.py nmap --target <ip_or_range> [--type quick|full|vuln|udp]
python agent.py dns --domain <domain>
python agent.py ssl --host <hostname> [--port 443]
```

## Core Functions

### `tcp_port_scan(host, ports)` — Scan TCP ports with banner grabbing
Scans 22 common ports by default. Returns open ports with service banners.

### `run_nmap_scan(target, scan_type)` — Execute nmap and parse XML results
Scan types: `quick` (top 100 -sV), `full` (-p- -sC), `vuln` (NSE vuln scripts), `udp` (top 50 UDP).

### `dns_enumeration(domain)` — Enumerate DNS records and subdomains
Queries A, AAAA, MX, NS, TXT, SOA, CNAME records. Tests 10 common subdomain prefixes.

### `ssl_check(host, port)` — Inspect TLS certificate and cipher suite
Returns subject, issuer, validity dates, TLS version, and negotiated cipher.

## Default Port List
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3),
135 (RPC), 139 (NetBIOS), 143 (IMAP), 443 (HTTPS), 445 (SMB), 993/995 (IMAPS/POP3S),
1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 3389 (RDP), 5432 (PostgreSQL),
5900 (VNC), 8080/8443 (HTTP Proxy/Alt HTTPS)

## Dependencies
```
pip install dnspython
```
System: nmap (optional, for advanced scanning)
