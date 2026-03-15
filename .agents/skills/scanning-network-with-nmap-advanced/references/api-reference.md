# API Reference: Scanning Network with Nmap Advanced

## python-nmap Library

### Installation
```bash
pip install python-nmap
```
Requires Nmap binary installed on the system (`nmap` must be in PATH).

### Core Classes

#### `nmap.PortScanner()`
Main scanner class wrapping the Nmap command-line tool.

| Method | Parameters | Returns | Description |
|--------|-----------|---------|-------------|
| `scan()` | `hosts`, `ports`, `arguments` | `dict` | Execute Nmap scan with given arguments |
| `all_hosts()` | - | `list[str]` | List of all scanned host IPs |
| `nmap_version()` | - | `tuple` | Installed Nmap version |
| `command_line()` | - | `str` | Nmap command that was executed |

#### Scanner Result Access
```python
scanner[host].state()              # Host state: 'up' or 'down'
scanner[host].all_protocols()      # ['tcp', 'udp']
scanner[host][proto].keys()        # List of port numbers
scanner[host][proto][port]         # Port info dict with keys: state, name, product, version
scanner[host].hostnames()          # [{'name': 'hostname', 'type': 'PTR'}]
scanner[host]['osmatch']           # OS detection results
```

### Common Nmap Arguments
| Argument | Purpose |
|----------|---------|
| `-sS` | TCP SYN scan (half-open, requires root) |
| `-sV` | Service version detection |
| `-sC` | Run default NSE scripts |
| `-O` | OS fingerprinting |
| `-sn` | Host discovery only (no port scan) |
| `--script vuln` | Run vulnerability detection scripts |
| `-T0` to `-T5` | Timing templates (paranoid to insane) |
| `--min-rate N` | Minimum packets per second |
| `-PE -PP -PS` | ICMP echo, timestamp, TCP SYN discovery probes |
| `-oX file` | Output results in XML format |

### Output Parsing
```python
scanner.csv()           # CSV-formatted scan results
scanner.scaninfo()      # Scan metadata (type, services scanned)
scanner.scanstats()     # Timing and host statistics
```

## References
- python-nmap docs: https://pypi.org/project/python-nmap/
- Nmap Reference Guide: https://nmap.org/book/man.html
- NSE Script Categories: https://nmap.org/nsedoc/categories/
