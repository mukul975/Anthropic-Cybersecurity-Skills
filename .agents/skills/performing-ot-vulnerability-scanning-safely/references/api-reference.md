# API Reference — Performing OT Vulnerability Scanning Safely

## Libraries Used
- **socket**: Rate-limited TCP port scanning
- **subprocess**: Execute tshark (passive), nmap (OT-safe settings)
- **time**: Rate limiting between scan probes
- **xml.etree.ElementTree**: Parse nmap XML output

## CLI Interface
```
python agent.py passive [--interface eth0] [--duration 60]
python agent.py tcp --target 192.168.1.10 [--rate 0.5]
python agent.py nmap --target 192.168.1.0/24 [--timing T1]
python agent.py checklist --target 192.168.1.0/24
```

## Core Functions

### `passive_discovery(interface, duration)` — Zero-packet host discovery
Uses tshark to capture and analyze existing traffic. No packets sent.

### `safe_tcp_scan(target, ports, rate_limit)` — Rate-limited scanning
Default 500ms between probes. Skips high-risk protocols (DNP3, IEC 104).

### `nmap_safe_scan(target, timing)` — OT-safe nmap configuration
Settings: T1 timing, version-light, max-retries 1, 500ms scan-delay.
Only T0/T1/T2 allowed — T3+ prohibited for OT.

### `pre_scan_checklist(target)` — 10-step safety checklist

## OT Protocol Safety Classification
| Port | Protocol | Scan Risk | Safe to Scan |
|------|----------|-----------|-------------|
| 502 | Modbus | LOW | Yes |
| 4840 | OPC-UA | LOW | Yes |
| 47808 | BACnet | LOW | Yes |
| 102 | S7Comm | MEDIUM | Yes (careful) |
| 44818 | EtherNet/IP | MEDIUM | Yes (careful) |
| 20000 | DNP3 | HIGH | No — skip |
| 2404 | IEC 104 | HIGH | No — skip |

## Dependencies
System: tshark, nmap (optional)
No Python packages required.
