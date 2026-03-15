# API Reference — Performing OT Network Security Assessment

## Libraries Used
- **csv**: Parse asset inventories and firewall rule exports
- **subprocess**: Execute nmap for OT protocol scanning
- **xml.etree.ElementTree**: Parse nmap XML output

## CLI Interface
```
python agent.py assets --csv ot_inventory.csv
python agent.py segmentation --csv firewall_rules.csv
python agent.py protocols --subnet 192.168.1.0/24
python agent.py report --assets inventory.csv [--firewall fw_rules.csv]
```

## Core Functions

### `assess_asset_inventory(csv_file)` — Purdue model zone analysis
Groups assets by Purdue level. Flags end-of-life and unknown firmware.

### `assess_network_segmentation(csv_file)` — Firewall rule audit
Detects: direct IT-to-OT access (CRITICAL), allow-any-protocol rules (HIGH).

### `scan_ot_protocols(target_subnet)` — OT protocol discovery
Scans ports: 102 (S7), 502 (Modbus), 4840 (OPC-UA), 44818 (EtherNet/IP),
47808 (BACnet), 20000 (DNP3).

### `generate_assessment_report(...)` — Comprehensive report

## OT Protocol Ports
| Port | Protocol | Usage |
|------|----------|-------|
| 102 | S7Comm | Siemens S7 PLCs |
| 502 | Modbus TCP | Industrial automation |
| 4840 | OPC-UA | Industrial data exchange |
| 44818 | EtherNet/IP | Allen-Bradley PLCs |
| 47808 | BACnet | Building automation |
| 20000 | DNP3 | SCADA/utility |

## Dependencies
System: nmap (optional, for protocol scanning)
No Python packages required.
