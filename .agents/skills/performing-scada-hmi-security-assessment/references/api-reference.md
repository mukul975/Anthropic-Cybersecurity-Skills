# SCADA HMI Security Assessment - API Reference

## SCADA Protocol Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 102 | S7comm | Siemens S7 PLC communication |
| 502 | Modbus TCP | Industrial automation protocol |
| 2222 | EtherNet/IP | Allen-Bradley, Rockwell |
| 4840 | OPC UA | Open Platform Communications Unified Architecture |
| 20000 | DNP3 | Distributed Network Protocol |
| 47808 | BACnet | Building Automation and Control |

## Port Scanning (socket stdlib)

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2.0)
result = sock.connect_ex((target, port))  # 0 = open
sock.close()
```

## pyshark for Protocol Analysis

```python
import pyshark
cap = pyshark.FileCapture("traffic.pcap")
for pkt in cap:
    for layer in pkt.layers:
        print(layer.layer_name)  # modbus, s7comm, dnp3, etc.
cap.close()
```

### Insecure SCADA Protocols
These protocols lack built-in encryption and authentication:
- **Modbus TCP** - No auth, no encryption, commands in plaintext
- **S7comm** - No auth (pre-V4), no encryption
- **DNP3** - Optional Secure Authentication (SA), rarely deployed
- **BACnet** - No native security mechanisms
- **EtherNet/IP** - No encryption, device enumeration possible

## HMI Configuration Checks

| Check | Severity | Description |
|-------|----------|-------------|
| Authentication disabled | Critical | HMI allows anonymous access |
| No session timeout | High | Sessions persist indefinitely |
| TLS disabled | High | Communications in plaintext |
| Remote access without VPN | Critical | HMI exposed without tunnel |
| No RBAC | High | Single role or no access control |
| Default credentials | Critical | Factory-default username/password |

## Common Default Credentials

| Username | Password | Platform |
|----------|----------|----------|
| admin | admin | Generic HMI |
| admin | 1234 | Siemens WinCC |
| operator | operator | Wonderware |
| engineer | engineer | GE iFIX |
| guest | guest | Various |

## ICS Security Standards

- **IEC 62443** - Industrial communication network security
- **NIST SP 800-82** - Guide to ICS Security
- **NERC CIP** - Critical Infrastructure Protection (power grid)

## Output Schema

```json
{
  "report": "scada_hmi_security_assessment",
  "target": "192.168.1.100",
  "total_findings": 6,
  "severity_summary": {"critical": 2, "high": 3, "medium": 1},
  "findings": [{"type": "open_scada_port", "severity": "high"}]
}
```

## CLI Usage

```bash
python agent.py --target 192.168.1.100 --pcap traffic.pcap --config hmi.json --output report.json
```
