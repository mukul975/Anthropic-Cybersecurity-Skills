# S7comm Protocol Security Analysis - API Reference

## pyshark Library

Python wrapper for TShark (Wireshark CLI) for packet analysis.

### Loading S7comm Traffic
```python
import pyshark
cap = pyshark.FileCapture("traffic.pcap", display_filter="s7comm")
for pkt in cap:
    s7_layer = pkt.s7comm
    print(s7_layer.rosctr, s7_layer.param_func)
cap.close()
```

### Key S7comm Layer Fields

| Field | Description |
|-------|-------------|
| `s7comm.rosctr` | PDU type: 1=Job, 2=Ack, 3=Ack-Data, 7=Userdata |
| `s7comm.param_func` | Function code (hex) |
| `s7comm.error_class` | Error class (0 = no error) |
| `s7comm.error_code` | Specific error code |
| `s7comm.param_data` | Parameter data payload |

## S7comm Function Codes

| Code | Name | Risk Level |
|------|------|------------|
| 0x04 | Read Var | Low - read process data |
| 0x05 | Write Var | High - modify PLC memory |
| 0x28 | Setup Communication | Low - session init |
| 0x29 | PLC Run | Critical - start PLC execution |
| 0x1a | PLC Stop | Critical - halt PLC execution |
| 0xf0 | Userdata | Medium - diagnostics/programming |

## S7comm Protocol Overview

S7comm runs over ISO-on-TCP (RFC 1006) on port 102. The protocol stack:
1. TCP connection on port 102
2. TPKT header (RFC 1006)
3. COTP connection-oriented transport (ISO 8073)
4. S7comm PDU

### Security Concerns
- No built-in authentication in S7comm (pre-S7comm-Plus)
- No encryption of traffic
- Write operations can modify PLC logic and process values
- Stop/Run commands can halt industrial processes

## Detection Patterns

### Unauthorized Access
Multiple unique source IPs connecting to a single PLC (> 3 sources) indicates potential unauthorized access.

### Brute Force
Repeated error responses (error_class != 0) from a PLC to a single source exceeding threshold count.

### Dangerous Operations
Any write_var, run, or stop function codes should be flagged and correlated with authorized change windows.

## Output Schema

```json
{
  "report": "s7comm_protocol_security_analysis",
  "total_s7_packets": 1500,
  "total_findings": 8,
  "severity_summary": {"critical": 2, "high": 5, "medium": 1},
  "traffic_patterns": {"function_distribution": {"read_var": 1200, "write_var": 50}},
  "findings": [{"type": "dangerous_operation_stop", "severity": "critical"}]
}
```

## CLI Usage

```bash
python agent.py --pcap capture.pcap --brute-threshold 10 --output report.json
```
