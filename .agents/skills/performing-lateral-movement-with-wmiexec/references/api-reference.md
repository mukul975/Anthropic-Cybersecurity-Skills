# API Reference — Performing Lateral Movement with WMIExec

## Libraries Used
- **python-evtx**: Parse Windows EVTX logs for WMI process creation artifacts
- **subprocess**: Execute Impacket wmiexec, tshark PCAP analysis, WMIC queries
- **xml.etree.ElementTree**: Parse Sysmon/Security event XML
- **impacket** (external): wmiexec.py for authorized lateral movement testing

## CLI Interface
```
python agent.py detect --evtx security.evtx
python agent.py exec --target 10.0.0.5 --domain CORP --user admin [--cmd whoami]
python agent.py network --pcap capture.pcap
python agent.py persistence
```

## Core Functions

### `detect_wmiexec_artifacts_evtx(evtx_file)` — Detect WMIExec in event logs
Searches for: Sysmon EID 1 with wmiprvse.exe parent, EID 4624 type 3 logons, EID 7045 service installs.

### `run_wmiexec_impacket(target, domain, username, command)` — Execute remote command
Uses Impacket wmiexec for authorized penetration testing.

### `detect_wmi_network_traffic(pcap_file)` — PCAP analysis for WMI
Uses tshark to filter DCOM UUID 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57 and port 135.

### `check_wmi_persistence()` — Local WMI subscription audit
Queries __EventFilter, CommandLineEventConsumer, __FilterToConsumerBinding.

## Detection Indicators
| Artifact | Event ID | Indicator |
|----------|----------|-----------|
| Process from WMI | Sysmon 1 | ParentImage = wmiprvse.exe |
| Network logon | Security 4624 | LogonType = 3 |
| Service install | System 7045 | BTOBTO/wmi patterns |

## Dependencies
```
pip install python-evtx impacket
```
System: tshark (optional, for PCAP analysis)
