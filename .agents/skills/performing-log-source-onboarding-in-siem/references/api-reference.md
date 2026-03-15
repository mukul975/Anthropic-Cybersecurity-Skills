# API Reference — Performing Log Source Onboarding in SIEM

## Libraries Used
- **socket**: Test syslog connectivity (UDP/TCP) to SIEM collectors
- **re**: Log format detection via pattern matching
- **pathlib**: Read log sample files

## CLI Interface
```
python agent.py detect --file sample.log
python agent.py validate --host siem.corp.com [--port 514] [--protocol udp|tcp]
python agent.py parse-config --format syslog_rfc3164 --source-type firewall_logs
python agent.py checklist --source "Palo Alto FW" --format syslog_rfc3164 --siem-host siem.corp.com
```

## Core Functions

### `detect_log_format(sample_file)` — Auto-detect log format
Identifies: syslog RFC 3164/5424, CEF, LEEF, JSON, CSV, Windows Event, Apache combined.

### `validate_syslog_connectivity(host, port, protocol)` — Test SIEM collector
Sends test syslog message via UDP or TCP. Validates port reachability.

### `generate_parsing_config(log_format, source_type)` — Create parsing rules
Generates Splunk (props.conf/transforms.conf) and Elastic (Filebeat/Logstash) configs.

### `create_onboarding_checklist(...)` — 10-step onboarding workflow
Covers: sample collection, format validation, connectivity, parsing, correlation rules, documentation.

## Supported Log Formats
| Format | Pattern Indicator |
|--------|------------------|
| syslog_rfc3164 | `<PRI>Mon DD HH:MM:SS` |
| syslog_rfc5424 | `<PRI>VER YYYY-MM-DDT` |
| CEF | `CEF:0\|` |
| LEEF | `LEEF:1.0\|` |
| JSON | `{...}` |
| Apache combined | IP - - [timestamp] "METHOD" |

## Dependencies
No external packages — Python standard library only.
