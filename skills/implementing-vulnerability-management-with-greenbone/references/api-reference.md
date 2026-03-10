# Greenbone/OpenVAS python-gvm API Reference

## Installation

```bash
pip install python-gvm
```

## Connection Setup

```python
from gvm.connections import UnixSocketConnection, TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

# Unix socket (local)
conn = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
# TLS (remote)
conn = TLSConnection(hostname="gvm-host", port=9390)

transform = EtreeTransform()
with Gmp(connection=conn, transform=transform) as gmp:
    gmp.authenticate("admin", "password")
    version = gmp.get_version()
```

## Core GMP API Methods

| Method | Description |
|--------|-------------|
| `gmp.authenticate(username, password)` | Authenticate to GVM |
| `gmp.get_version()` | Get GMP protocol version |
| `gmp.create_target(name, hosts, port_list_id)` | Create scan target |
| `gmp.create_task(name, config_id, target_id, scanner_id)` | Create scan task |
| `gmp.start_task(task_id)` | Start a scan task |
| `gmp.get_task(task_id)` | Get task status/progress |
| `gmp.get_tasks()` | List all scan tasks |
| `gmp.get_report(report_id, report_format_id)` | Retrieve scan report |
| `gmp.get_reports()` | List all reports |
| `gmp.get_results(filter_string)` | Get vulnerability results |

## Default Resource IDs

| Resource | ID | Description |
|----------|-----|-------------|
| Port List (All IANA TCP) | `33d0cd82-57c6-11e1-8ed1-406186ea4fc5` | All IANA assigned TCP ports |
| Scan Config (Full and fast) | `daba56c8-73ec-11df-a475-002264764cea` | Full and fast scan |
| Scanner (OpenVAS Default) | `08b69003-5fc2-4037-a479-93b440211c73` | Default OpenVAS scanner |
| Report Format (XML) | `a994b278-1f62-11e1-96ac-406186ea4fc5` | XML report format |

## Report XML Structure

```xml
<report>
  <results>
    <result>
      <host>192.168.1.10</host>
      <name>SSL/TLS Certificate Expired</name>
      <threat>High</threat>
      <severity>7.5</severity>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103955">
        <cve>CVE-2024-12345</cve>
      </nvt>
      <description>The SSL certificate has expired...</description>
    </result>
  </results>
</report>
```

## CLI Usage

```bash
python agent.py --input scan_results.json --output report.json
python agent.py --input scan_results.json --host gvm-server --username admin --password secret
```

## References

- python-gvm GitHub: https://github.com/greenbone/python-gvm
- GMP Protocol Docs: https://greenbone.github.io/docs/latest/api.html
- Greenbone Community Docs: https://greenbone.github.io/docs/latest/
